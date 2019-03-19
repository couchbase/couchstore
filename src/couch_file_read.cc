/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#include "config.h"

#include <fcntl.h>
#include <phosphor/phosphor.h>
#include <platform/cb_malloc.h>
#include <snappy.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "bitfield.h"
#include "crc32.h"
#include "internal.h"
#include "iobuffer.h"
#include "util.h"

void stop_trace() {
    PHOSPHOR_INSTANCE.stop();
}
couchstore_error_t tree_file_open(tree_file* file,
                                  const char *filename,
                                  int openflags,
                                  crc_mode_e crc_mode,
                                  FileOpsInterface* ops,
                                  tree_file_options file_options)
{
    if(filename == nullptr || file == nullptr || ops == nullptr) {
        return COUCHSTORE_ERROR_INVALID_ARGUMENTS;
    }

    couchstore_error_t errcode = COUCHSTORE_SUCCESS;

    memset(file, 0, sizeof(*file));

    file->crc_mode = crc_mode;
    file->options = file_options;

    file->path = (const char *) cb_strdup(filename);
    error_unless(file->path, COUCHSTORE_ERROR_ALLOC_FAIL);

    if (file_options.buf_io_enabled) {
        buffered_file_ops_params params((openflags == O_RDONLY),
                                        file_options.tracing_enabled,
                                        file_options.write_validation_enabled,
                                        file_options.mprotect_enabled,
                                        file_options.buf_io_read_unit_size,
                                        file_options.buf_io_read_buffers);

        file->ops = couch_get_buffered_file_ops(&file->lastError, ops,
                                                &file->handle, params);
    } else {
        file->ops = ops;
        file->handle = file->ops->constructor(&file->lastError);
    }

    error_unless(file->ops, COUCHSTORE_ERROR_ALLOC_FAIL);

    error_pass(file->ops->open(&file->lastError, &file->handle,
                               filename, openflags));

    if (file->options.periodic_sync_bytes != 0) {
        error_pass(file->ops->set_periodic_sync(
                file->handle, file->options.periodic_sync_bytes));
    }
    if (file->options.tracing_enabled) {
        error_pass(file->ops->set_tracing_enabled(file->handle));
    }
    if (file->options.write_validation_enabled) {
        error_pass(file->ops->set_write_validation_enabled(file->handle));
    }
    if (file->options.mprotect_enabled) {
        error_pass(file->ops->set_mprotect_enabled(file->handle));
    }
cleanup:
    if (errcode != COUCHSTORE_SUCCESS) {
        cb_free((char *) file->path);
        file->path = NULL;
        if (file->ops) {
            file->ops->destructor(file->handle);
            file->ops = NULL;
            file->handle = NULL;
        }
    }
    return errcode;
}

couchstore_error_t tree_file_close(tree_file* file)
{
    couchstore_error_t errcode = COUCHSTORE_SUCCESS;
    if (file->ops) {
        errcode = file->ops->close(&file->lastError, file->handle);
        file->ops->destructor(file->handle);
    }
    cb_free((char*)file->path);
    return errcode;
}

/** Read bytes from the database file, skipping over the header-detection bytes at every block
    boundary. */
static couchstore_error_t read_skipping_prefixes(tree_file *file,
                                                 cs_off_t *pos,
                                                 ssize_t len,
                                                 void *dst) {
    if (*pos % COUCH_BLOCK_SIZE == 0) {
        ++*pos;
    }
    while (len > 0) {
        ssize_t read_size = COUCH_BLOCK_SIZE - (*pos % COUCH_BLOCK_SIZE);
        if (read_size > len) {
            read_size = len;
        }
        ssize_t got_bytes = file->ops->pread(&file->lastError, file->handle,
                                             dst, read_size, *pos);
        if (got_bytes < 0) {
            return (couchstore_error_t) got_bytes;
        } else if (got_bytes == 0) {
            return COUCHSTORE_ERROR_READ;
        }
        *pos += got_bytes;
        len -= got_bytes;
        dst = (char*)dst + got_bytes;
        if (*pos % COUCH_BLOCK_SIZE == 0) {
            ++*pos;
        }
    }
    return COUCHSTORE_SUCCESS;
}

/*
 * Common subroutine of pread_bin, pread_compressed and pread_header.
 * Parameters and return value are the same as for pread_bin,
 * except the 'max_header_size' parameter which is greater than 0 if
 * reading a header, 0 otherwise.
 */
static int pread_bin_internal(tree_file *file,
                              cs_off_t pos,
                              char **ret_ptr,
                              uint32_t max_header_size)
{
    struct {
        uint32_t chunk_len;
        uint32_t crc32;
    } info;

    couchstore_error_t err = read_skipping_prefixes(file, &pos, sizeof(info), &info);
    if (err < 0) {
        return err;
    }

    info.chunk_len = ntohl(info.chunk_len) & ~0x80000000;
    if (max_header_size) {
        if (info.chunk_len < 4 || info.chunk_len > max_header_size) {
            stop_trace();
            return COUCHSTORE_ERROR_CORRUPT;
        }
        info.chunk_len -= 4; // Header len includes CRC len.
    }
    info.crc32 = ntohl(info.crc32);

    uint8_t* buf = static_cast<uint8_t*>(cb_malloc(info.chunk_len));
    if (!buf) {
        return COUCHSTORE_ERROR_ALLOC_FAIL;
    }
    err = read_skipping_prefixes(file, &pos, info.chunk_len, buf);

    if (!err && !perform_integrity_check(buf, info.chunk_len, info.crc32, file->crc_mode)) {
        stop_trace();
        err = COUCHSTORE_ERROR_CHECKSUM_FAIL;
    }

    if (err < 0) {
        cb_free(buf);
        return err;
    }

    *ret_ptr = reinterpret_cast<char*>(buf);
    return info.chunk_len;
}

int pread_header(tree_file *file,
                 cs_off_t pos,
                 char **ret_ptr,
                 uint32_t max_header_size)
{
    if (max_header_size == 0) {
        return COUCHSTORE_ERROR_INVALID_ARGUMENTS;
    }

    ScopedFileTag tag(file->ops, file->handle, FileTag::FileHeader);
    return pread_bin_internal(file, pos + 1, ret_ptr, max_header_size);
}

int pread_compressed(tree_file *file, cs_off_t pos, char **ret_ptr)
{
    char *compressed_buf;
    char *new_buf;
    int len = pread_bin_internal(file, pos, &compressed_buf, 0);
    if (len < 0) {
        return len;
    }
    size_t uncompressed_len;

    if (!snappy::GetUncompressedLength(compressed_buf, len, &uncompressed_len)) {
        //should be compressed but snappy doesn't see it as valid.
        cb_free(compressed_buf);
        stop_trace();
        return COUCHSTORE_ERROR_CORRUPT;
    }

    new_buf = static_cast<char *>(cb_malloc(uncompressed_len));
    if (!new_buf) {
        cb_free(compressed_buf);
        return COUCHSTORE_ERROR_ALLOC_FAIL;
    }

    if (!snappy::RawUncompress(compressed_buf, len, new_buf)) {
        cb_free(compressed_buf);
        cb_free(new_buf);
        stop_trace();
        return COUCHSTORE_ERROR_CORRUPT;
    }

    cb_free(compressed_buf);
    *ret_ptr = new_buf;
    return static_cast<int>(uncompressed_len);
}

int pread_bin(tree_file *file, cs_off_t pos, char **ret_ptr)
{
    return pread_bin_internal(file, pos, ret_ptr, 0);
}
