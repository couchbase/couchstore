/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#include "couchstore_config.h"

#include <fcntl.h>
#include <phosphor/phosphor.h>
#include <platform/cb_malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <platform/compress.h>

#include "bitfield.h"
#include "crc32.h"
#include "crypto.h"
#include "internal.h"
#include "iobuffer.h"
#include "log_last_internal_error.h"
#include "util.h"

#include <gsl/gsl-lite.hpp>

static void stop_trace() {
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

    try {
        errcode = file->close();
        if (errcode != COUCHSTORE_SUCCESS) {
            return errcode;
        }
        file->crc_mode = crc_mode;
        file->options = file_options;
        file->path = filename;
    } catch (const std::bad_alloc&) {
        error_pass(COUCHSTORE_ERROR_ALLOC_FAIL);
    } catch (const std::exception&) {
        error_pass(COUCHSTORE_ERROR_INVALID_ARGUMENTS);
    }

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

    error_unless(file->ops && file->handle, COUCHSTORE_ERROR_ALLOC_FAIL);

    error_pass(file->ops->open(&file->lastError, &file->handle,
                               filename, openflags));
    file->handle_open = true;

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
        (void)file->close();
    }
    return errcode;
}

couchstore_error_t tree_file::close() {
    couchstore_error_t errcode = COUCHSTORE_SUCCESS;
    if (ops && handle) {
        if (handle_open) {
            errcode = ops->close(&lastError, handle);
        }
        ops->destructor(handle);
    }
    pos = 0;
    ops = nullptr;
    handle = nullptr;
    handle_open = false;
    crc_mode = CRC_UNKNOWN;
    options = {};
    path.clear();
    cipher.reset();
    cipher_keyid.clear();
    return errcode;
}

tree_file::~tree_file() {
    (void)close();
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

/**
 * uint32_t value with only its highest bit set
 *
 * Used to set/test/mask that bit when dealing with chunk lengths.
 * Unencrypted data chunk lengths should have the highest bit set,
 * to differentiate them from header chunks and encrypted data chunks.
 */
constexpr uint32_t high_bit_set = 0x80000000;

static int pread_encrypted(tree_file* file, cs_off_t pos, char** ret_ptr) {
    const auto initPos = pos;

    uint32_t chunkLen;
    auto err = read_skipping_prefixes(file, &pos, sizeof(chunkLen), &chunkLen);
    if (err < 0) {
        return err;
    }
    chunkLen = ntohl(chunkLen);
    const size_t macSize = file->cipher->getMacSize();
    if ((chunkLen & high_bit_set) || (chunkLen < macSize)) {
        log_last_internal_error(
                "Couchstore::pread_encrypted() "
                "Invalid chunk length:%u pos:%" PRId64,
                chunkLen,
                initPos);
        stop_trace();
        return COUCHSTORE_ERROR_CORRUPT;
    }

    // pread_* return a cb_malloc:ed pointer.
    // Manage the pointer with unique_ptr until it can be successfully returned.
    std::unique_ptr<char, cb_free_deleter> buf{
            reinterpret_cast<char*>(cb_malloc(chunkLen))};
    if (!buf) {
        return COUCHSTORE_ERROR_ALLOC_FAIL;
    }
    err = read_skipping_prefixes(file, &pos, chunkLen, buf.get());
    if (err < 0) {
        return err;
    }

    try {
        const size_t msgSize = chunkLen - macSize;
        // Decrypt inplace
        file->cipher->decrypt(offset2nonce(initPos),
                              {buf.get(), msgSize},
                              {buf.get() + msgSize, macSize},
                              {buf.get(), msgSize});

        *ret_ptr = buf.release();
        return gsl::narrow<int>(msgSize);
    } catch (const cb::crypto::MacVerificationError& ex) {
        log_last_internal_error("Couchstore::pread_encrypted() pos:%" PRId64
                                " %s",
                                initPos,
                                ex.what());
        stop_trace();
        return COUCHSTORE_ERROR_CHECKSUM_FAIL;
    } catch (const std::bad_alloc&) {
        return COUCHSTORE_ERROR_ALLOC_FAIL;
    } catch (const std::exception& ex) {
        log_last_internal_error("Couchstore::pread_encrypted() pos:%" PRId64
                                " %s",
                                initPos,
                                ex.what());
        return COUCHSTORE_ERROR_DECRYPT;
    }
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
    if (file->cipher && !max_header_size) {
        return pread_encrypted(file, pos, ret_ptr);
    }

    const auto init_pos = pos;
    struct {
        uint32_t chunk_len;
        uint32_t crc32;
    } info;

    couchstore_error_t err = read_skipping_prefixes(file, &pos, sizeof(info), &info);
    if (err < 0) {
        return err;
    }

    info.chunk_len = ntohl(info.chunk_len);
    if ((max_header_size != 0) != !(info.chunk_len & high_bit_set)) {
        // High bit must not be set for header chunks
        // and must be set for unencrypted data chunks
        log_last_internal_error(
                "Couchstore::pread_bin_internal() "
                "Invalid chunk length:%u max_header_size:%u pos:%" PRId64,
                info.chunk_len,
                max_header_size,
                init_pos);
        stop_trace();
        return COUCHSTORE_ERROR_CORRUPT;
    }
    info.chunk_len &= ~high_bit_set;
    if (max_header_size) {
        if (info.chunk_len < 4 || info.chunk_len > max_header_size) {
            log_last_internal_error(
                    "Couchstore::pread_bin_internal() "
                    "Invalid header length:%u max_header_size:%u pos:%" PRId64,
                    info.chunk_len,
                    max_header_size,
                    init_pos);
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

    if (!err && !perform_integrity_check(
                        buf, info.chunk_len, info.crc32, file->crc_mode)) {
        log_last_internal_error(
                "Couchstore::pread_bin_internal() "
                "Checksum fail length:%u crc:%u pos:%" PRId64,
                info.chunk_len,
                info.crc32,
                init_pos);
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
    int len = pread_bin_internal(file, pos, &compressed_buf, 0);
    if (len < 0) {
        return len;
    }

    auto allocator = cb::compression::Allocator{
        cb::compression::Allocator::Mode::Malloc};

    cb::compression::Buffer buffer(allocator);
    try {
        if (!cb::compression::inflateSnappy(
                    {compressed_buf, size_t(len)},
                    buffer,
                    std::numeric_limits<size_t>::max())) {
            cb_free(compressed_buf);
            log_last_internal_error("Couchstore::pread_compressed() "
                     "Invalid compressed buffer length:%d pos:%" PRId64, len, pos);
            stop_trace();
            return COUCHSTORE_ERROR_CORRUPT;
        }
    } catch (const std::bad_alloc&) {
        cb_free(compressed_buf);
        return COUCHSTORE_ERROR_ALLOC_FAIL;
    }

    cb_free(compressed_buf);

    len = gsl::narrow_cast<int>(buffer.size());
    *ret_ptr = buffer.release();
    return len;
}

int pread_bin(tree_file *file, cs_off_t pos, char **ret_ptr)
{
    return pread_bin_internal(file, pos, ret_ptr, 0);
}
