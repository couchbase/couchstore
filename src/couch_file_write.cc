/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#include "config.h"

#include <libcouchstore/couch_db.h>
#include <phosphor/phosphor.h>
#include <platform/cb_malloc.h>
#include <snappy.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include "crc32.h"
#include "internal.h"
#include "util.h"

static ssize_t raw_write(tree_file *file, const sized_buf *buf, cs_off_t pos)
{
    cs_off_t write_pos = pos;
    size_t buf_pos = 0;
    char blockprefix = 0;
    ssize_t written;
    size_t block_remain;
    while (buf_pos < buf->size) {
        block_remain = COUCH_BLOCK_SIZE - (write_pos % COUCH_BLOCK_SIZE);
        if (block_remain > (buf->size - buf_pos)) {
            block_remain = buf->size - buf_pos;
        }

        if (write_pos % COUCH_BLOCK_SIZE == 0) {
            if (file->options.tracing_enabled) {
                TRACE_INSTANT1(
                        "couchstore_write", "block_start", "offset", write_pos);
            }
            written = file->ops->pwrite(&file->lastError, file->handle,
                                        &blockprefix, 1, write_pos);
            if (written < 0) {
                return written;
            }
            write_pos += 1;
            continue;
        }
        /* calculate CRC for the piece written and trace it. */
        if (file->options.tracing_enabled) {
            uint32_t crc32 =
                    get_checksum(reinterpret_cast<uint8_t*>(buf->buf + buf_pos),
                                 block_remain,
                                 CRC32C);
            TRACE_INSTANT2("couchstore_write",
                           "raw_write",
                           "offset",
                           write_pos,
                           "nbytes&CRC",
                           block_remain << 32 | crc32);
        }

        written = file->ops->pwrite(&file->lastError, file->handle,
                                    buf->buf + buf_pos, block_remain, write_pos);
        if (written < 0) {
            return written;
        }
        buf_pos += written;
        write_pos += written;
    }

    return (ssize_t)(write_pos - pos);
}

couchstore_error_t write_header(tree_file *file, sized_buf *buf, cs_off_t *pos)
{
    cs_off_t write_pos = align_to_next_block(file->pos);
    ssize_t written;
    uint32_t size = htonl(buf->size + 4); //Len before header includes hash len.
    uint32_t crc32 = htonl(get_checksum(reinterpret_cast<uint8_t*>(buf->buf),
                                        buf->size,
                                        file->crc_mode));
    char headerbuf[1 + 4 + 4];

    *pos = write_pos;

    // Write the header's block header
    headerbuf[0] = 1;
    memcpy(&headerbuf[1], &size, 4);
    memcpy(&headerbuf[5], &crc32, 4);

    if (file->options.tracing_enabled) {
        uint32_t size_tmp = buf->size + 4;
        uint32_t crc32_tmp = ntohl(crc32);
        TRACE_INSTANT2("couchstore_write",
                       "write_header",
                       "offset",
                       write_pos,
                       "nbytes&CRC",
                       size_t(size_tmp) << 32 | crc32_tmp);
    }
    written = file->ops->pwrite(&file->lastError, file->handle,
                                &headerbuf, sizeof(headerbuf), write_pos);
    if (written < 0) {
        if (file->options.tracing_enabled) {
            TRACE_INSTANT1(
                    "couchstore_write", "write_header", "written", write_pos);
        }
        return (couchstore_error_t)written;
    }
    write_pos += written;

    //Write actual header
    written = raw_write(file, buf, write_pos);
    if (written < 0) {
        return (couchstore_error_t)written;
    }
    write_pos += written;
    file->pos = write_pos;

    return COUCHSTORE_SUCCESS;
}

int db_write_buf(tree_file *file, const sized_buf *buf, cs_off_t *pos, size_t *disk_size)
{
    cs_off_t write_pos = file->pos;
    cs_off_t end_pos = write_pos;
    ssize_t written;
    uint32_t size = htonl(buf->size | 0x80000000);
    uint32_t crc32 = htonl(get_checksum(reinterpret_cast<uint8_t*>(buf->buf),
                                        buf->size,
                                        file->crc_mode));
    char headerbuf[4 + 4];

    // Write the buffer's header:
    memcpy(&headerbuf[0], &size, 4);
    memcpy(&headerbuf[4], &crc32, 4);

    if ((file->options.tracing_enabled) && (size == 0 && crc32 == 0)) {
        TRACE_INSTANT2("couchstore_write",
                       "Warning:db_write_buf",
                       "size",
                       size,
                       "CRC",
                       crc32);
    }

    sized_buf sized_headerbuf = { headerbuf, 8 };
    written = raw_write(file, &sized_headerbuf, end_pos);
    if (written < 0) {
        return (int)written;
    }
    end_pos += written;

    // Write actual buffer:
    written = raw_write(file, buf, end_pos);
    if (written < 0) {
        return (int)written;
    }
    end_pos += written;

    if (pos) {
        *pos = write_pos;
    }

    file->pos = end_pos;
    if (disk_size) {
        *disk_size = (size_t) (end_pos - write_pos);
    }

    return 0;
}

couchstore_error_t db_write_buf_compressed(tree_file *file, const sized_buf *buf, cs_off_t *pos, size_t *disk_size)
{
    couchstore_error_t errcode = COUCHSTORE_SUCCESS;
    sized_buf to_write;
    size_t max_size = snappy::MaxCompressedLength(buf->size);

    char* compressbuf = static_cast<char *>(cb_malloc(max_size));
    to_write.buf = compressbuf;
    to_write.size = max_size;
    error_unless(to_write.buf, COUCHSTORE_ERROR_ALLOC_FAIL);

    snappy::RawCompress(buf->buf, buf->size, to_write.buf, &to_write.size);

    error_pass(static_cast<couchstore_error_t>(db_write_buf(file, &to_write, pos, disk_size)));
cleanup:
    cb_free(compressbuf);
    return errcode;
}
