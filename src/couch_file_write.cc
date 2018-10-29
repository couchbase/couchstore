/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#include "config.h"

#include <platform/cb_malloc.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <libcouchstore/couch_db.h>
#include <platform/compress.h>

#include "internal.h"
#include "crc32.h"
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
            written = file->ops->pwrite(&file->lastError, file->handle,
                                        &blockprefix, 1, write_pos);
            if (written < 0) {
                return written;
            }
            write_pos += 1;
            continue;
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

    written = file->ops->pwrite(&file->lastError, file->handle,
                                &headerbuf, sizeof(headerbuf), write_pos);
    if (written < 0) {
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

couchstore_error_t db_write_buf_compressed(tree_file *file,
                                           const sized_buf *buf,
                                           cs_off_t *pos,
                                           size_t *disk_size)
{
    cb::compression::Buffer buffer;
    try {
        using cb::compression::Algorithm;
        if (!cb::compression::deflate(Algorithm::Snappy,
                                      {buf->buf, buf->size},
                                      buffer)) {
            log_last_internal_error("Couchstore::db_write_buf_compressed() "
                                    "Compression failed buffer size:%zu", buf->size);
            return COUCHSTORE_ERROR_CORRUPT;
        }
    } catch (const std::bad_alloc&) {
        return COUCHSTORE_ERROR_ALLOC_FAIL;
    }

    sized_buf to_write{};
    to_write.buf = buffer.data();
    to_write.size = buffer.size();

    return static_cast<couchstore_error_t>(db_write_buf(file, &to_write, pos, disk_size));
}
