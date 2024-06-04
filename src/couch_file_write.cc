/*
 *     Copyright 2020 Couchbase, Inc.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */
#include "couchstore_config.h"

#include "crc32.h"
#include "internal.h"
#include "log_last_internal_error.h"
#include "util.h"

#include <libcouchstore/couch_db.h>
#include <phosphor/phosphor.h>
#include <platform/compress.h>
#include <sys/types.h>
#include <cstdint>

static ssize_t write_entire_buffer(tree_file *file, const void* buf,
                                   size_t nbytes, cs_off_t offset) {
    size_t left_to_write = nbytes;
    const char* src = reinterpret_cast<const char*>(buf);

    /* calculate CRC for the piece written and trace it. */
    if (file->options.tracing_enabled) {
        TRACE_INSTANT2(
                "couchstore_write",
                "write_entire_buffer",
                "offset",
                offset,
                "nbytes&CRC",
                nbytes << 32 |
                        get_checksum(reinterpret_cast<const uint8_t*>(buf),
                                     nbytes,
                                     CRC32C));
    }

    while (left_to_write) {
        ssize_t written = file->ops->pwrite(&file->lastError, file->handle,
                                            src, nbytes, offset);
        if (written < 0) {
            return written;
        }
        left_to_write -= written;
        src += written;
        offset += written;
    }
    return (ssize_t)nbytes;
}

static ssize_t raw_write(const DiskBlockType diskBlockType,
                         tree_file* file,
                         const sized_buf* buf,
                         cs_off_t pos) {
    cs_off_t write_pos = pos;
    size_t buf_pos = 0;
    ssize_t written;
    size_t block_remain;

    // break up the write buffer into blocks adding the block prefix as needed
    while (buf_pos < buf->size) {
        block_remain = COUCH_BLOCK_SIZE - (write_pos % COUCH_BLOCK_SIZE);
        if (block_remain > (buf->size - buf_pos)) {
            block_remain = buf->size - buf_pos;
        }

        if (write_pos % COUCH_BLOCK_SIZE == 0) {
            written = write_entire_buffer(file, &diskBlockType, 1, write_pos);
            if (written < 0) {
                return written;
            }
            write_pos += written;
            continue;
        }
        written = write_entire_buffer(file, buf->buf + buf_pos, block_remain, write_pos);
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
    uint8_t headerbuf[1 + 4 + 4];

    *pos = write_pos;

    // Write the header's block header
    headerbuf[0] = uint8_t(DiskBlockType::Header);
    memcpy(&headerbuf[1], &size, 4);
    memcpy(&headerbuf[5], &crc32, 4);

    written = write_entire_buffer(file, &headerbuf, sizeof(headerbuf), write_pos);
    if (written < 0) {
        if (file->options.tracing_enabled) {
            TRACE_INSTANT1(
                    "couchstore_write", "write_header", "written", write_pos);
        }
        return (couchstore_error_t)written;
    }
    write_pos += written;

    //Write actual header
    written = raw_write(DiskBlockType::Header, file, buf, write_pos);
    if (written < 0) {
        return (couchstore_error_t)written;
    }
    write_pos += written;
    file->pos = write_pos;

    return COUCHSTORE_SUCCESS;
}

couchstore_error_t db_write_buf(tree_file* file,
                                const sized_buf* buf,
                                cs_off_t* pos,
                                size_t* disk_size) {
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
    written = raw_write(DiskBlockType::Data, file, &sized_headerbuf, end_pos);
    if (written < 0) {
        return static_cast<couchstore_error_t>(written);
    }
    end_pos += written;

    // Write actual buffer:
    written = raw_write(DiskBlockType::Data, file, buf, end_pos);
    if (written < 0) {
        return static_cast<couchstore_error_t>(written);
    }
    end_pos += written;

    if (pos) {
        *pos = write_pos;
    }

    file->pos = end_pos;
    if (disk_size) {
        *disk_size = sized_headerbuf.size + buf->size;
    }

    return COUCHSTORE_SUCCESS;
}

couchstore_error_t db_write_buf_compressed(tree_file *file,
                                           const sized_buf *buf,
                                           cs_off_t *pos,
                                           size_t *disk_size)
{
    cb::compression::Buffer buffer;
    try {
        if (!cb::compression::deflateSnappy({buf->buf, buf->size}, buffer)) {
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

    return db_write_buf(file, &to_write, pos, disk_size);
}
