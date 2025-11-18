/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2016 Couchbase, Inc
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

#include "iobuffer.h"
#include "couchstore_config.h"
#include "crc32.h"
#include "internal.h"

#include <boost/intrusive/list.hpp>
#include <phosphor/phosphor.h>
#include <platform/string_hex.h>
#include <cstdlib>
#include <cstring>
#include <gsl/gsl-lite.hpp>
#include <memory>
#include <new>
#include <unordered_map>
#include <vector>

#ifndef WIN32
#include <sys/mman.h>
#endif


// Uncomment to enable debug logging of buffer operations.
// #define LOG_BUFFER 1
#if defined(LOG_BUFFER)
#include <stdio.h>
#endif

static long getPageSize() {
#ifdef WIN32
    throw std::invalid_argument(
            "getPageSize(): mprotect not implemented for win32");
#else
    static std::atomic_long pagesize{0};
    if (!pagesize) {
        auto ret = sysconf(_SC_PAGE_SIZE);
        if (ret == -1) {
            throw std::system_error(
                    errno, std::system_category(), "sysconf(_SC_PAGE_SIZE)");
        }
        pagesize = ret;
    }

    return pagesize;
#endif
}

size_t getAlignment(bool mprotect) {
    if (mprotect) {
        // mprotect need to be page aligned
        return getPageSize();
    }

    // We can do with byte alignment, but posix_memalign require a minimum
    // of sizeof(void*) so lets just use that..
    return sizeof(void*);
}

enum class AccessMode { None, Read, Write, Full };

struct BufferedFileHandle;
struct FileBuffer : public boost::intrusive::list_base_hook<> {
    FileBuffer(BufferedFileHandle& _owner,
               size_t _capacity,
               bool _tracing_enabled,
               bool _write_validation_enabled,
               bool _mprotect_enabled)
        : owner(_owner),
          capacity(_capacity),
          // Setting initial offset to 0 may cause problem
          // as there can be an actual buffer corresponding
          // to offset 0.
          offset(static_cast<cs_off_t>(-1)),
          tracing_enabled(_tracing_enabled),
          write_validation_enabled(_write_validation_enabled),
          mprotect_enabled(_mprotect_enabled),
          bytes{static_cast<uint8_t*>(cb_aligned_alloc(
                  getAlignment(mprotect_enabled), _capacity))} {
        if (!bytes) {
            throw std::bad_alloc();
        }
        setAccessMode(AccessMode::None);
    }

    ~FileBuffer() {
        // We need to remove any restrictions to the memory in case the
        // memory allocator reuse it without clearing such
        try {
            setAccessMode(AccessMode::Full);
        } catch (const std::exception&) {
            // we failed to remove the restriction so we should probably just
            // leak the memory to avoid weird stuff to happen when the memory
            // gets reused
            std::cerr << "Failed to remove protection mode for allocated "
                         "memory in FileBuffer. Leak the memory allocated at "
                      << cb::to_hex(uint64_t(bytes.get()))
                      << " to avoid crashing at a later use when the memory "
                         "gets returned from the allocator"
                      << std::endl;
            std::cout.flush();
            bytes.release();
        }
    }

    uint8_t* getRawPtr() {
        return bytes.get();
    }

    void setAccessMode(AccessMode accessMode) {
        currentAccessMode = accessMode;
#ifndef WIN32
        if (mprotect_enabled) {
            int mode = PROT_NONE;
            switch (accessMode) {
            case AccessMode::None:
                break;
            case AccessMode::Read:
                mode = PROT_READ;
                break;
            case AccessMode::Write:
                mode = PROT_WRITE;
                break;
            case AccessMode::Full:
                mode = PROT_READ | PROT_WRITE;
                break;
            }
            if (mprotect(bytes.get(), capacity, mode) == -1) {
                throw std::system_error(
                        errno, std::system_category(), "mprotect failed");
            }
        }
#endif
    }

    // Hook for intrusive list.
    boost::intrusive::list_member_hook<> _lru_hook;
    // File handle that owns this buffer instance.
    BufferedFileHandle& owner;
    // Buffer capacity.
    size_t capacity;
    // Length of data written.
    size_t length = 0;
    // Starting offset of buffer.
    cs_off_t offset;
    // Flag indicating whether or not this buffer contains dirty data.
    uint8_t dirty = 0;
    // Trace and verify flags
    bool tracing_enabled;
    bool write_validation_enabled;
    const bool mprotect_enabled;
    AccessMode currentAccessMode;

    // Data array.
    struct CbAllocDeletor {
        void operator()(uint8_t* ptr) {
            cb_aligned_free(ptr);
        }
    };
    std::unique_ptr<uint8_t, CbAllocDeletor> bytes;
};

class AccessModeGuard {
public:
    AccessModeGuard(FileBuffer& buffer, AccessMode mode) : buffer(buffer) {
        buffer.setAccessMode(mode);
    }
    ~AccessModeGuard() {
        buffer.setAccessMode(AccessMode::None);
    }

protected:
    FileBuffer& buffer;
};

using UniqueFileBufferPtr = std::unique_ptr<FileBuffer>;

using ListMember =
        boost::intrusive::member_hook<FileBuffer,
                                      boost::intrusive::list_member_hook<>,
                                      &FileBuffer::_lru_hook>;

using FileBufferList = boost::intrusive::list<FileBuffer, ListMember>;
using FileBufferMap = std::unordered_map<size_t, UniqueFileBufferPtr>;

struct BufferedFileHandle;

/**
 * Class for management of LRU list and hash index for read buffers.
 * All buffer instances are tracked by using shared pointers.
 */
class ReadBufferManager {
public:
    ReadBufferManager() = default;
    ~ReadBufferManager();
    FileBuffer* findBuffer(BufferedFileHandle* h, cs_off_t offset);
    void relocateBuffer(cs_off_t old_offset, cs_off_t new_offset);

private:
    // LRU list for buffers.
    FileBufferList readLRU;
    // Map from offset to buffer instance.
    FileBufferMap readMap;
    // Number of buffers allocated.
    size_t nBuffers = 0;
};

// How I interpret a couch_file_handle:
struct BufferedFileHandle {
    BufferedFileHandle(FileOpsInterface* raw_ops,
                       couch_file_handle raw_ops_handle,
                       buffered_file_ops_params params)
        : raw_ops(raw_ops), raw_ops_handle(raw_ops_handle), params(params) {
    }
    FileOpsInterface* raw_ops;
    couch_file_handle raw_ops_handle;
    UniqueFileBufferPtr write_buffer;
    std::unique_ptr<ReadBufferManager> read_buffer_mgr;
    buffered_file_ops_params params;
};

ReadBufferManager::~ReadBufferManager() {
    // Note: all elements in intrusive list MUST be unlinked
    //       before they are freed (unless it will internally
    //       invoke an assertion failure).
    auto itr = readLRU.begin();
    while (itr != readLRU.end()) {
        itr = readLRU.erase(itr);
    }
}

FileBuffer* ReadBufferManager::findBuffer(BufferedFileHandle* h,
                                          cs_off_t offset) {
    // Align offset.
    offset = offset - offset % h->params.read_buffer_capacity;

    // Find a buffer for this offset,
    // OR use the last one in LRU list.
    FileBuffer* buffer = nullptr;
    auto itr_map = readMap.find(offset);
    if (itr_map != readMap.end()) {
        // Matching buffer exists.
        // Move it to the front of LRU, and return.
        buffer = itr_map->second.get();
        readLRU.splice(readLRU.begin(), readLRU, readLRU.iterator_to(*buffer));
        return buffer;
    }

    // ==== Otherwise: not found.

    if (nBuffers < h->params.max_read_buffers) {
        // We can still create another buffer.
        UniqueFileBufferPtr buffer_unique;
        buffer_unique =
                std::make_unique<FileBuffer>(*h,
                                             h->params.read_buffer_capacity,
                                             h->params.tracing_enabled,
                                             h->params.write_validation_enabled,
                                             h->params.mprotect_enabled);
        buffer = buffer_unique.get();
        ++nBuffers;
        readMap.insert(
                std::make_pair(buffer->offset, std::move(buffer_unique)));
        // Locate it at the front of LRU, and return.
        readLRU.push_front(*buffer);
        return buffer;
    }

    // We cannot create a new one.
    // Recycle the last buffer in the LRU list.
    auto itr_list = readLRU.rbegin();
    buffer = &(*itr_list);
#if defined(LOG_BUFFER)
    fprintf(stderr,
            "BUFFER: %p recycled, from %zd to %zd\n",
            buffer,
            buffer->offset,
            offset);
#endif
    // Move the buffer to the front of LRU.
    readLRU.splice(readLRU.begin(), readLRU, itr_list.base());
    return buffer;
}

void ReadBufferManager::relocateBuffer(cs_off_t old_offset,
                                       cs_off_t new_offset) {
    auto itr = readMap.find(old_offset);
    if (itr == readMap.end()) {
        return;
    }

    UniqueFileBufferPtr tmp = std::move(itr->second);
    readMap.erase(itr);
    tmp->offset = new_offset;
    tmp->length = 0;
    readMap.insert(std::make_pair(new_offset, std::move(tmp)));
}

//////// BUFFER WRITES:


// Write as many bytes as possible into the buffer, returning the count
static size_t write_to_buffer(FileBuffer* buf,
                              const void* bytes,
                              size_t nbyte,
                              cs_off_t offset) {
    if (buf->length == 0) {
        // If buffer is empty, align it to start at the current offset:
        buf->offset = offset;
    } else if (offset < buf->offset || offset > buf->offset + (cs_off_t)buf->length) {
        // If it's out of range, don't write anything
        return 0;
    }
    auto offset_in_buffer = (size_t)(offset - buf->offset);
    size_t buffer_nbyte = std::min(buf->capacity - offset_in_buffer, nbyte);

    if (buf->tracing_enabled) {
        TRACE_INSTANT2("couchstore_write",
                       "write_to_buffer",
                       "offset",
                       offset,
                       "nbytes&CRC",
                       buffer_nbyte << 32 |
                               get_checksum(static_cast<const uint8_t*>(bytes),
                                            buffer_nbyte,
                                            CRC32C));
    }

    {
        AccessModeGuard guard(*buf, AccessMode::Write);
        memcpy(buf->getRawPtr() + offset_in_buffer, bytes, buffer_nbyte);
    }

    buf->dirty = 1;
    offset_in_buffer += buffer_nbyte;
    if (offset_in_buffer > buf->length)
        buf->length = offset_in_buffer;

    return buffer_nbyte;
}

// Write the current buffer to disk and empty it.
static couchstore_error_t flush_buffer(couchstore_error_info_t* errinfo,
                                       FileBuffer* buf) {
    while (buf->length > 0 && buf->dirty) {
        ssize_t raw_written;
        {
            AccessModeGuard guard(*buf, AccessMode::Read);
            raw_written = buf->owner.raw_ops->pwrite(errinfo,
                                                     buf->owner.raw_ops_handle,
                                                     buf->getRawPtr(),
                                                     buf->length,
                                                     buf->offset);

#if defined(LOG_BUFFER)
            fprintf(stderr,
                    "BUFFER: %p flush %zd bytes at %zd --> %zd\n",
                    buf,
                    buf->length,
                    buf->offset,
                    raw_written);
#endif
            if (buf->tracing_enabled) {
                TRACE_INSTANT2(
                        "couchstore_write",
                        "flush_buffer",
                        "offset",
                        buf->offset,
                        "nbytes&CRC",
                        raw_written << 32 | get_checksum(buf->getRawPtr(),
                                                         buf->length,
                                                         CRC32));
            }
        }

        if (raw_written < 0) {
            if (buf->tracing_enabled) {
                TRACE_INSTANT1("couchstore_write",
                               "flush_buffer",
                               "raw_written",
                               raw_written);
            }
            return (couchstore_error_t)raw_written;
        }
        buf->length -= raw_written;
        buf->offset += raw_written;

        {
            AccessModeGuard guard(*buf, AccessMode::Full);
            memmove(buf->getRawPtr(),
                    buf->getRawPtr() + raw_written,
                    buf->length);
        }
    }
    buf->dirty = 0;
    return COUCHSTORE_SUCCESS;
}

//////// BUFFER READS:

static size_t read_from_buffer(FileBuffer* buf,
                               void* bytes,
                               size_t nbyte,
                               cs_off_t offset) {
    if (offset < buf->offset || offset >= buf->offset + (cs_off_t)buf->length) {
        return 0;
    }
    auto offset_in_buffer = (size_t)(offset - buf->offset);
    size_t buffer_nbyte = std::min(buf->length - offset_in_buffer, nbyte);

    AccessModeGuard guard(*buf, AccessMode::Read);
    memcpy(bytes, buf->getRawPtr() + offset_in_buffer, buffer_nbyte);
    return buffer_nbyte;
}

static couchstore_error_t load_buffer_from(couchstore_error_info_t* errinfo,
                                           FileBuffer* buf,
                                           cs_off_t offset,
                                           size_t nbyte) {
    if (buf->dirty) {
        // If buffer contains data to be written, flush it first:
        couchstore_error_t err = flush_buffer(errinfo, buf);
        if (err < 0) {
            return err;
        }
    }

    if (offset < buf->offset || offset + nbyte > buf->offset + buf->capacity) {
        // Reset the buffer to empty if it has to move:
        buf->offset = offset;
        buf->length = 0;
    }

    // Read data to extend the buffer to its capacity (if possible):
    do {
        ssize_t bytes_read;
        {
            AccessModeGuard guard(*buf, AccessMode::Write);
            bytes_read =
                    buf->owner.raw_ops->pread(errinfo,
                                              buf->owner.raw_ops_handle,
                                              buf->getRawPtr() + buf->length,
                                              buf->capacity - buf->length,
                                              buf->offset + buf->length);
        }
#if defined(LOG_BUFFER)
        fprintf(stderr,
                "BUFFER: %p loaded %zd bytes from %zd\n",
                buf,
                bytes_read,
                offset + buf->length);
#endif
        if (bytes_read <= 0) {
            if (bytes_read < 0) {
                return static_cast<couchstore_error_t>(bytes_read);
            }
            break;
        }
        buf->length += bytes_read;
    } while (buf->length < buf->capacity);
    return COUCHSTORE_SUCCESS;
}

//////// PARAMS:

buffered_file_ops_params::buffered_file_ops_params()
    : readOnly(false),
      tracing_enabled(false),
      write_validation_enabled(false),
      mprotect_enabled(false),
      read_buffer_capacity(READ_BUFFER_CAPACITY),
      max_read_buffers(MAX_READ_BUFFERS) {
}

buffered_file_ops_params::buffered_file_ops_params(
        const buffered_file_ops_params& src)
    : readOnly(src.readOnly),
      tracing_enabled(src.tracing_enabled),
      write_validation_enabled(src.write_validation_enabled),
      mprotect_enabled(src.mprotect_enabled),
      read_buffer_capacity(src.read_buffer_capacity),
      max_read_buffers(src.max_read_buffers) {
}

buffered_file_ops_params::buffered_file_ops_params(
        const bool _read_only,
        bool _tracing_enabled,
        bool _write_validation_enabled,
        bool _mprotect_enabled,
        const uint32_t _read_buffer_capacity,
        const uint32_t _max_read_buffers)
    : readOnly(_read_only),
      tracing_enabled(_tracing_enabled),
      write_validation_enabled(_write_validation_enabled),
      mprotect_enabled(_mprotect_enabled),
      read_buffer_capacity(_read_buffer_capacity),
      max_read_buffers(_max_read_buffers) {
}

//////// FILE API:

void BufferedFileOps::destructor(couch_file_handle handle)
{
    auto* h = (BufferedFileHandle*)handle;
    if (!h) {
        return;
    }
    h->raw_ops->destructor(h->raw_ops_handle);

    delete h;
}

couch_file_handle BufferedFileOps::constructor(
        couchstore_error_info_t* errinfo,
        FileOpsInterface* raw_ops,
        buffered_file_ops_params params) {
    return (couch_file_handle) new BufferedFileHandle(
            raw_ops, raw_ops->constructor(errinfo), params);
}

couch_file_handle BufferedFileOps::constructor(couchstore_error_info_t* errinfo)
{
    return constructor(errinfo, couchstore_get_default_file_ops(),
                       buffered_file_ops_params());
}

couchstore_error_t BufferedFileOps::open(couchstore_error_info_t* errinfo,
                                         couch_file_handle* handle,
                                         const char* path,
                                         int oflag)
{
    auto* h = (BufferedFileHandle*)*handle;
    return h->raw_ops->open(errinfo, &h->raw_ops_handle, path, oflag);
}

couchstore_error_t BufferedFileOps::close(couchstore_error_info_t* errinfo,
                            couch_file_handle handle)
{
    auto* h = (BufferedFileHandle*)handle;
    if (!h) {
        return COUCHSTORE_ERROR_INVALID_ARGUMENTS;
    }

    if (h->write_buffer) {
        flush_buffer(errinfo, h->write_buffer.get());
    }
    return h->raw_ops->close(errinfo, h->raw_ops_handle);
}

void BufferedFileOps::allocate_read_buffer(couch_file_handle handle) {
    auto* h = (BufferedFileHandle*)handle;

    Expects(!h->read_buffer_mgr);
    h->read_buffer_mgr = std::make_unique<ReadBufferManager>();
}

void BufferedFileOps::allocate_write_buffer(couch_file_handle handle) {
    auto* h = (BufferedFileHandle*)handle;

    Expects(!h->write_buffer);
    h->write_buffer = std::make_unique<FileBuffer>(
            *h,
            h->params.readOnly ? 0 : WRITE_BUFFER_CAPACITY,
            h->params.tracing_enabled,
            h->params.write_validation_enabled,
            h->params.mprotect_enabled);
}

void BufferedFileOps::free_buffers(couch_file_handle handle) {
    auto* h = (BufferedFileHandle*)handle;
    Expects(h);

    // Free the read and write buffers to reclaim memory
    h->write_buffer.reset();
    h->read_buffer_mgr.reset();
}

couchstore_error_t BufferedFileOps::set_periodic_sync(couch_file_handle handle,
                                                      uint64_t period_bytes) {
    // Delegate to underlying file ops, given they perform the real disk
    // writes.
    auto* h = (BufferedFileHandle*)handle;
    return h->raw_ops->set_periodic_sync(h->raw_ops_handle, period_bytes);
}

couchstore_error_t BufferedFileOps::set_tracing_enabled(
        couch_file_handle handle) {
    // trigger setting tracing flags at the file level */
    auto* h = (BufferedFileHandle*)handle;
    return h->raw_ops->set_tracing_enabled(h->raw_ops_handle);
}

couchstore_error_t BufferedFileOps::set_write_validation_enabled(
        couch_file_handle handle) {
    // trigger setting write validation flags at the file level */
    auto* h = (BufferedFileHandle*)handle;
    return h->raw_ops->set_write_validation_enabled(h->raw_ops_handle);
}

couchstore_error_t BufferedFileOps::set_mprotect_enabled(
        couch_file_handle handle) {
    // trigger setting mprotect flags at the file level */
    auto* h = (BufferedFileHandle*)handle;
    return h->raw_ops->set_mprotect_enabled(h->raw_ops_handle);
}

ssize_t BufferedFileOps::pread(couchstore_error_info_t* errinfo,
                               couch_file_handle handle,
                               void *buf,
                               size_t nbyte,
                               cs_off_t offset)
{
#if defined(LOG_BUFFER)
    //fprintf(stderr, "r");
#endif
    auto* h = (BufferedFileHandle*)handle;

    // Flush the write buffer before trying to read anything:
    if (h->write_buffer) {
        auto err = flush_buffer(errinfo, h->write_buffer.get());
        if (err < 0) {
            return err;
        }
    }

    if (!h->read_buffer_mgr) {
        allocate_read_buffer(handle);
    }

    ssize_t total_read = 0;
    while (nbyte > 0) {
        FileBuffer* buffer = h->read_buffer_mgr->findBuffer(h, offset);

        // Read as much as we can from the current buffer:
        ssize_t nbyte_read = read_from_buffer(buffer, buf, nbyte, offset);
        if (nbyte_read == 0) {
            // 'nbyte_read==0' means that the returned buffer contains
            // data for other offset and needs to be recycled.

            // Move the buffer to cover the remainder of the data to be read.
            cs_off_t block_start = offset -
                                   (offset % h->params.read_buffer_capacity);
            h->read_buffer_mgr->relocateBuffer(buffer->offset, block_start);
            auto err = load_buffer_from(errinfo, buffer, block_start,
                                   (size_t)(offset + nbyte - block_start));
            if (err < 0) {
                return err;
            }

            nbyte_read = read_from_buffer(buffer, buf, nbyte, offset);
            if (nbyte_read == 0)
                break;  // must be at EOF
        }
        buf = (char*)buf + nbyte_read;
        nbyte -= nbyte_read;
        offset += nbyte_read;
        total_read += nbyte_read;
    }
    return total_read;
}

ssize_t BufferedFileOps::pwrite(couchstore_error_info_t* errinfo,
                                couch_file_handle handle,
                                const void* buf,
                                size_t nbyte,
                                cs_off_t offset)
{
#if defined(LOG_BUFFER)
    //fprintf(stderr, "w");
#endif
    if (nbyte == 0) {
        return 0;
    }

    auto* h = (BufferedFileHandle*)handle;

    if (!h->write_buffer) {
        allocate_write_buffer(handle);
    }

    FileBuffer* buffer = h->write_buffer.get();

    // Write data to the current buffer:
    size_t nbyte_written = write_to_buffer(buffer, buf, nbyte, offset);
    if (nbyte_written > 0) {
        buf = (char*)buf + nbyte_written;
        offset += nbyte_written;
        nbyte -= nbyte_written;
    }

    // Flush the buffer if it's full, or if it isn't aligned with the current write:
    if (buffer->length == buffer->capacity || nbyte_written == 0) {
        couchstore_error_t error = flush_buffer(errinfo, buffer);
        if (error < 0)
            return error;
    }

    if (nbyte > 0) {
        ssize_t written;
        // If the remaining data will fit into the buffer, write it; else write directly:
        if (nbyte <= (buffer->capacity - buffer->length)) {
            written = write_to_buffer(buffer, buf, nbyte, offset);
        } else {
            written = h->raw_ops->pwrite(errinfo, h->raw_ops_handle, buf,
                                         nbyte, offset);
#if defined(LOG_BUFFER)
            fprintf(stderr, "BUFFER: passthru %zd bytes at %zd --> %zd\n",
                    nbyte, offset, written);
#endif
            if (written < 0) {
                return written;
            }
        }
        nbyte_written += written;
    }

    return nbyte_written;
}

cs_off_t BufferedFileOps::goto_eof(couchstore_error_info_t* errinfo,
                                  couch_file_handle handle)
{
    auto* h = (BufferedFileHandle*)handle;
    return h->raw_ops->goto_eof(errinfo, h->raw_ops_handle);
}

couchstore_error_t BufferedFileOps::sync(couchstore_error_info_t* errinfo,
                                         couch_file_handle handle)
{
    auto* h = (BufferedFileHandle*)handle;

    couchstore_error_t err = COUCHSTORE_SUCCESS;
    if (h->write_buffer) {
        err = flush_buffer(errinfo, h->write_buffer.get());
    }

    if (err == COUCHSTORE_SUCCESS) {
        err = h->raw_ops->sync(errinfo, h->raw_ops_handle);
    }
    return err;
}

couchstore_error_t BufferedFileOps::advise(couchstore_error_info_t* errinfo,
                                           couch_file_handle handle,
                                           cs_off_t offs,
                                           cs_off_t len,
                                           couchstore_file_advice_t adv)
{
    auto* h = (BufferedFileHandle*)handle;
    return h->raw_ops->advise(errinfo, h->raw_ops_handle, offs, len, adv);
}

FileOpsInterface::FHStats* BufferedFileOps::get_stats(
        couch_file_handle handle) {
    // Not implemeted ourselves, just forward to wrapped ops.
    auto* h = (BufferedFileHandle*)handle;
    return h->raw_ops->get_stats(h->raw_ops_handle);
}

static BufferedFileOps ops;

FileOpsInterface* couch_get_buffered_file_ops(couchstore_error_info_t* errinfo,
                                              FileOpsInterface* raw_ops,
                                              couch_file_handle* handle,
                                              buffered_file_ops_params params)
{
    *handle = ops.constructor(errinfo, raw_ops, params);

    if (*handle) {
        return &ops;
    } else {
        return nullptr;
    }
}
