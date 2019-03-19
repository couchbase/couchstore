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
#include "config.h"
#include <errno.h>
#include <fcntl.h>
#include <phosphor/phosphor.h>
#include <platform/cbassert.h>
#include <sys/types.h>
#include "crc32.h"

#include "internal.h"

#undef LOG_IO
#ifdef LOG_IO
#include <stdio.h>
#endif

static void save_errno(couchstore_error_info_t *errinfo) {
    if (errinfo) {
        errinfo->error = errno;
    }
}

class PosixFileOps : public FileOpsInterface {
public:
    PosixFileOps() {}

    couch_file_handle constructor(couchstore_error_info_t* errinfo) override ;
    couchstore_error_t open(couchstore_error_info_t* errinfo,
                            couch_file_handle* handle, const char* path,
                            int oflag) override;
    couchstore_error_t close(couchstore_error_info_t* errinfo,
                             couch_file_handle handle) override;
    couchstore_error_t set_periodic_sync(couch_file_handle handle,
                                         uint64_t period_bytes) override;
    couchstore_error_t set_tracing_enabled(couch_file_handle handle) override;
    couchstore_error_t set_write_validation_enabled(
            couch_file_handle handle) override;
    couchstore_error_t set_mprotect_enabled(couch_file_handle handle) override;
    ssize_t pread(couchstore_error_info_t* errinfo,
                  couch_file_handle handle, void* buf, size_t nbytes,
                  cs_off_t offset) override;
    ssize_t pwrite(couchstore_error_info_t* errinfo,
                   couch_file_handle handle, const void* buf,
                   size_t nbytes, cs_off_t offset) override;
    cs_off_t goto_eof(couchstore_error_info_t* errinfo,
                      couch_file_handle handle) override;
    couchstore_error_t sync(couchstore_error_info_t* errinfo,
                            couch_file_handle handle) override;
    couchstore_error_t advise(couchstore_error_info_t* errinfo,
                              couch_file_handle handle, cs_off_t offset,
                              cs_off_t len,
                              couchstore_file_advice_t advice) override;
    void destructor(couch_file_handle handle) override;

private:
    // State of a single file handle, as returned by open().
    struct File {
        File(int fd = -1) : fd(fd) {
        }

        /// File descriptor to operate on.
        int fd;

        // If non-zero, specifies that sync() should automatically be called after
        // every N bytes are written.
        uint64_t periodic_sync_bytes = 0;

        // for tracing and verifying
        bool tracing_enabled = false;
        bool write_validation_enabled = false;
        bool mprotect_enabled = false;

        // Count of how many bytes have been written since the last sync().
        uint64_t bytes_written_since_last_sync = 0;
    };

    static File* to_file(couch_file_handle handle)
    {
        return reinterpret_cast<File*>(handle);
    }
};

ssize_t PosixFileOps::pread(couchstore_error_info_t* errinfo,
                            couch_file_handle handle,
                            void* buf,
                            size_t nbyte,
                            cs_off_t offset)
{
#ifdef LOG_IO
    fprintf(stderr, "PREAD  %8llx -- %8llx  (%6.1f kbytes)\n", offset,
            offset+nbyte, nbyte/1024.0);
#endif
    auto* file = to_file(handle);
    ssize_t rv;
    do {
        rv = ::pread(file->fd, buf, nbyte, offset);
    } while (rv == -1 && errno == EINTR);

    if (rv < 0) {
        save_errno(errinfo);
        return (ssize_t) COUCHSTORE_ERROR_READ;
    }
    return rv;
}

ssize_t PosixFileOps::pwrite(couchstore_error_info_t* errinfo,
                             couch_file_handle handle,
                             const void* buf,
                             size_t nbyte,
                             cs_off_t offset)
{
#ifdef LOG_IO
    fprintf(stderr, "PWRITE %8llx -- %8llx  (%6.1f kbytes)\n", offset,
            offset+nbyte, nbyte/1024.0);
#endif
    auto* file = to_file(handle);
    ssize_t rv;
    do {
        rv = ::pwrite(file->fd, buf, nbyte, offset);
    } while (rv == -1 && errno == EINTR);

    if (rv < 0) {
        if (file->tracing_enabled) {
            TRACE_INSTANT2("couchstore_write",
                           "pwrite_failure",
                           "offset",
                           offset,
                           "nbyte",
                           nbyte);
        }
        save_errno(errinfo);
        return (ssize_t) COUCHSTORE_ERROR_WRITE;
    }

    if (file->write_validation_enabled) {
        /* read the rv bytes or 8K bytes written and compare to verify that
           we read what we wrote */
        size_t len = (rv < 8192) ? rv : 8192;
        size_t len_to_read = len;
        char tmp[8192];
        char* read_buf = tmp;
        cs_off_t read_offset = offset;
        while (len > 0) {
            ssize_t got_bytes = ::pread(file->fd, read_buf, len, read_offset);
            if ((file->tracing_enabled) && (got_bytes <= 0)) {
                TRACE_INSTANT1("couchstore_write",
                               "pwrite_verify_CRC_mismatch",
                               "read_offset",
                               read_offset);
                break;
            }
            len -= got_bytes;
            read_offset += got_bytes;
            read_buf = (char*)read_buf + got_bytes;
        }

        uint32_t write_crc32 =
                get_checksum(reinterpret_cast<uint8_t*>(const_cast<void*>(buf)),
                             len_to_read,
                             CRC32C);
        uint32_t read_crc32 = get_checksum(
                reinterpret_cast<uint8_t*>(tmp), len_to_read, CRC32C);

        if (write_crc32 != read_crc32) {
            if (file->tracing_enabled) {
                TRACE_INSTANT2("couchstore_write",
                               "pwrite",
                               "read_crc",
                               read_crc32,
                               "write_crc",
                               write_crc32);
            }
            PHOSPHOR_INSTANCE.stop();
            return (ssize_t)COUCHSTORE_ERROR_CHECKSUM_FAIL;
        }
    }
    file->bytes_written_since_last_sync += rv;
    if ((file->periodic_sync_bytes > 0) &&
        (file->bytes_written_since_last_sync >= file->periodic_sync_bytes)) {
        couchstore_error_t sync_rv = sync(errinfo, handle);
        file->bytes_written_since_last_sync = 0;
        if (sync_rv != COUCHSTORE_SUCCESS) {
            return sync_rv;
        }
    }

    return rv;
}

couchstore_error_t PosixFileOps::open(couchstore_error_info_t* errinfo,
                                      couch_file_handle* handle,
                                      const char* path,
                                      int oflag)
{
    auto* file = to_file(*handle);
    if (file) {
        cb_assert(file->fd == -1);
        delete file;
        *handle = nullptr;
    }

    int fd;
    do {
        fd = ::open(path, oflag | O_LARGEFILE, 0666);
    } while (fd == -1 && errno == EINTR);

    if (fd < 0) {
        save_errno(errinfo);
        if (errno == ENOENT) {
            return COUCHSTORE_ERROR_NO_SUCH_FILE;
        } else {
            return COUCHSTORE_ERROR_OPEN_FILE;
        }
    }
    /* Tell the caller about the new handle (file descriptor) */
    file = new File(fd);
    *handle = reinterpret_cast<couch_file_handle>(file);
    return COUCHSTORE_SUCCESS;
}

couchstore_error_t PosixFileOps::close(couchstore_error_info_t* errinfo,
                                       couch_file_handle handle)
{
    auto* file = to_file(handle);
    int rv = 0;
    couchstore_error_t error = COUCHSTORE_SUCCESS;

    if (file->fd != -1) {
        do {
            cb_assert(file->fd >= 3);
            rv = ::close(file->fd);
        } while (rv == -1 && errno == EINTR);
    }
    if (rv < 0) {
        save_errno(errinfo);
        error = COUCHSTORE_ERROR_FILE_CLOSE;
    }
    file->fd = -1;
    return error;
}

couchstore_error_t PosixFileOps::set_periodic_sync(couch_file_handle handle,
                                                   uint64_t period_bytes) {
    auto* file = to_file(handle);
    file->periodic_sync_bytes = period_bytes;
    return COUCHSTORE_SUCCESS;
}

couchstore_error_t PosixFileOps::set_tracing_enabled(couch_file_handle handle) {
    auto* file = to_file(handle);
    file->tracing_enabled = true;
    return COUCHSTORE_SUCCESS;
}

couchstore_error_t PosixFileOps::set_write_validation_enabled(
        couch_file_handle handle) {
    auto* file = to_file(handle);
    file->write_validation_enabled = true;
    return COUCHSTORE_SUCCESS;
}

couchstore_error_t PosixFileOps::set_mprotect_enabled(
        couch_file_handle handle) {
    auto* file = to_file(handle);
    file->mprotect_enabled = true;
    return COUCHSTORE_SUCCESS;
}
cs_off_t PosixFileOps::goto_eof(couchstore_error_info_t* errinfo,
                                couch_file_handle handle)
{
    auto* file = to_file(handle);
    cs_off_t rv = lseek(file->fd, 0, SEEK_END);
    if (rv < 0) {
        save_errno(errinfo);
        rv = static_cast<cs_off_t>(COUCHSTORE_ERROR_READ);
    }
    return rv;
}


couchstore_error_t PosixFileOps::sync(couchstore_error_info_t* errinfo,
                                      couch_file_handle handle)
{
    auto* file = to_file(handle);
    int rv;
    do {
#ifdef __FreeBSD__
        rv = fsync(file->fd);
#else
        rv = fdatasync(file->fd);
#endif
    } while (rv == -1 && errno == EINTR);

    if (rv == -1) {
        TRACE_INSTANT1("couchstore_write", "sync", "rv", rv);
        save_errno(errinfo);
        return COUCHSTORE_ERROR_WRITE;
    }

    return COUCHSTORE_SUCCESS;
}

couch_file_handle PosixFileOps::constructor(couchstore_error_info_t* errinfo)
{
    (void)errinfo;
    return reinterpret_cast<couch_file_handle>(new File());
}

void PosixFileOps::destructor(couch_file_handle handle) {
    auto* file = to_file(handle);
    delete file;
}

couchstore_error_t PosixFileOps::advise(couchstore_error_info_t* errinfo,
                                        couch_file_handle handle,
                                        cs_off_t offset,
                                        cs_off_t len,
                                        couchstore_file_advice_t advice)
{
#ifdef POSIX_FADV_NORMAL
    auto* file = to_file(handle);
    int error = posix_fadvise(file->fd, offset, len, (int) advice);
    if (error != 0) {
        save_errno(errinfo);
    }
    switch(error) {
        case EINVAL:
        case ESPIPE:
            return COUCHSTORE_ERROR_INVALID_ARGUMENTS;
            break;
        case EBADF:
            return COUCHSTORE_ERROR_OPEN_FILE;
            break;
    }
#else
    (void) handle; (void)offset; (void)len; (void)advice;
    (void)errinfo;
#endif
    return COUCHSTORE_SUCCESS;
}

PosixFileOps default_file_ops;

LIBCOUCHSTORE_API
FileOpsInterface* couchstore_get_default_file_ops(void)
{
    return &default_file_ops;
}

LIBCOUCHSTORE_API
FileOpsInterface* create_default_file_ops(void)
{
    return new PosixFileOps();
}
