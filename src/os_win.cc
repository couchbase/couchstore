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
#include "couchstore_config.h"

#include "internal.h"

#include <errno.h>
#include <fcntl.h>
#include <io.h>
#include <platform/cbassert.h>
#include <share.h>
#include <sys/types.h>

#undef LOG_IO
#ifdef LOG_IO
#include <cstdio>
#endif

static DWORD save_windows_error(couchstore_error_info_t *errinfo) {
    DWORD err = GetLastError();
    if (errinfo) {
        errinfo->error = err;
    }

    return err;
}

static HANDLE handle_to_win(couch_file_handle handle)
{
    return (HANDLE)(intptr_t)handle;
}

static couch_file_handle win_to_handle(HANDLE hdl)
{
    return (couch_file_handle)(intptr_t)hdl;
}

class WindowsFileOps : public FileOpsInterface {
public:
    WindowsFileOps() {}

    couch_file_handle constructor(couchstore_error_info_t* errinfo) override ;
    couchstore_error_t open(couchstore_error_info_t* errinfo,
                            couch_file_handle* handle, const char* path,
                            int oflag) override;
    couchstore_error_t close(couchstore_error_info_t* errinfo,
                             couch_file_handle handle) override;
    couchstore_error_t set_periodic_sync(couch_file_handle handle,
                                         uint64_t period_bytes) override;
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
        File(HANDLE fh = INVALID_HANDLE_VALUE) : fh(fh) {
        }

        /// File handle to operate on.
        HANDLE fh;

        /**
         * If non-zero, specifies that sync() should automatically be called
         * after every N bytes are written.
         */
        uint64_t periodic_sync_bytes = 0;

        /// Count of how many bytes have been written since the last sync().
        uint64_t bytes_written_since_last_sync = 0;
    };

    static File* to_file(couch_file_handle handle)
    {
        return reinterpret_cast<File*>(handle);
    }
};

ssize_t WindowsFileOps::pread(couchstore_error_info_t* errinfo,
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
    BOOL rv;
    DWORD bytesread;
    OVERLAPPED winoffs;
    memset(&winoffs, 0, sizeof(winoffs));
    winoffs.Offset = offset & 0xFFFFFFFF;
    winoffs.OffsetHigh = (offset >> 32) & 0x7FFFFFFF;
    rv = ReadFile(file->fh, buf, nbyte, &bytesread, &winoffs);
    if(!rv) {
        save_windows_error(errinfo);
        return (ssize_t) COUCHSTORE_ERROR_READ;
    }
    return bytesread;
}

ssize_t WindowsFileOps::pwrite(couchstore_error_info_t *errinfo,
                               couch_file_handle handle,
                               const void *buf,
                               size_t nbyte,
                               cs_off_t offset)
{
#ifdef LOG_IO
    fprintf(stderr, "PWRITE %8llx -- %8llx  (%6.1f kbytes)\n", offset,
            offset+nbyte, nbyte/1024.0);
#endif
    auto* file = to_file(handle);
    BOOL rv;
    DWORD byteswritten;
    OVERLAPPED winoffs;
    memset(&winoffs, 0, sizeof(winoffs));
    winoffs.Offset = offset & 0xFFFFFFFF;
    winoffs.OffsetHigh = (offset >> 32) & 0x7FFFFFFF;
    rv = WriteFile(file->fh, buf, nbyte, &byteswritten, &winoffs);
    if(!rv) {
        save_windows_error(errinfo);
        return (ssize_t) COUCHSTORE_ERROR_WRITE;
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

    return byteswritten;
}

couchstore_error_t WindowsFileOps::open(couchstore_error_info_t *errinfo,
                                        couch_file_handle* handle,
                                        const char* path,
                                        int oflag)
{
    auto* file = to_file(*handle);
    if (file) {
        cb_assert(file->fh == INVALID_HANDLE_VALUE);
        delete file;
        *handle = nullptr;
    }

    int creationflag = OPEN_EXISTING;
    if(oflag & O_CREAT) {
        creationflag = OPEN_ALWAYS;
    }
    if (oflag & O_EXCL) {
        creationflag = CREATE_NEW;
    }

    HANDLE os_handle =
            CreateFileA(path,
                        GENERIC_READ | GENERIC_WRITE,
                        FILE_SHARE_DELETE | FILE_SHARE_WRITE | FILE_SHARE_READ,
                        nullptr,
                        creationflag,
                        0,
                        nullptr);

    if(os_handle == INVALID_HANDLE_VALUE) {
        DWORD last_error = save_windows_error(errinfo);
        if(last_error == ERROR_FILE_NOT_FOUND ||
                last_error == ERROR_SUCCESS) {
            return COUCHSTORE_ERROR_NO_SUCH_FILE;
        };
        return COUCHSTORE_ERROR_OPEN_FILE;
    }
    /* Tell the caller about the new handle (file descriptor) */
    file = new File(os_handle);
    *handle = reinterpret_cast<couch_file_handle>(file);
    return COUCHSTORE_SUCCESS;
}

couchstore_error_t WindowsFileOps::close(couchstore_error_info_t* errinfo,
                                         couch_file_handle handle)
{
    auto* file = to_file(handle);
    if(!CloseHandle(file->fh)) {
        save_windows_error(errinfo);
        return COUCHSTORE_ERROR_FILE_CLOSE;
    }
    return COUCHSTORE_SUCCESS;
}

couchstore_error_t WindowsFileOps::set_periodic_sync(couch_file_handle handle,
                                                     uint64_t period_bytes) {
    auto* file = to_file(handle);
    file->periodic_sync_bytes = period_bytes;
    return COUCHSTORE_SUCCESS;
}

cs_off_t WindowsFileOps::goto_eof(couchstore_error_info_t* errinfo,
                                  couch_file_handle handle)
{
    auto* file = to_file(handle);
    LARGE_INTEGER size;
    if(!GetFileSizeEx(file->fh, &size)) {
        save_windows_error(errinfo);
        return (cs_off_t) COUCHSTORE_ERROR_READ;
    }
    return size.QuadPart;
}


couchstore_error_t WindowsFileOps::sync(couchstore_error_info_t* errinfo,
                                        couch_file_handle handle)
{
    auto* file = to_file(handle);

    if (!FlushFileBuffers(file->fh)) {
        save_windows_error(errinfo);
        return COUCHSTORE_ERROR_WRITE;
    }

    return COUCHSTORE_SUCCESS;
}

couch_file_handle WindowsFileOps::constructor(couchstore_error_info_t* errinfo)
{

    /*  We don't have a file descriptor till couch_open runs,
        so return an invalid value for now. */
    return reinterpret_cast<couch_file_handle>(new File());
}

void WindowsFileOps::destructor(couch_file_handle handle)
{
    auto* file = to_file(handle);
    delete file;
}

couchstore_error_t WindowsFileOps::advise(couchstore_error_info_t* errinfo,
                                          couch_file_handle handle,
                                          cs_off_t offset,
                                          cs_off_t len,
                                          couchstore_file_advice_t advice)
{
    return COUCHSTORE_SUCCESS;
}

WindowsFileOps default_file_ops;

FileOpsInterface* couchstore_get_default_file_ops(void)
{
    return &default_file_ops;
}

FileOpsInterface* create_default_file_ops(void)
{
    return new WindowsFileOps();
}
