/*
 *     Copyright 2020 Couchbase, Inc
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
#pragma once

#include <folly/portability/SysTypes.h>
#include <folly/portability/Windows.h>
#include <cstdint>

#include "couch_common.h"

/**
 * Abstract file handle. Implementations can use it for anything
 * they want, whether a pointer to an allocated data structure, or
 * an integer such as a Unix file descriptor.
 */
using couch_file_handle = struct couch_file_handle_opaque*;

struct couchstore_error_info_t {
#ifdef WIN32
    DWORD error;
#else
    int error;
#endif
};

/**
 * An abstract base class that defines the interface of the file
 * I/O primitives used by CouchStore. Passed to couchstore_open_db_ex().
 */
class LIBCOUCHSTORE_API
FileOpsInterface {
public:
    /**
     * An interface to query statistical information about a specific file
     * handle.
     */
    class FHStats {
    public:
        virtual ~FHStats() = default;

        /**
         * Return the number of read() calls performed on this file handle
         * since it was created.
         */
        virtual size_t getReadCount() = 0;

        /**
         * Return the number of write() calls performed on this file handle
         * since it was created.
         */
        virtual size_t getWriteCount() = 0;

        /**
         * Return the number of write() bytes written to this file handle
         * since it was created.
         */
        virtual size_t getWriteBytes() = 0;
    };

    /**
     * Virtual destructor used for optional cleanup
     */
    virtual ~FileOpsInterface() = default;

    /**
     * Initialize state (e.g. allocate memory) for a file handle
     * before opening a file.  This method is optional and
     * doesn't need to do anything at all; it can just return NULL
     * if there isn't anything to do.
     *
     * Note: No error checking is done on the result of this call
     * so any failure should be handled accordingly (e.g. error
     * when calling the `open` method).
     */
    virtual couch_file_handle constructor(couchstore_error_info_t* errinfo) = 0;

    /**
     * Open a file.
     *
     * @param on input, a pointer to the file handle that was
     *        returned by the constructor function. The function
     *        can change this value if it wants to; the value
     *        stored here on return is the one that will be passed
     *        to the other functions.
     * @param path the name of the file
     * @param flags flags as specified by UNIX open(2) system call
     * @return COUCHSTORE_SUCCESS upon success.
     */
    virtual couchstore_error_t open(couchstore_error_info_t* errinfo,
                                    couch_file_handle* handle, const char* path,
                                    int oflag) = 0;

    /**
     * Close file associated with this handle.
     *
     * @param handle file handle to close
     * @return COUCHSTORE_SUCCESS upon success, COUCHSTORE_ERROR_FILE_CLOSE if
     *         there was an error.
     */
    virtual couchstore_error_t close(couchstore_error_info_t* errinfo,
                                     couch_file_handle handle) = 0;

    /**
     * Specify that sync() should automatically be called after every N bytes
     * of data written.
     * Optional - defaults to COUCHSTORE_ERROR_NOT_SUPPORTED.
     *
     * @param handle file handle to set periodic sync for.
     * @param period_bytes Perform a sync() call after the specified number of
     *        bytes have been written. Specify 0 to disabled automatic sync().
     * @return COUCHSTORE_SUCCESS upon success, or
     *         COUCHSTORE_ERROR_NOT_SUPPORTED if automatic syncing not supported.
     */
    virtual couchstore_error_t set_periodic_sync(
            couch_file_handle handle,
            uint64_t period_bytes) {
        return COUCHSTORE_ERROR_NOT_SUPPORTED;
    }

    /**
     * Specify tracing  is enabled
     *
     * @param handle file handle to set the verification mode for.
     * @return COUCHSTORE_SUCCESS upon success
     */
    virtual couchstore_error_t set_tracing_enabled(couch_file_handle handle) {
        return COUCHSTORE_ERROR_NOT_SUPPORTED;
    }

    /**
     * Specify that write validation is enabled
     *
     * @param handle file handle to set the verification mode for.
     * @return COUCHSTORE_SUCCESS upon success
     */
    virtual couchstore_error_t set_write_validation_enabled(
            couch_file_handle handle) {
        return COUCHSTORE_ERROR_NOT_SUPPORTED;
    }

    /**
     * Specify that mprotect is enabled
     *
     * @param handle file handle to set the verification mode for.
     * @return COUCHSTORE_SUCCESS upon success
     */
    virtual couchstore_error_t set_mprotect_enabled(couch_file_handle handle) {
        return COUCHSTORE_ERROR_NOT_SUPPORTED;
    }

    /**
     * Read a chunk of data from a given offset in the file.
     *
     * @param handle file handle to read from
     * @param buf where to store data
     * @param nbyte number of bytes to read
     * @param offset where to read from
     * @return number of bytes read (which may be less than nbytes),
     *         or a value <= 0 if an error occurred
     */
    virtual ssize_t pread(couchstore_error_info_t* errinfo,
                          couch_file_handle handle, void* buf, size_t nbytes,
                          cs_off_t offset) = 0;

    /**
     * Write a chunk of data to a given offset in the file.
     *
     * @param handle file handle to write to
     * @param buf where to read data
     * @param nbyte number of bytes to write
     * @param offset where to write to
     * @return number of bytes written (which may be less than nbytes),
     *         or a value <= 0 if an error occurred
     */
    virtual ssize_t pwrite(couchstore_error_info_t* errinfo,
                           couch_file_handle handle, const void* buf,
                           size_t nbytes, cs_off_t offset) = 0;

    /**
     * Find the end of the file.
     *
     * @param handle file handle to find the offset for
     * @return the offset (from beginning of the file), or -1 if
     *         the operation failed
     */
    virtual cs_off_t goto_eof(couchstore_error_info_t* errinfo,
                              couch_file_handle handle) = 0;

    /**
     * Flush the buffers to disk
     *
     * @param handle file handle to flush
     * @return COUCHSTORE_SUCCESS upon success
     */
    virtual couchstore_error_t sync(couchstore_error_info_t* errinfo,
                                    couch_file_handle handle) = 0;

    /**
     * Give filesystem caching advice.
     * @param handle file handle to give advice on
     * @param offset offset to start at
     * @param len length of range to advise on
     * @param advice the advice type, see couchstore_file_advice_t
     *        in couch_common.h
     */
    virtual couchstore_error_t advise(couchstore_error_info_t* errinfo,
                                      couch_file_handle handle, cs_off_t offset,
                                      cs_off_t len,
                                      couchstore_file_advice_t advice) = 0;

    /**
     * Inform the file handlers the type of subsequent accesses.
     */
    virtual void tag(couch_file_handle handle, FileTag tag) {
    }

    /**
     * Request stats associated with this file handle.
     * Optional; subclasses may not support per-fileHandle stats; in which case
     * nullptr is returned.
     */
    virtual FHStats* get_stats(couch_file_handle handle) {
        return nullptr;
    }

    /**
     * Called as part of shutting down the db instance this instance was
     * passed to. A hook to for releasing allocated resources
     *
     * @param handle file handle to be released
     */
    virtual void destructor(couch_file_handle handle) = 0;
};

class ScopedFileTag {
public:
    ScopedFileTag(FileOpsInterface* ops, couch_file_handle handle, FileTag tag)
        : ops(ops), handle(handle) {
        ops->tag(handle, tag);
    }

    ~ScopedFileTag() {
        ops->tag(handle, FileTag::Unknown);
    }

private:
    FileOpsInterface* ops;
    couch_file_handle handle;
};
