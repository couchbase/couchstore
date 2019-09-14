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

#ifndef LIBCOUCHSTORE_IOBUFFER_H
#define LIBCOUCHSTORE_IOBUFFER_H 1

#include <libcouchstore/couch_db.h>

/* Buffered IO parameters */
struct buffered_file_ops_params {
    buffered_file_ops_params();
    buffered_file_ops_params(const buffered_file_ops_params& src);
    buffered_file_ops_params(const bool _read_only,
                             bool _tracing_enabled,
                             bool _write_validation_enabled,
                             bool _mprotect_enabled,
                             const uint32_t _read_buffer_capacity,
                             const uint32_t _max_read_buffers);

    // Flag indicating whether or not the file is being opened as read only.
    bool readOnly;
    /* Flags for tracing and validation */
    bool tracing_enabled;
    bool write_validation_enabled;
    bool mprotect_enabled;
    // Read buffer capacity.
    uint32_t read_buffer_capacity;
    // Max read buffer count.
    uint32_t max_read_buffers;
};

/**
 * Constructs a set of file ops that buffer the I/O provided by an
 * underlying set of raw ops.
 *
 * @param raw_ops the file ops callbacks to use for the underlying I/O
 * @param handle on output, a constructed (but not opened) couch_file_handle
 * @param params buffered IO parameters
 * @return the couch_file_ops to use, or NULL on failure
 */
FileOpsInterface* couch_get_buffered_file_ops(couchstore_error_info_t *errinfo,
                                              FileOpsInterface* raw_ops,
                                              couch_file_handle* handle,
                                              buffered_file_ops_params params);

class BufferedFileOps : public FileOpsInterface {
public:
    BufferedFileOps() {}

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
    FHStats* get_stats(couch_file_handle handle) override;

    void destructor(couch_file_handle handle) override;

    couch_file_handle constructor(couchstore_error_info_t *errinfo,
                                  FileOpsInterface* raw_ops,
                                  buffered_file_ops_params params);
};

#endif // LIBCOUCHSTORE_IOBUFFER_H
