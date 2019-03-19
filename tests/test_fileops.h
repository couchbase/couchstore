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

#pragma once

#include "config.h"
#include <libcouchstore/couch_db.h>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "gmock/gmock.h"

/**
 * This is a 'Mock' implementation of a FileOpsInterface. It usually
 * delegates calls to its methods to the FileOpsInterface instance
 * `wrapped_ops`.
 *
 * It can be driven, if required, to return errors etc. by using the
 * Google Mock API.
 */
class MockOps : public FileOpsInterface {
public:
    MockOps(FileOpsInterface* ops);
    ~MockOps();

    MOCK_METHOD0(version, uint64_t());
    MOCK_METHOD1(constructor,
                 couch_file_handle(couchstore_error_info_t* errinfo));
    MOCK_METHOD4(open, couchstore_error_t(couchstore_error_info_t* errinfo,
                                          couch_file_handle* handle,
                                          const char* path, int oflag));
    MOCK_METHOD2(close, couchstore_error_t(couchstore_error_info_t* errinfo,
                                           couch_file_handle handle));
    MOCK_METHOD2(set_periodic_sync,
                 couchstore_error_t(couch_file_handle handle,
                                    uint64_t period_bytes));
    MOCK_METHOD5(pread, ssize_t(couchstore_error_info_t* errinfo,
                                couch_file_handle handle, void* buf,
                                size_t nbytes, cs_off_t offset));
    MOCK_METHOD5(pwrite, ssize_t(couchstore_error_info_t* errinfo,
                                 couch_file_handle handle, const void* buf,
                                 size_t nbytes, cs_off_t offset));
    MOCK_METHOD2(goto_eof, cs_off_t(couchstore_error_info_t* errinfo,
                                    couch_file_handle handle));
    MOCK_METHOD2(sync, couchstore_error_t(couchstore_error_info_t* errinfo,
                                          couch_file_handle handle));
    MOCK_METHOD5(advise, couchstore_error_t(couchstore_error_info_t* errinfo,
                                            couch_file_handle handle,
                                            cs_off_t offset, cs_off_t len,
                                            couchstore_file_advice_t advice));
    MOCK_METHOD1(destructor, void(couch_file_handle handle));
    MOCK_METHOD1(set_tracing_enabled,
                 couchstore_error_t(couch_file_handle handle));
    MOCK_METHOD1(set_write_validation_enabled,
                 couchstore_error_t(couch_file_handle handle));
    MOCK_METHOD1(set_mprotect_enabled,
                 couchstore_error_t(couch_file_handle handle));

    void DelegateToFake();

    FileOpsInterface* get_wrapped();

protected:
    std::unique_ptr<FileOpsInterface> wrapped_ops;
};

/**
 * This is a FileOpsInterface implementation that always delegates calls
 * to the `wrapped_ops` instance. It will also log trace information about
 * the calls which are being made to stderr.
 */
class LogOps : public FileOpsInterface {
public:
    LogOps(FileOpsInterface* ops);
    ~LogOps();

    couch_file_handle constructor(couchstore_error_info_t* errinfo) override ;
    couchstore_error_t open(couchstore_error_info_t* errinfo,
                            couch_file_handle* handle, const char* path,
                            int oflag) override;
    couchstore_error_t close(couchstore_error_info_t* errinfo,
                             couch_file_handle handle) override;
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
    couchstore_error_t set_tracing_enabled(couch_file_handle handle) override;
    couchstore_error_t set_write_validation_enabled(
            couch_file_handle handle) override;
    couchstore_error_t set_mprotect_enabled(couch_file_handle handle) override;
    void destructor(couch_file_handle handle) override;
protected:
    std::unique_ptr<FileOpsInterface> wrapped_ops;
};
