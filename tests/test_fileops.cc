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

#include "test_fileops.h"

MockOps::MockOps(FileOpsInterface* ops) : wrapped_ops(ops) {
    DelegateToFake();
}

MockOps::~MockOps() {
}

using ::testing::Invoke;
using ::testing::_;

FileOpsInterface* MockOps::get_wrapped() {
    return wrapped_ops.get();
}

void MockOps::DelegateToFake() {
    ON_CALL(*this, pwrite(_, _, _, _, _))
            .WillByDefault(Invoke(wrapped_ops.get(), &FileOpsInterface::pwrite));
    ON_CALL(*this, pread(_, _, _, _, _))
            .WillByDefault(Invoke(wrapped_ops.get(), &FileOpsInterface::pread));
    ON_CALL(*this, sync(_, _))
            .WillByDefault(Invoke(wrapped_ops.get(), &FileOpsInterface::sync));
    ON_CALL(*this, constructor(_))
            .WillByDefault(Invoke(wrapped_ops.get(), &FileOpsInterface::constructor));
    ON_CALL(*this, destructor(_))
            .WillByDefault(Invoke(wrapped_ops.get(), &FileOpsInterface::destructor));
    ON_CALL(*this, open(_, _, _, _))
            .WillByDefault(Invoke(wrapped_ops.get(), &FileOpsInterface::open));
    ON_CALL(*this, close(_, _))
            .WillByDefault(Invoke(wrapped_ops.get(), &FileOpsInterface::close));
    ON_CALL(*this, set_periodic_sync(_, _))
            .WillByDefault(Invoke(wrapped_ops.get(),
                                  &FileOpsInterface::set_periodic_sync));
    ON_CALL(*this, goto_eof(_, _))
            .WillByDefault(Invoke(wrapped_ops.get(), &FileOpsInterface::goto_eof));
    ON_CALL(*this, advise(_, _, _, _, _))
        .WillByDefault(Invoke(wrapped_ops.get(), &FileOpsInterface::advise));
    ON_CALL(*this, set_tracing_enabled(_))
            .WillByDefault(Invoke(wrapped_ops.get(),
                                  &FileOpsInterface::set_tracing_enabled));
    ON_CALL(*this, set_write_validation_enabled(_))
            .WillByDefault(
                    Invoke(wrapped_ops.get(),
                           &FileOpsInterface::set_write_validation_enabled));
    ON_CALL(*this, set_mprotect_enabled(_))
            .WillByDefault(Invoke(wrapped_ops.get(),
                                  &FileOpsInterface::set_mprotect_enabled));
}

LogOps::LogOps(FileOpsInterface* ops) : wrapped_ops(ops) {}

LogOps::~LogOps() {}

couch_file_handle LogOps::constructor(couchstore_error_info_t* errinfo) {
    auto rv = wrapped_ops->constructor(errinfo);
    std::cerr << "@constructor(" << errinfo << ") -> " << rv << std::endl;
    return rv;
}

couchstore_error_t LogOps::open(couchstore_error_info_t* errinfo,
                                couch_file_handle* handle, const char* path,
                                int oflag) {
    auto rv = wrapped_ops->open(errinfo, handle, path, oflag);
    std::cerr << "@open(" << errinfo << ", " << handle << ", " << path << ", "
              << oflag << ") -> " << rv << std::endl;
    return rv;
}

couchstore_error_t LogOps::close(couchstore_error_info_t* errinfo,
                                 couch_file_handle handle) {
    auto rv = wrapped_ops->close(errinfo, handle);
    std::cerr << "@close(" << errinfo << ", " << handle << ") -> "
              << rv << std::endl;
    return rv;
}

ssize_t LogOps::pread(couchstore_error_info_t* errinfo,
                      couch_file_handle handle, void* buf, size_t nbytes,
                      cs_off_t offset) {
    auto rv = wrapped_ops->pread(errinfo, handle, buf, nbytes, offset);
    std::cerr << "@pread(" << errinfo << ", " << handle << ", " << buf << ", "
              << nbytes << ", " << offset << ") -> " << rv << std::endl;
    return rv;
}

ssize_t LogOps::pwrite(couchstore_error_info_t* errinfo,
                       couch_file_handle handle, const void* buf, size_t nbytes,
                       cs_off_t offset) {
    auto rv = wrapped_ops->pwrite(errinfo, handle, buf, nbytes, offset);
    std::cerr << "@pwrite(" << errinfo << ", " << handle << ", " << buf << ", "
              << nbytes << ", " << offset << ") -> " << rv << std::endl;
    return rv;
}

cs_off_t LogOps::goto_eof(couchstore_error_info_t* errinfo,
                          couch_file_handle handle) {
    auto rv = wrapped_ops->goto_eof(errinfo, handle);
    std::cerr << "@goto_eof(" << errinfo << ", " << handle << ") -> "
              << rv << std::endl;
    return rv;
}

couchstore_error_t LogOps::sync(couchstore_error_info_t* errinfo,
                                couch_file_handle handle) {
    auto rv = wrapped_ops->sync(errinfo, handle);
    std::cerr << "@sync(" << errinfo << ", " << handle << ") -> "
              << rv << std::endl;
    return rv;
}

couchstore_error_t LogOps::advise(couchstore_error_info_t* errinfo,
                                  couch_file_handle handle, cs_off_t offset,
                                  cs_off_t len,
                                  couchstore_file_advice_t advice) {
    auto rv = wrapped_ops->advise(errinfo, handle, offset, len, advice);
    std::cerr << "@advise(" << errinfo << ", " << handle << ", " << offset
              << ", " << len << ", " << advice << ") -> " << rv << std::endl;
    return rv;
}

couchstore_error_t LogOps::set_tracing_enabled(couch_file_handle handle) {
    auto rv = wrapped_ops->set_tracing_enabled(handle);
    std::cerr << "@set_tracing_enabled(" << handle << ") -> " << rv
              << std::endl;
    return rv;
}

couchstore_error_t LogOps::set_write_validation_enabled(
        couch_file_handle handle) {
    auto rv = wrapped_ops->set_write_validation_enabled(handle);
    std::cerr << "@set_write_validation_enabled(" << handle << ") -> " << rv
              << std::endl;
    return rv;
}

couchstore_error_t LogOps::set_mprotect_enabled(couch_file_handle handle) {
    auto rv = wrapped_ops->set_mprotect_enabled(handle);
    std::cerr << "@set_mprotect_enabled(" << handle << ") -> " << rv
              << std::endl;
    return rv;
}

void LogOps::destructor(couch_file_handle handle) {
    std::cerr << "@destructor(" << handle << ")" << std::endl;
    wrapped_ops->destructor(handle);
}
