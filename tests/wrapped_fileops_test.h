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
#include "test_fileops.h"
#include "internal.h"

#include <folly/portability/GMock.h>
#include <folly/portability/GTest.h>

/**
 * These tests are used to explicitly test that an Ops
 * implementation which wraps another will correctly
 * propogate any errors returned from the underlying file
 * ops.
 *
 * This is done by passing in an instance of MockOps to
 * wrap and injecting errors on various method calls.
 *
 * There are roughly three groups of tests:
 *
 * - Those that make sense for all wrapping FileOps `WrappedOpsTest`
 * - Those that make sense for all unbuffered FileOps `UnbufferedWrappedOpsTest`
 * - Those that make sense only for Buffering FileOps `BufferedWrappedOpsTest`
 */

const int FILE_FLAGS = O_CREAT | O_RDWR;

template <class T>
class WrappedOpsTest : public ::testing::Test {
public:
    WrappedOpsTest();
    ~WrappedOpsTest();

    void populate(size_t length);

protected:
    MockOps* mock_ops;
    T ops;
    couchstore_error_info_t errinfo;
    couchstore_error_t error;
    couch_file_handle handle;
    char buf[4096];

    std::string file_path;
};

template <class T>
WrappedOpsTest<T>::WrappedOpsTest()
    // Due to certain complexities the ownerhip semantics of
    // MockOps is somewhat unclear.
    //
    // Is is owned by the `T ops` object and WrappedOpsTest
    // holds a pointer to the MockOps in order to perform the
    // error injection.
    : mock_ops(new testing::NiceMock<MockOps>(create_default_file_ops())),
      ops(mock_ops),
      handle(0),
      file_path("wrapped_ops_test.couch") {
    this->handle = this->ops.constructor(&this->errinfo);
}

template <class T>
WrappedOpsTest<T>::~WrappedOpsTest() {
    testing::Mock::VerifyAndClearExpectations(this->mock_ops);
    this->ops.close(&this->errinfo, this->handle);
    this->ops.destructor(this->handle);
    remove(file_path.c_str());
}

template <class T>
void WrappedOpsTest<T>::populate(size_t length) {
    std::vector<char> inp(length, 'H');
    ASSERT_EQ(static_cast<ssize_t>(length),
              ops.pwrite(&this->errinfo, this->handle, &inp.front(), length, 0));
}

template <class T>
class UnbufferedWrappedOpsTest : public WrappedOpsTest<T> {
};

template <class T>
class BufferedWrappedOpsTest : public UnbufferedWrappedOpsTest<T> {
};

TYPED_TEST_CASE_P(WrappedOpsTest);
TYPED_TEST_CASE_P(BufferedWrappedOpsTest);
TYPED_TEST_CASE_P(UnbufferedWrappedOpsTest);

using namespace testing;

TYPED_TEST_P(WrappedOpsTest, open) {
    EXPECT_CALL(*this->mock_ops,
                open(_, _, _, _)).WillOnce(Return(COUCHSTORE_ERROR_OPEN_FILE));
    EXPECT_EQ(COUCHSTORE_ERROR_OPEN_FILE,
              this->ops.open(&this->errinfo, &this->handle,
                             this->file_path.c_str(), FILE_FLAGS));
}

TYPED_TEST_P(WrappedOpsTest, close) {
    ASSERT_EQ(COUCHSTORE_SUCCESS,
              this->ops.open(&this->errinfo, &this->handle,
                             this->file_path.c_str(), FILE_FLAGS));

    EXPECT_CALL(*this->mock_ops,
                close(_, _)).WillOnce(Return(COUCHSTORE_ERROR_FILE_CLOSE));

    EXPECT_EQ(COUCHSTORE_ERROR_FILE_CLOSE,
              this->ops.close(&this->errinfo, this->handle));
}

TYPED_TEST_P(WrappedOpsTest, pread_single) {
    ASSERT_EQ(COUCHSTORE_SUCCESS,
              this->ops.open(&this->errinfo, &this->handle,
                             this->file_path.c_str(), FILE_FLAGS));
    this->populate(1);
    EXPECT_CALL(*this->mock_ops,
                pread(_, _, _, _, _)).WillOnce(Return(COUCHSTORE_ERROR_FILE_CLOSE));

    EXPECT_EQ(COUCHSTORE_ERROR_FILE_CLOSE,
              this->ops.pread(&this->errinfo, this->handle, &this->buf, 1, 0));
}

TYPED_TEST_P(WrappedOpsTest, sync) {
    ASSERT_EQ(COUCHSTORE_SUCCESS,
              this->ops.open(&this->errinfo, &this->handle,
                             this->file_path.c_str(), FILE_FLAGS));
    EXPECT_CALL(*this->mock_ops,
                sync(_, _)).WillOnce(Return(COUCHSTORE_ERROR_WRITE));

    EXPECT_EQ(COUCHSTORE_ERROR_WRITE,
              this->ops.sync(&this->errinfo, this->handle));
}

TYPED_TEST_P(WrappedOpsTest, goto_eof) {
    ASSERT_EQ(COUCHSTORE_SUCCESS,
              this->ops.open(&this->errinfo, &this->handle,
                             this->file_path.c_str(), FILE_FLAGS));
    EXPECT_CALL(*this->mock_ops,
                goto_eof(_, _)).WillOnce(Return(COUCHSTORE_ERROR_READ));

    EXPECT_EQ(COUCHSTORE_ERROR_READ,
              this->ops.goto_eof(&this->errinfo, this->handle));
}

TYPED_TEST_P(WrappedOpsTest, advise) {
    ASSERT_EQ(COUCHSTORE_SUCCESS,
              this->ops.open(&this->errinfo, &this->handle,
                             this->file_path.c_str(), FILE_FLAGS));
    EXPECT_CALL(*this->mock_ops,
                advise(_, _, _, _, _)).WillOnce(Return(COUCHSTORE_ERROR_READ));

    EXPECT_EQ(COUCHSTORE_ERROR_READ,
              this->ops.advise(&this->errinfo, this->handle, 0, 1,
                               COUCHSTORE_FILE_ADVICE_EVICT));
}

/**
 * Reads the same memory location twice with an error
 * on the second invocation. This should fail with any
 * buffering as they'll remember the initial result.
 */
TYPED_TEST_P(UnbufferedWrappedOpsTest, pread_double_cacheable) {
    ASSERT_EQ(COUCHSTORE_SUCCESS,
              this->ops.open(&this->errinfo, &this->handle,
                             this->file_path.c_str(), FILE_FLAGS));
    this->populate(1);
    ASSERT_EQ(1,
              this->ops.pread(&this->errinfo, this->handle, &this->buf, 1, 0));

    EXPECT_CALL(*this->mock_ops,
                pread(_, _, _, _, _)).WillOnce(Return(COUCHSTORE_ERROR_READ));

    EXPECT_EQ(COUCHSTORE_ERROR_READ,
              this->ops.pread(&this->errinfo, this->handle, &this->buf, 1, 0));
}

/**
 * Same as previous except reading two memory locations
 * further apart than the default IOBuffer read buffer size
 */
TYPED_TEST_P(WrappedOpsTest, pread_double_cachebuster) {
    ASSERT_EQ(COUCHSTORE_SUCCESS,
              this->ops.open(&this->errinfo, &this->handle,
                             this->file_path.c_str(), FILE_FLAGS));
    this->populate(17000);
    ASSERT_EQ(1,
              this->ops.pread(&this->errinfo, this->handle, &this->buf, 1, 0));

    EXPECT_CALL(*this->mock_ops,
                pread(_, _, _, _, _)).WillOnce(Return(COUCHSTORE_ERROR_READ));

    EXPECT_EQ(COUCHSTORE_ERROR_READ,
              this->ops.pread(&this->errinfo, this->handle, &this->buf, 1, 16900));
}

TYPED_TEST_P(UnbufferedWrappedOpsTest, pwrite_cacheable) {
    ASSERT_EQ(COUCHSTORE_SUCCESS,
              this->ops.open(&this->errinfo, &this->handle,
                             this->file_path.c_str(), FILE_FLAGS));
    EXPECT_CALL(*this->mock_ops,
                pwrite(_, _, _, _, _)).WillOnce(Return(COUCHSTORE_ERROR_WRITE));
    std::vector<char> inp(4096, 'H');
    EXPECT_EQ(COUCHSTORE_ERROR_WRITE,
              this->ops.pwrite(&this->errinfo, this->handle, &inp.front(), 4096, 0));
}

TYPED_TEST_P(WrappedOpsTest, pwrite_cachebuster) {
    ASSERT_EQ(COUCHSTORE_SUCCESS,
              this->ops.open(&this->errinfo, &this->handle,
                             this->file_path.c_str(), FILE_FLAGS));
    EXPECT_CALL(*this->mock_ops,
                pwrite(_, _, _, _, _)).WillOnce(Return(COUCHSTORE_ERROR_WRITE));
    std::vector<char> inp(129 * 1024, 'H');
    EXPECT_EQ(COUCHSTORE_ERROR_WRITE,
              this->ops.pwrite(&this->errinfo, this->handle, &inp.front(), 129 * 1024, 0));
}

/**
 * Buffer should perform a pwrite to flush the buffer when syncing
 * and propogate this error (without actually doing the sync).
 */
TYPED_TEST_P(BufferedWrappedOpsTest, sync_bufferflush) {
    ASSERT_EQ(COUCHSTORE_SUCCESS,
              this->ops.open(&this->errinfo, &this->handle,
                             this->file_path.c_str(), FILE_FLAGS));
    EXPECT_CALL(*this->mock_ops,
                pwrite(_, _, _, _, _)).WillOnce(Return(COUCHSTORE_ERROR_FILE_CLOSE));
    EXPECT_CALL(*this->mock_ops,
                sync(_, _)).Times(0);
    this->populate(1);
    EXPECT_EQ(COUCHSTORE_ERROR_FILE_CLOSE,
              this->ops.sync(&this->errinfo, this->handle));
}

REGISTER_TYPED_TEST_CASE_P(
    WrappedOpsTest,
    open, close, pread_single, sync, goto_eof,
    advise, pread_double_cachebuster, pwrite_cachebuster);

REGISTER_TYPED_TEST_CASE_P(
    UnbufferedWrappedOpsTest,
    pread_double_cacheable, pwrite_cacheable);

REGISTER_TYPED_TEST_CASE_P(
    BufferedWrappedOpsTest,
    sync_bufferflush);
