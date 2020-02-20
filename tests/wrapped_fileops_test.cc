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

#include "wrapped_fileops_test.h"
#include "iobuffer.h"

/**
 * This is a slightly modified version of the regular
 * BufferedFileOps class.
 *
 * The regular BufferedFileOps has a custom `constructor`
 * method outside of the FileOpsInterface. This version
 * uses its C++ constructor to set the File ops to be
 * wrapped for the `constructor` method in the interface
 * which allows it to share tests and bootstrapping with
 * other FileOps implementations.
 */
class TestBufferedFileOps : public BufferedFileOps {
public:
    TestBufferedFileOps(FileOpsInterface* ops) : wrapped_ops(ops) {
    }
    couch_file_handle constructor(couchstore_error_info_t* errinfo) override {
        return BufferedFileOps::constructor(errinfo, wrapped_ops.get(),
                                            buffered_file_ops_params());
    }

protected:
    std::unique_ptr<FileOpsInterface> wrapped_ops;
};


typedef testing::Types<LogOps, TestBufferedFileOps, testing::NiceMock<MockOps>>
    WrappedOpsImplementations;

typedef testing::Types<TestBufferedFileOps>
    BufferedWrappedOpsImplementations;

typedef testing::Types<LogOps, testing::NiceMock<MockOps>>
    UnbufferedWrappedOpsImplementations;

INSTANTIATE_TYPED_TEST_SUITE_P(CouchstoreOpsTest,
                              WrappedOpsTest,
                              WrappedOpsImplementations
                              );

INSTANTIATE_TYPED_TEST_SUITE_P(CouchstoreOpsTest,
                              UnbufferedWrappedOpsTest,
                              UnbufferedWrappedOpsImplementations
                             );

INSTANTIATE_TYPED_TEST_SUITE_P(CouchstoreOpsTest,
                              BufferedWrappedOpsTest,
                              BufferedWrappedOpsImplementations
                             );
