/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2015 Couchbase, Inc
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

#include "couchstore_config.h"
#include "test_fileops.h"
#include "documents.h"

#include <folly/portability/GMock.h>
#include <folly/portability/GTest.h>
#include <libcouchstore/couch_db.h>
#include <libcouchstore/couch_latency.h>

#include <string>
#include <vector>

/**
 * Base class for other tests
 *
 * Auto-cleans when the test is complete.
 *   a) If db is not null, closes the db
 *   b) removes testfile.couch.
 */
class CouchstoreBaseTest : public ::testing::Test {
protected:
    CouchstoreBaseTest();
    CouchstoreBaseTest(
            std::string file_path, bool display_latency_info = false);
    ~CouchstoreBaseTest() override;
    void clean_up();

    Db* db;
    const std::string filePath;
    const bool displayLatencyInfo;
};

/**
 * Fixture for tests that will run with and without encryption
 *
 * Extends CouchstoreBaseTest
 */
class CouchstoreEncryptedUnencryptedTest : public CouchstoreBaseTest {
protected:
    CouchstoreEncryptedUnencryptedTest();

    virtual bool isEncrypted() = 0;

    cb::couchstore::EncryptionKeyGetter getEncryptionKeyCB();

    couchstore_error_t open_db(couchstore_open_flags extra_flags);

private:
    cb::couchstore::SharedEncryptionKey sharedEncryptionKey;
};

class CouchstoreTest
    : public CouchstoreEncryptedUnencryptedTest,
      public ::testing::WithParamInterface<bool> {
protected:
    bool isEncrypted() override;
};

class CouchstoreDocTest
    : public CouchstoreEncryptedUnencryptedTest,
      public ::testing::WithParamInterface<std::tuple<bool, int, bool>> {
protected:
    bool isEncrypted() override;
};

/**
 * Global test class for internal only tests
 *
 * Extends CouchstoreBaseTest
 */
class CouchstoreInternalTest : public CouchstoreBaseTest {
protected:
    CouchstoreInternalTest();
    ~CouchstoreInternalTest() override;

    /**
     * Opens a database instance with the current filePath, ops and with
     * buffering disabled.
     *
     * @param extra_flags  Any additional flags, other than
     *                     COUCHSTORE_OPEN_FLAG_UNBUFFERED to open the db with.
     */
    couchstore_error_t open_db(couchstore_open_flags extra_flags);

    /**
     * Opens a database instance with the current filePath, ops and with
     * buffering disabled. It then populates the database with the
     * specified number of documents.
     *
     * @param extra_flags  Any additional flags, other than
     *                     COUCHSTORE_OPEN_FLAG_UNBUFFERED to open the db with.
     * @param count  Number of documents to populate with
     */
    void open_db_and_populate(couchstore_open_flags extra_flags, size_t count);

    /**
     * Creates a LocalDoc object from two strings
     *
     * Note: The localDoc will just point to strings' memory
     * so the strings should stay alive as long as the LocalDoc
     * does.
     *
     * @param id  ID of the document
     * @param json  Body of the document
     */
    LocalDoc create_local_doc(std::string& id, std::string& json);

    std::string compactPath;
    Documents documents;
    ::testing::NiceMock<MockOps> ops;
    DocInfo* info;
    Doc* doc;
};

/**
 * Multi-threaded test.
 */
class CouchstoreMTTest
    : public ::testing::Test,
      public ::testing::WithParamInterface<std::tuple<bool, size_t> > {
protected:
    CouchstoreMTTest();
    CouchstoreMTTest(std::string file_path);

    void TearDown();

    size_t numThreads;
    std::vector<Db*> dbs;
    std::string filePath;
};

/**
 * Test class for error injection tests
 */
typedef CouchstoreInternalTest FileOpsErrorInjectionTest;

/**
 * Parameterised test class for error injection tests
 */
class ParameterisedFileOpsErrorInjectionTest : public FileOpsErrorInjectionTest,
                                               public ::testing::WithParamInterface<int> {
};
