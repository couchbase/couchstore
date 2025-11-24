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

#include "couchstoretest.h"
#include <libcouchstore/couch_db.h>
#include <src/internal.h>

#include <utility>

/**
 * Callback function for latency info.
 * This is a simple example how to get latency info.
 */
int couchstore_test_latency_callback(const char* stat_name,
                                     CouchLatencyHisto* latencies,
                                     const CouchLatencyMicroSecRep elapsed_time,
                                     void* ctx) {
    (void)ctx;
    size_t total = latencies->total();
    std::cout << stat_name;
    std::cout << ": " << total << " calls, ";
    std::cout << "avg " << (elapsed_time / total);
    std::cout << " us" << std::endl;
    std::stringstream ss;
    for (auto& itr_hist : *latencies) {
        if (itr_hist->count()) {
            ss << "  ";
            ss << itr_hist->start() << " us";
            ss << " -- ";
            ss << itr_hist->end() << " us";
            ss << ": ";
            ss << itr_hist->count();
            ss << std::endl;
        }
    }
    std::cout << ss.str();
    return 0;
}

CouchstoreBaseTest::CouchstoreBaseTest()
    : CouchstoreBaseTest("testfile.couch") {
}

CouchstoreBaseTest::CouchstoreBaseTest(
        std::string file_path, bool display_latency_info)
    : db(nullptr),
      filePath(std::move(file_path)),
      displayLatencyInfo(display_latency_info) {
    couchstore_latency_collector_start();
    remove(filePath.c_str());
}

/**
    Called after each test finishes.
      - Closes db (if non-null)
      - Removes testfile.couch
**/
CouchstoreBaseTest::~CouchstoreBaseTest() {
    clean_up();
    /* make sure os.c didn't accidentally call close(0): */
#ifndef WIN32
    EXPECT_TRUE(lseek(0, 0, SEEK_CUR) >= 0 || errno != EBADF);
#endif
}

void CouchstoreBaseTest::clean_up() {
    if (db) {
        couchstore_close_file(db);
        couchstore_free_db(db);
        db = nullptr;
    }

    if (displayLatencyInfo) {
        couchstore_latency_dump_options options;
        couchstore_get_latency_info(couchstore_test_latency_callback,
                                    options,
                                    nullptr);
    }
    couchstore_latency_collector_stop();

    remove(filePath.c_str());
}

CouchstoreEncryptedUnencryptedTest::CouchstoreEncryptedUnencryptedTest()
    : sharedEncryptionKey(std::make_shared<cb::crypto::KeyDerivationKey>(
              "MyKeyId",
              cb::crypto::Cipher::AES_256_GCM,
              std::string(32, 'k'))) {
}

couchstore_error_t CouchstoreEncryptedUnencryptedTest::open_db(
        couchstore_open_flags extra_flags) {
    return couchstore_open_db_ex(filePath.c_str(),
                                 extra_flags,
                                 getEncryptionKeyCB(),
                                 couchstore_get_default_file_ops(),
                                 &db);
}

cb::couchstore::EncryptionKeyGetter
CouchstoreEncryptedUnencryptedTest::getEncryptionKeyCB() {
    return [this](std::string_view) -> cb::couchstore::SharedEncryptionKey {
        if (!isEncrypted()) {
            return nullptr;
        }
        return sharedEncryptionKey;
    };
}

bool CouchstoreTest::isEncrypted() {
    return GetParam();
}

bool CouchstoreDocTest::isEncrypted() {
    auto& [a, b, encrypt] = GetParam();
    return encrypt;
}

CouchstoreInternalTest::CouchstoreInternalTest()
        : CouchstoreBaseTest("testfile_internal.couch"),
          compactPath("testfile_internal.couch.compact"),
          documents(Documents(0)),
          ops(create_default_file_ops()) {
    remove(compactPath.c_str());
}

CouchstoreInternalTest::~CouchstoreInternalTest() {
    // Destruct db here instead of parent so that ops isn't destructed
    // when we try to destruct the db.
    clean_up();
    remove(compactPath.c_str());
}

couchstore_error_t CouchstoreInternalTest::open_db(couchstore_open_flags extra_flags) {
    return couchstore_open_db_ex(filePath.c_str(),
                                 extra_flags | COUCHSTORE_OPEN_FLAG_UNBUFFERED,
                                 {}, &ops, &db);
}

void CouchstoreInternalTest::open_db_and_populate(couchstore_open_flags extra_flags,
                                                  size_t count) {
    ASSERT_EQ(COUCHSTORE_SUCCESS, open_db(extra_flags));
    documents = Documents(count);
    documents.generateDocs();
    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_save_documents(db, documents.getDocs(),
                                        documents.getDocInfos(), count, 0));

}

LocalDoc CouchstoreInternalTest::create_local_doc(std::string& id,
                                                  std::string& json) {
    LocalDoc doc;
    doc.id.buf = &id[0];
    doc.id.size = strlen(doc.id.buf);
    doc.json.buf = &json[0];
    doc.json.size = strlen(doc.json.buf);
    doc.deleted = 0;
    return doc;
}

CouchstoreMTTest::CouchstoreMTTest()
    : CouchstoreMTTest("testfile_mt.couch") {
}

CouchstoreMTTest::CouchstoreMTTest(std::string file_path)
    : numThreads(std::get<1>(GetParam())),
      dbs(numThreads),
      filePath(std::move(file_path)) {
}

void CouchstoreMTTest::TearDown() {
    for (size_t ii=0; ii<numThreads; ++ii) {
        std::string actual_file_path = filePath + std::to_string(ii);
        remove(actual_file_path.c_str());

        if (dbs[ii]) {
            couchstore_close_file(dbs[ii]);
            couchstore_free_db(dbs[ii]);
            dbs[ii] = nullptr;
        }
    }
}

