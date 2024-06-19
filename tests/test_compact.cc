/*
 *     Copyright 2020 Couchbase, Inc.
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
#include <folly/portability/GTest.h>
#include <libcouchstore/couch_db.h>
#include <platform/cb_malloc.h>
#include <platform/dirutils.h>

using namespace cb::couchstore;

class CouchstoreCompactTest
    : public ::testing::Test,
      public ::testing::WithParamInterface<std::tuple<bool, bool>> {
protected:
    void SetUp() override {
        Test::SetUp();
        sourceFilename = cb::io::mktemp("CouchstoreCompactTest");
        targetFilename = sourceFilename + ".compact";
        ::remove(targetFilename.c_str());
    }

    void TearDown() override {
        Test::TearDown();
        cb::io::rmrf(sourceFilename);
        ::remove(targetFilename.c_str());
    }

    UniqueDbPtr openDb(const std::string& fname) {
        const bool encrypt =
                (fname == sourceFilename && std::get<0>(GetParam())) ||
                (fname == targetFilename && std::get<1>(GetParam()));
        auto [status, db] = openDatabase(
                fname,
                COUCHSTORE_OPEN_FLAG_CREATE | COUCHSTORE_OPEN_WITH_MPROTECT,
                [encrypt](std::string_view) {
                    return getEncryptionKey(encrypt);
                });
        if (status != COUCHSTORE_SUCCESS) {
            throw std::runtime_error(std::string{"Failed to open database \""} +
                                     fname +
                                     "\": " + couchstore_strerror(status));
        }
        return std::move(db);
    }

    UniqueDbPtr openSourceDb() {
        return openDb(sourceFilename);
    }

    UniqueDbPtr openTargetDb() {
        return openDb(targetFilename);
    }

    static void storeDocument(
            Db& db, std::string_view key, std::string_view value) {
        Doc doc = {};
        doc.id = {const_cast<char*>(key.data()), key.size()};
        doc.data = {const_cast<char*>(value.data()), value.size()};
        DocInfo docInfo = {};
        docInfo.id = doc.id;
        ASSERT_EQ(COUCHSTORE_SUCCESS,
                  couchstore_save_document(&db, &doc, &docInfo, 0));
    }

    static void storeLocalDocument(
            Db& db, std::string_view key, std::string_view value) {
        LocalDoc localDoc;
        localDoc.deleted = 0;
        localDoc.id = {const_cast<char*>(key.data()), key.size()};
        localDoc.json = {const_cast<char*>(value.data()), value.size()};
        ASSERT_EQ(COUCHSTORE_SUCCESS,
                  couchstore_save_local_document(&db, &localDoc));
    }

    static SharedEncryptionKey getEncryptionKey(bool encrypt) {
        if (!encrypt) {
            return nullptr;
        }
        return std::make_shared<cb::crypto::DataEncryptionKey>(
                cb::crypto::DataEncryptionKey{"MyKeyId",
                                              cb::crypto::Cipher::AES_256_GCM,
                                              std::string(32, 'k')});
    }

    static SharedEncryptionKey getTargetEncryptionKey(std::string_view) {
        return getEncryptionKey(std::get<1>(GetParam()));
    }

    std::string sourceFilename;
    std::string targetFilename;
};

/**
 * Generate a database with multiple header blocks and make sure that
 * after running compaction we're down to 1 header block and and all
 * values are packed into a single disk block (they're ~20 bytes) (for
 * simplicity let's assume that B-trees etc is part of the "header")
 *
 * Initially the database will look like:
 *  | H |
 *
 * When we add the first document it'll be appended to the header block (
 * as there is available space there) so the file looks like:
 *  | Hd0 | H |
 *
 * We loop doing that so that we'll get:
 *  | Hd0 | Hd1 | Hd2 | Hd3 | Hd4 | Hd5 | Hd6 | Hd7 | Hd8 | Hd9 | H |
 *
 * After compaction I expect it to be:
 *  | d0d1d2d3d4d5d6d7d8d9 | H |
 */
TEST_P(CouchstoreCompactTest, NormalCompaction) {
    auto db = openSourceDb();

    const std::string value = "This is a small value";
    for (auto ii = 0; ii < 10; ii++) {
        ASSERT_EQ(
                cb::couchstore::getDiskBlockSize(*db) * (ii + isEncrypted(*db)),
                couchstore_get_header_position(db.get()))
                << "Unexpected header location";
        storeDocument(*db, std::to_string(ii), value);
        ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_commit(db.get()));
    }

    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_compact_db(db.get(), targetFilename.c_str()));

    db = openTargetDb();
    EXPECT_EQ(cb::couchstore::getDiskBlockSize(*db),
              couchstore_get_header_position(db.get()));

    // Validate that we can fetch all of documents (none was lost or corrupted)
    for (auto ii = 0; ii < 10; ii++) {
        auto [status, doc] =
                cb::couchstore::openDocument(*db, std::to_string(ii));
        EXPECT_EQ(status, COUCHSTORE_SUCCESS)
                << "Failed to get \"" << std::to_string(ii) << "\"";
        EXPECT_TRUE(doc);
        if (doc) {
            EXPECT_EQ(value, std::string_view(doc->data.buf, doc->data.size));
        }
    }
}

/**
 * Compaction removed the initial header block created automatically
 * as part of couchstore_open_db_ex, but not set the block magic to Data
 */
TEST_P(CouchstoreCompactTest, MB38788_IncorrectBlockSize) {
    auto db = openSourceDb();

    const std::string value = "This is a small value";
    for (auto ii = 0; ii < 10; ii++) {
        ASSERT_EQ(
                cb::couchstore::getDiskBlockSize(*db) * (ii + isEncrypted(*db)),
                couchstore_get_header_position(db.get()))
                << "Unexpected header location";
        storeDocument(*db, std::to_string(ii), value);
        ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_commit(db.get()));
    }

    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_compact_db(db.get(), targetFilename.c_str()));

    db = openTargetDb();
    EXPECT_EQ(cb::couchstore::getDiskBlockSize(*db),
              couchstore_get_header_position(db.get()));

    // Validate that we can fetch all of documents (none was lost or corrupted)
    for (auto ii = 0; ii < 10; ii++) {
        auto [status, doc] =
                cb::couchstore::openDocument(*db, std::to_string(ii));
        EXPECT_EQ(status, COUCHSTORE_SUCCESS)
                << "Failed to get \"" << std::to_string(ii) << "\"";
        EXPECT_EQ(value, std::string(doc->data.buf, doc->data.size));
    }

    // Compaction removes the header block located at the beginning
    // of the file so we should have only 1 header in the file.
    // Before MB38788 seek would fail with checksum error as it found something
    // it thought was a header (due to the magic), but with invalid content
    db = openTargetDb();
    EXPECT_EQ(COUCHSTORE_ERROR_NO_HEADER,
              cb::couchstore::seek(*db, cb::couchstore::Direction::Backward));
    EXPECT_EQ(COUCHSTORE_ERROR_NO_HEADER,
              cb::couchstore::seek(*db, cb::couchstore::Direction::Forward));
}

/**
 * Run the same test as NormalCompactionEx, but use the _ex version of compact
 * and provide the callback methods
 */
static int couchstore_compact_hook_wrapper(Db*, DocInfo*, sized_buf, void*) {
    return COUCHSTORE_COMPACT_KEEP_ITEM;
}
static int couchstore_compact_docinfo_hook(DocInfo**, const sized_buf*) {
    return 0;
}
TEST_P(CouchstoreCompactTest, NormalCompactionEx) {
    auto db = openSourceDb();

    const std::string value = "This is a small value";
    for (auto ii = 0; ii < 10; ii++) {
        ASSERT_EQ(
                cb::couchstore::getDiskBlockSize(*db) * (ii + isEncrypted(*db)),
                couchstore_get_header_position(db.get()))
                << "Unexpected header location";
        storeDocument(*db, std::to_string(ii), value);
        ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_commit(db.get()));
    }

    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_compact_db_ex(db.get(),
                                       targetFilename.c_str(),
                                       COUCHSTORE_COMPACT_FLAG_UNBUFFERED,
                                       couchstore_compact_hook_wrapper,
                                       couchstore_compact_docinfo_hook,
                                       nullptr,
                                       couchstore_get_default_file_ops()));

    db = openTargetDb();
    EXPECT_EQ(cb::couchstore::getDiskBlockSize(*db),
              couchstore_get_header_position(db.get()));

    // Validate that we can fetch all of documents (none was lost or corrupted)
    for (auto ii = 0; ii < 10; ii++) {
        auto [status, doc] =
                cb::couchstore::openDocument(*db, std::to_string(ii));
        EXPECT_EQ(status, COUCHSTORE_SUCCESS)
                << "Failed to get \"" << std::to_string(ii) << "\"";
        EXPECT_EQ(value, std::string(doc->data.buf, doc->data.size));
    }
}

/**
 * Rerun the same test above, but use the new C++ method which allows for
 * binding std::functions to do stuff for us
 */
TEST_P(CouchstoreCompactTest, NormalCompactionDeduplicateHeaderBlocks) {
    auto db = openSourceDb();

    const std::string value = "This is a small value";
    for (auto ii = 0; ii < 10; ii++) {
        ASSERT_EQ(
                cb::couchstore::getDiskBlockSize(*db) * (ii + isEncrypted(*db)),
                couchstore_get_header_position(db.get()))
                << "Unexpected header location";
        storeDocument(*db, std::to_string(ii), value);
        ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_commit(db.get()));
    }

    ASSERT_EQ(COUCHSTORE_SUCCESS,
              cb::couchstore::compact(*db,
                                      targetFilename.c_str(),
                                      COUCHSTORE_COMPACT_FLAG_UNBUFFERED,
                                      {},
                                      {},
                                      {},
                                      couchstore_get_default_file_ops()));

    db = openTargetDb();
    EXPECT_EQ(cb::couchstore::getDiskBlockSize(*db),
              couchstore_get_header_position(db.get()));

    // Validate that we can fetch all of documents (none was lost or corrupted)
    for (auto ii = 0; ii < 10; ii++) {
        auto [status, doc] =
                cb::couchstore::openDocument(*db, std::to_string(ii));
        EXPECT_EQ(status, COUCHSTORE_SUCCESS)
                << "Failed to get \"" << std::to_string(ii) << "\"";
        EXPECT_EQ(value, std::string(doc->data.buf, doc->data.size));
    }
}

/**
 * Generate a database with some documents and verify that we can drop
 * documents as part of the compaction.
 */
TEST_P(CouchstoreCompactTest, CompactionAllowsForDroppingItems) {
    auto db = openSourceDb();

    std::string value = "This is a small value";
    for (auto ii = 0; ii < 10; ii++) {
        storeDocument(*db, std::to_string(ii), value);
    }
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_commit(db.get()));

    std::vector<std::string> keys;

    ASSERT_EQ(COUCHSTORE_SUCCESS,
              cb::couchstore::compact(
                      *db,
                      targetFilename.c_str(),
                      COUCHSTORE_COMPACT_FLAG_UNBUFFERED,
                      getTargetEncryptionKey,
                      [&keys](Db&, DocInfo* docInfo, sized_buf value) -> int {
                          if (docInfo == nullptr) {
                              // Indication that we're done with compaction
                              return COUCHSTORE_SUCCESS;
                          }
                          keys.emplace_back(std::string{docInfo->id.buf,
                                                        docInfo->id.size});
                          if (keys.back() == "5") {
                              return COUCHSTORE_COMPACT_DROP_ITEM;
                          }
                          return COUCHSTORE_COMPACT_KEEP_ITEM;
                      },
                      {},
                      couchstore_get_default_file_ops()));

    // Verify that we interated over all keys:
    EXPECT_EQ(10, keys.size());

    db = openTargetDb();

    // Verify that they're all there (except for key 5 which I deleted!)
    for (auto& key : keys) {
        auto [status, doc] = cb::couchstore::openDocument(*db, key);
        if (key == "5") {
            EXPECT_EQ(COUCHSTORE_ERROR_DOC_NOT_FOUND, status)
                    << "Key \"5\" should be dropped in compaction";
        } else {
            EXPECT_EQ(COUCHSTORE_SUCCESS, status)
                    << "Expect \"" << key << "\" to be in the database";
            const auto val = std::string{doc->data.buf, doc->data.size};
        }
    }
}

/**
 * Generate a database with a document and verify that we can request the
 * value for the document as part of the compaction
 */
TEST_P(CouchstoreCompactTest, CompactionAllowsForRequestingValue) {
    auto db = openSourceDb();

    std::string value;
    value.resize(cb::couchstore::getDiskBlockSize(*db));
    storeDocument(*db, "BigDocument", value);
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_commit(db.get()));

    bool callbackWithoutValue = false;
    std::string dbValue;

    ASSERT_EQ(COUCHSTORE_SUCCESS,
              cb::couchstore::compact(
                      *db,
                      targetFilename.c_str(),
                      COUCHSTORE_COMPACT_FLAG_UNBUFFERED,
                      getTargetEncryptionKey,
                      [&callbackWithoutValue, &dbValue](
                              Db&, DocInfo* docInfo, sized_buf value) -> int {
                          if (docInfo == nullptr) {
                              // Indication that we're done with compaction
                              return COUCHSTORE_SUCCESS;
                          }

                          const auto key = std::string{docInfo->id.buf,
                                                       docInfo->id.size};
                          if (key != "BigDocument") {
                              // Incorrect key pushed!
                              return COUCHSTORE_ERROR_CANCEL;
                          }

                          if (value.buf == nullptr) {
                              callbackWithoutValue = true;
                              return COUCHSTORE_COMPACT_NEED_BODY;
                          }

                          dbValue = std::string{value.buf, value.size};
                          return COUCHSTORE_COMPACT_KEEP_ITEM;
                      },
                      {},
                      couchstore_get_default_file_ops()));

    EXPECT_TRUE(callbackWithoutValue)
            << "Expected to a callback without the value";
    EXPECT_EQ(dbValue, value) << "Expected a callback with the value";
}

/**
 * Generate a database with a document and verify that we can rewrite the
 * DocumentInfo section for the document as part of compaction.
 *
 * For key 1 we won't change the doc info, for key 2 we'll make it bigger
 */
TEST_P(CouchstoreCompactTest, CompactionAllowsForRewritingDocInfo) {
    auto db = openSourceDb();

    storeDocument(*db, "1", "value");
    storeDocument(*db, "2", "value");
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_commit(db.get()));

    ASSERT_EQ(COUCHSTORE_SUCCESS,
              cb::couchstore::compact(
                      *db,
                      targetFilename.c_str(),
                      COUCHSTORE_COMPACT_FLAG_UNBUFFERED,
                      getTargetEncryptionKey,
                      [](Db& db, DocInfo* info, sized_buf body) -> int {
                          return COUCHSTORE_COMPACT_KEEP_ITEM;
                      },
                      [](DocInfo*& docInfo, sized_buf value) -> int {
                          const auto key = std::string{docInfo->id.buf,
                                                       docInfo->id.size};
                          if (key == "1") {
                              return 0;
                          }

                          auto* newDocInfo = static_cast<DocInfo*>(cb_calloc(
                                  sizeof(DocInfo) + docInfo->id.size + 256, 1));

                          *newDocInfo = *docInfo;
                          // Correct the id buffer
                          newDocInfo->id.buf =
                                  reinterpret_cast<char*>(newDocInfo + 1);
                          std::copy(docInfo->id.buf,
                                    docInfo->id.buf + docInfo->id.size,
                                    newDocInfo->id.buf);
                          newDocInfo->rev_meta.size = 256;
                          newDocInfo->rev_meta.buf =
                                  newDocInfo->id.buf + newDocInfo->id.size;
                          couchstore_free_docinfo(docInfo);

                          // Lets point to the new header
                          docInfo = newDocInfo;
                          return 1;
                      },
                      couchstore_get_default_file_ops()));

    // Now let's verify that we have meta information for key 2, and none for
    // key 1
    db = openTargetDb();
    {
        auto [status, info] = cb::couchstore::openDocInfo(*db, "1");
        ASSERT_EQ(COUCHSTORE_SUCCESS, status);
        EXPECT_EQ(0, info->rev_meta.size);
    }

    {
        auto [status, info] = cb::couchstore::openDocInfo(*db, "2");
        ASSERT_EQ(COUCHSTORE_SUCCESS, status);
        EXPECT_EQ(256, info->rev_meta.size);
    }
}

INSTANTIATE_TEST_SUITE_P(
        CouchstoreCompactTest,
        CouchstoreCompactTest,
        ::testing::Combine(::testing::Bool(), ::testing::Bool()),
        [](const ::testing::TestParamInfo<std::tuple<bool, bool>>& testInfo)
                -> std::string {
            return std::string(std::get<0>(testInfo.param)
                                       ? "FromEncrypted"
                                       : "FromUnencrypted") +
                   (std::get<1>(testInfo.param) ? "ToEncrypted"
                                                : "ToUnencrypted");
        });
