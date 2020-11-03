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

class CouchstoreCompactTest : public ::testing::Test {
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

    static UniqueDbPtr openDb(std::string fname) {
        auto [status, db] = openDatabase(
                fname,
                COUCHSTORE_OPEN_FLAG_CREATE | COUCHSTORE_OPEN_FLAG_UNBUFFERED);
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

    void storeDocument(Db& db, std::string_view key, std::string_view value) {
        Doc doc = {};
        doc.id = {const_cast<char*>(key.data()), key.size()};
        doc.data = {const_cast<char*>(value.data()), value.size()};
        DocInfo docInfo = {};
        docInfo.id = doc.id;
        ASSERT_EQ(COUCHSTORE_SUCCESS,
                  couchstore_save_document(&db, &doc, &docInfo, 0));
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
TEST_F(CouchstoreCompactTest, NormalCompaction) {
    auto db = openSourceDb();

    const std::string value = "This is a small value";
    for (auto ii = 0; ii < 10; ii++) {
        ASSERT_EQ(cb::couchstore::getDiskBlockSize(*db) * ii,
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
}

/**
 * Compaction removed the initial header block created automatically
 * as part of couchstore_open_db_ex, but not set the block magic to Data
 */
TEST_F(CouchstoreCompactTest, MB38788_IncorrectBlockSize) {
    auto db = openSourceDb();

    const std::string value = "This is a small value";
    for (auto ii = 0; ii < 10; ii++) {
        ASSERT_EQ(cb::couchstore::getDiskBlockSize(*db) * ii,
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
TEST_F(CouchstoreCompactTest, NormalCompactionEx) {
    auto db = openSourceDb();

    const std::string value = "This is a small value";
    for (auto ii = 0; ii < 10; ii++) {
        ASSERT_EQ(cb::couchstore::getDiskBlockSize(*db) * ii,
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
TEST_F(CouchstoreCompactTest, NormalCompactionDeduplicateHeaderBlocks) {
    auto db = openSourceDb();

    const std::string value = "This is a small value";
    for (auto ii = 0; ii < 10; ii++) {
        ASSERT_EQ(cb::couchstore::getDiskBlockSize(*db) * ii,
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
TEST_F(CouchstoreCompactTest, CompactionAllowsForDroppingItems) {
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
TEST_F(CouchstoreCompactTest, CompactionAllowsForRequestingValue) {
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
TEST_F(CouchstoreCompactTest, CompactionAllowsForRewritingDocInfo) {
    auto db = openSourceDb();

    storeDocument(*db, "1", "value");
    storeDocument(*db, "2", "value");
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_commit(db.get()));

    ASSERT_EQ(COUCHSTORE_SUCCESS,
              cb::couchstore::compact(
                      *db,
                      targetFilename.c_str(),
                      COUCHSTORE_COMPACT_FLAG_UNBUFFERED,
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

/**
 * Generate a database with multiple headers and verify that we may
 * perform full compaction up to one point, then incremental / compactions
 * moving up to the final point in time
 */
TEST_F(CouchstoreCompactTest, PitrCompaction) {
    // Create a database with 100 headers where we update a key in
    // each header
    auto db = openSourceDb();
    for (int ii = 0; ii < 100; ++ii) {
        storeDocument(*db, "PitrCompaction", std::to_string(ii));
        // use the timestamp as the timestamp for the header
        ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_commit_ex(db.get(), ii));
    }

    // Function to verify that the documents value in the file is correct
    // in all values of the headers
    auto verifyHeaders =
            [](Db& db, uint64_t oldest, int expected_num_headers) -> void {
        int num_headers = 1;
        do {
            auto header = cb::couchstore::getHeader(db);
            ASSERT_EQ(cb::couchstore::Header::Version::V13, header.version);
            if (header.timestamp < oldest ||
                expected_num_headers == num_headers) {
                EXPECT_EQ(expected_num_headers, num_headers);
                return;
            }
            auto [status, doc] =
                    cb::couchstore::openDocument(db, "PitrCompaction");
            ASSERT_EQ(COUCHSTORE_SUCCESS, status);
            const auto value = std::string{doc->data.buf, doc->data.size};
            EXPECT_EQ(value, std::to_string(header.timestamp));
            num_headers++;
            ASSERT_EQ(COUCHSTORE_SUCCESS,
                      cb::couchstore::seek(db,
                                           cb::couchstore::Direction::Backward))
                    << "There should be more headers (" << num_headers << " < "
                    << expected_num_headers << ")";
        } while (true);
    };

    // Verify that we've got all of the headers and that the document
    // has the correct value in all versions
    verifyHeaders(*openSourceDb(), 1, 99);

    // now compact the database up to 50
    ASSERT_EQ(COUCHSTORE_SUCCESS,
              cb::couchstore::compact(*db,
                                      targetFilename.c_str(),
                                      COUCHSTORE_COMPACT_FLAG_UNBUFFERED,
                                      {},
                                      {},
                                      couchstore_get_default_file_ops(),
                                      {},
                                      50,
                                      1,
                                      {},
                                      {},
                                      {},
                                      {}));

    db = openTargetDb();
    int num_headers = 1;
    while (cb::couchstore::seek(*db, cb::couchstore::Direction::Backward) ==
           COUCHSTORE_SUCCESS) {
        ++num_headers;
    }
    ASSERT_EQ(50, num_headers);

    // Verify that we've got the expected numbers of headers in the file!
    verifyHeaders(*openTargetDb(), 50, 50);
}

/**
 * Generate a database with multiple headers and verify that we may
 * perform full compaction up to one point, then incremental / compactions
 * moving up to the final point in time and squashing headers as we go
 */
TEST_F(CouchstoreCompactTest, PitrCompactionSquashHeaders) {
    // Create a database with 100 headers where we update a key in
    // each header
    auto db = openSourceDb();
    for (int ii = 0; ii < 100; ++ii) {
        storeDocument(*db, "PitrCompaction", std::to_string(ii));
        // use the timestamp as the timestamp for the header
        ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_commit_ex(db.get(), ii));
    }

    // Function to verify that the documents value in the file is correct
    // in all values of the headers
    auto verifyHeaders =
            [](Db& db, uint64_t oldest, int expected_num_headers) -> void {
        int num_headers = 1;
        do {
            auto header = cb::couchstore::getHeader(db);
            ASSERT_EQ(cb::couchstore::Header::Version::V13, header.version);
            if (header.timestamp < oldest ||
                expected_num_headers == num_headers) {
                EXPECT_EQ(expected_num_headers, num_headers);
                return;
            }
            auto [status, doc] =
                    cb::couchstore::openDocument(db, "PitrCompaction");
            ASSERT_EQ(COUCHSTORE_SUCCESS, status);
            const auto value = std::string{doc->data.buf, doc->data.size};
            EXPECT_EQ(value, std::to_string(header.timestamp));
            num_headers++;
            ASSERT_EQ(COUCHSTORE_SUCCESS,
                      cb::couchstore::seek(db,
                                           cb::couchstore::Direction::Backward))
                    << "There should be more headers (" << num_headers << " < "
                    << expected_num_headers << ")";
        } while (true);
    };

    // Verify that we've got all of the headers and that the document
    // has the correct value in all versions
    verifyHeaders(*openSourceDb(), 1, 99);

    // now compact the database up to 50
    ASSERT_EQ(COUCHSTORE_SUCCESS,
              cb::couchstore::compact(*db,
                                      targetFilename.c_str(),
                                      COUCHSTORE_COMPACT_FLAG_UNBUFFERED,
                                      {},
                                      {},
                                      couchstore_get_default_file_ops(),
                                      {},
                                      50,
                                      5,
                                      {},
                                      {},
                                      {},
                                      {}));

    db = openTargetDb();
    int num_headers = 1;
    while (cb::couchstore::seek(*db, cb::couchstore::Direction::Backward) ==
           COUCHSTORE_SUCCESS) {
        ++num_headers;
    }
    ASSERT_EQ(11, num_headers);

    // Verify that we've got the expected numbers of headers in the file!
    verifyHeaders(*openTargetDb(), 50, 11);
}

/**
 * Generate a database with multiple headers and verify that we may
 * perform full compaction up to one point (and that the expected header
 * is provided in the preCompactionCallback), then incremental / compactions
 * moving up to the final point in time and squashing headers as we go,
 * but we should NOT move beyond the provided source header.
 *
 * The database will have the following input headers
 *
 * | 10 | 25 | 30 | 100 | 109 | 170 |
 *
 * And we'll run compact with 109 as the "source" database, 30 the oldest
 * entry to keep, and delta of 75 so we should end up with:
 *
 * | 30 | 100 | 109 |
 */
TEST_F(CouchstoreCompactTest, PitrCompactionNotLastBlock) {
    using cb::couchstore::Direction;
    using cb::couchstore::seek;

    auto db = openSourceDb();

    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_commit_ex(db.get(), 10));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_commit_ex(db.get(), 25));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_commit_ex(db.get(), 30));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_commit_ex(db.get(), 100));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_commit_ex(db.get(), 109));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_commit_ex(db.get(), 170));
    ASSERT_EQ(COUCHSTORE_SUCCESS, seek(*db, Direction::Backward));

    // verify that cancel works for pre-compaction callback as we'll be using
    // that functionality in the real compaction
    auto db2 = openSourceDb();
    ASSERT_EQ(
            COUCHSTORE_ERROR_CANCEL,
            cb::couchstore::compact(*db2,
                                    targetFilename.c_str(),
                                    COUCHSTORE_COMPACT_FLAG_UNBUFFERED,
                                    {},
                                    {},
                                    couchstore_get_default_file_ops(),
                                    {},
                                    30,
                                    70,
                                    [](Db&) { return COUCHSTORE_ERROR_CANCEL; },
                                    {},
                                    {},
                                    {}));
    db2.reset();
    ASSERT_FALSE(cb::io::isFile(targetFilename));

    // verify that the the pre-compaction callback receives the correct
    // header
    ASSERT_EQ(COUCHSTORE_SUCCESS,
              cb::couchstore::compact(*db,
                                      targetFilename.c_str(),
                                      COUCHSTORE_COMPACT_FLAG_UNBUFFERED,
                                      {},
                                      {},
                                      couchstore_get_default_file_ops(),
                                      {},
                                      30,
                                      70,
                                      [](Db& database) {
                                          using cb::couchstore::getHeader;
                                          auto header = getHeader(database);
                                          if (header.timestamp != 30) {
                                              // Incorrect header version!
                                              // cancel
                                              return COUCHSTORE_ERROR_CANCEL;
                                          }

                                          return COUCHSTORE_SUCCESS;
                                      },
                                      {},
                                      {},
                                      {}));

    db = openTargetDb();
    ASSERT_EQ(109, cb::couchstore::getHeader(*db).timestamp);
    ASSERT_EQ(COUCHSTORE_SUCCESS, seek(*db, Direction::Backward));

    ASSERT_EQ(100, cb::couchstore::getHeader(*db).timestamp);
    ASSERT_EQ(COUCHSTORE_SUCCESS, seek(*db, Direction::Backward));

    ASSERT_EQ(30, cb::couchstore::getHeader(*db).timestamp);
    ASSERT_EQ(COUCHSTORE_ERROR_NO_HEADER, seek(*db, Direction::Backward));
}

/**
 * Create a database where the first header in the database block is newer
 * than the oldest data we want to keep, so we don't get out of sync trying
 * to locate the next PiTR bar (align the current block, and set search for
 * the next barrier).
 *
 * Create a database with multiple commit headers (all fitting within the
 * same granularity bar, but there are plenty of "empty" slots from the time
 * of the oldest we want to keep and the oldest one present in the database
 * file). We should do a full compaction up to the first database block,
 * and then all of the next ones should be deduplicated into the same slot).
 *
 * (in the previous implementation we got out of sync causing a lot of the
 * other headers to be copied over without dedupling).
 */
TEST_F(CouchstoreCompactTest, CheckMultipleMissingInBeginning) {
    using cb::couchstore::Direction;
    using cb::couchstore::seek;

    auto db = openSourceDb();

    auto now = cb::couchstore::getHeader(*db).timestamp;
    for (int ii = 0; ii < 10; ++ii) {
        ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_commit_ex(db.get(), now + ii));
    }

    ASSERT_EQ(
            COUCHSTORE_SUCCESS,
            cb::couchstore::compact(
                    *db,
                    targetFilename.c_str(),
                    COUCHSTORE_COMPACT_FLAG_UNBUFFERED,
                    {},
                    {},
                    couchstore_get_default_file_ops(),
                    {},
                    now - std::chrono::duration_cast<std::chrono::nanoseconds>(
                                  std::chrono::hours(1))
                                    .count(),
                    std::chrono::duration_cast<std::chrono::nanoseconds>(
                            std::chrono::seconds(1))
                            .count(),
                    {},
                    {},
                    {},
                    {}));

    db = openTargetDb();
    ASSERT_EQ(now + 9, cb::couchstore::getHeader(*db).timestamp);
    ASSERT_EQ(COUCHSTORE_SUCCESS, seek(*db, Direction::Backward));
    ASSERT_EQ(now, cb::couchstore::getHeader(*db).timestamp);
    ASSERT_EQ(COUCHSTORE_ERROR_NO_HEADER, seek(*db, Direction::Backward));
}
