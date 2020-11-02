/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
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

#include <folly/portability/GTest.h>
#include <libcouchstore/couch_db.h>
#include <nlohmann/json.hpp>
#include <platform/dirutils.h>

using namespace cb::couchstore;

class CouchstoreCxxTest : public ::testing::Test {
protected:
    void SetUp() override {
        Test::SetUp();
        filename = cb::io::mktemp("CouchstoreCxxTest");
        auto db = openDb();

        std::string value;
        value.resize(cb::couchstore::getDiskBlockSize(*db));

        for (int ii = 0; ii < 10; ii++) {
            headers.emplace_back(couchstore_get_header_position(db.get()));
            // Store a document which makes sure that the header won't
            // arrive at the next block (so that if we try to seek in the
            // file we won't find the header block at the next offset)
            storeDocument(*db, std::to_string(ii), value);
            ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_commit(db.get()));
            ASSERT_LT(headers.back(), couchstore_get_header_position(db.get()));
        }
        headers.emplace_back(couchstore_get_header_position(db.get()));
    }

    void TearDown() override {
        Test::TearDown();
        cb::io::rmrf(filename);
        for (const auto& file : dbfiles) {
            if (cb::io::isFile(file)) {
                cb::io::rmrf(file);
            }
        }
    }

    UniqueDbPtr openDb(
            couchstore_open_flags flags = COUCHSTORE_OPEN_FLAG_CREATE |
                                          COUCHSTORE_OPEN_FLAG_UNBUFFERED) {
        auto [status, db] = openDatabase(filename, flags);
        if (status != COUCHSTORE_SUCCESS) {
            throw std::runtime_error(std::string{"Failed to open database: "} +
                                     couchstore_strerror(status));
        }
        return std::move(db);
    }

    void storeDocument(Db& db,
                       std::string_view key,
                       std::string_view value,
                       bool deleted = false) {
        Doc doc = {};
        doc.id = {const_cast<char*>(key.data()), key.size()};
        doc.data = {const_cast<char*>(value.data()), value.size()};
        DocInfo docInfo = {};
        docInfo.id = doc.id;
        docInfo.deleted = deleted;
        if (deleted && value.empty()) {
            ASSERT_EQ(COUCHSTORE_SUCCESS,
                      couchstore_save_document(&db, nullptr, &docInfo, 0));
        } else {
            ASSERT_EQ(COUCHSTORE_SUCCESS,
                      couchstore_save_document(&db, &doc, &docInfo, 0));
        }
    }

    std::string filename;
    std::vector<std::string> dbfiles;
    std::vector<cs_off_t> headers;
};

/**
 * Test that we can seek in both directions of the file (to an older version
 * of the database by locating the previous header, but also that we
 * can seek in the other direction of the file.
 *
 * The test assumes that the rest of the logic in couchstore works as
 * expected (We don't try to verify that the header we're using points
 * to the correct B-tree etc. The backwards search for header have been
 * in production for couchstore for years, and the forward search use
 * the same internal logic except that it instead of searching every 4k
 * block towards the beginning of the file it search towards the end
 * of the file).
 */
TEST_F(CouchstoreCxxTest, seekDirections) {
    using cb::couchstore::Direction;
    auto db = openDb();

    // Verify that we can rewind back to the first header in the file
    for (int idx = headers.size() - 2; idx >= 0; --idx) {
        ASSERT_EQ(COUCHSTORE_SUCCESS,
                  cb::couchstore::seek(*db, Direction::Backward));
        EXPECT_EQ(headers[idx], couchstore_get_header_position(db.get()));
    }

    // expect to be at offset 0
    EXPECT_EQ(0, couchstore_get_header_position(db.get()));
    ASSERT_EQ(COUCHSTORE_ERROR_NO_HEADER,
              cb::couchstore::seek(*db, Direction::Backward));
    // And we shouldn't have moved
    EXPECT_EQ(0, couchstore_get_header_position(db.get()));

    // And fast forward should find the same headers.
    for (int ii = 0; ii < 10; ii++) {
        EXPECT_EQ(headers[ii], couchstore_get_header_position(db.get()));
        ASSERT_EQ(COUCHSTORE_SUCCESS,
                  cb::couchstore::seek(*db, Direction::Forward));
    }

    // And we should be at the end of the file
    ASSERT_EQ(COUCHSTORE_ERROR_NO_HEADER,
              cb::couchstore::seek(*db, Direction::Forward));
    // And we shouldn't have moved
    EXPECT_EQ(headers.back(), couchstore_get_header_position(db.get()));

    // verify that we handle invalid arguments
    EXPECT_EQ(COUCHSTORE_ERROR_INVALID_ARGUMENTS,
              cb::couchstore::seek(*db, Direction(4)));

    // Verify that we don't crash if we use a closed file
    couchstore_close_file(db.get());
    EXPECT_EQ(COUCHSTORE_ERROR_FILE_CLOSED,
              cb::couchstore::seek(*db, Direction::Forward));
    EXPECT_EQ(COUCHSTORE_ERROR_FILE_CLOSED,
              cb::couchstore::seek(*db, Direction::Backward));
}

TEST_F(CouchstoreCxxTest, seek) {
    using cb::couchstore::Direction;
    auto db = openDb();
    const auto DiskBlockSize = cb::couchstore::getDiskBlockSize(*db);

    // verify that we can seek to a given point in time
    for (auto& offset : headers) {
        ASSERT_EQ(COUCHSTORE_SUCCESS, cb::couchstore::seek(*db, offset));
        EXPECT_EQ(offset, couchstore_get_header_position(db.get()));
    }

    // Verify that we can't jump beyond the file size
    ASSERT_EQ(COUCHSTORE_ERROR_NO_HEADER,
              cb::couchstore::seek(*db, headers.back() + DiskBlockSize));
    // And the failure didn't move us
    EXPECT_EQ(headers.back(), couchstore_get_header_position(db.get()));

    // Verify that we don't allow unaligned addresses
    ASSERT_EQ(COUCHSTORE_ERROR_INVALID_ARGUMENTS,
              cb::couchstore::seek(*db, DiskBlockSize - 10));
    // And the failure didn't move us
    EXPECT_EQ(headers.back(), couchstore_get_header_position(db.get()));

    // Verify that we can't seek to a data block. We should have a header at
    // the beginning of the file, then a document and btree which exceeds the
    // the rest of that block and into the next block so that the next header
    // is at the beginning of the 3rd block in the file
    EXPECT_EQ(0, headers[0]);
    EXPECT_EQ(2 * DiskBlockSize, headers[1]);
    EXPECT_EQ(COUCHSTORE_ERROR_NO_HEADER,
              cb::couchstore::seek(*db, DiskBlockSize));

    // Verify that we don't crash if we use a closed file
    couchstore_close_file(db.get());
    EXPECT_EQ(COUCHSTORE_ERROR_FILE_CLOSED, cb::couchstore::seek(*db, 0));
}

/**
 * Test that we can't seek forward outside what the file was opened with,
 * but seek end can do that
 */
TEST_F(CouchstoreCxxTest, seekForwardReadOnlyWithOtherWriters) {
    using namespace cb::couchstore;
    auto writeDb = openDb();
    auto writeDb2 = openDb();
    auto readDb = openDb(COUCHSTORE_OPEN_FLAG_RDONLY);

    auto start = getHeader(*readDb);
    EXPECT_EQ(COUCHSTORE_ERROR_NO_HEADER, seek(*readDb, Direction::Forward));
    storeDocument(*writeDb, "foo", "bar");
    couchstore_commit_ex(writeDb.get(), 0xdeadbeef);

    EXPECT_EQ(COUCHSTORE_ERROR_NO_HEADER, seek(*writeDb2, Direction::Forward));
    EXPECT_EQ(COUCHSTORE_ERROR_NO_HEADER, seek(*readDb, Direction::Forward));

    // but End is allowed
    EXPECT_EQ(COUCHSTORE_SUCCESS, seek(*readDb, Direction::End));
    auto end = getHeader(*readDb);
    EXPECT_LT(start.headerPosition, end.headerPosition);

    EXPECT_EQ(COUCHSTORE_SUCCESS, seek(*writeDb2, Direction::End));
    end = getHeader(*writeDb2);
    EXPECT_LT(start.headerPosition, end.headerPosition);
}

// Verify that we work as expected on files with the previous disk formats
TEST_F(CouchstoreCxxTest, CommitTimestampOldDiskFormat) {
    cb::io::rmrf(filename);
    auto db = openDb(COUCHSTORE_OPEN_FLAG_CREATE |
                     COUCHSTORE_OPEN_WITH_LEGACY_CRC);
    auto header = cb::couchstore::getHeader(*db);
    ASSERT_EQ(Header::Version::V11, header.version);
    EXPECT_EQ(0, header.timestamp);
    couchstore_commit_ex(db.get(), 0xdeadbeef);

    // Verify that the timestamp was cleared from the "in memory" copy
    header = cb::couchstore::getHeader(*db);
    ASSERT_EQ(Header::Version::V11, header.version);
    EXPECT_EQ(0, header.timestamp);

    // verify that it wasn't stored on the disk
    db = openDb(COUCHSTORE_OPEN_FLAG_RDONLY);
    header = cb::couchstore::getHeader(*db);
    ASSERT_EQ(Header::Version::V11, header.version);
    EXPECT_EQ(0, header.timestamp);
}

TEST_F(CouchstoreCxxTest, CommitTimestamp) {
    auto db = openDb();
    auto header = cb::couchstore::getHeader(*db);
    ASSERT_EQ(Header::Version::V13, header.version);
    // When we created the database in SetUp we did a commit which added
    // the current time as the header...
    EXPECT_NE(0, header.timestamp);
    EXPECT_GT(std::chrono::system_clock::now().time_since_epoch().count(),
              header.timestamp);
    couchstore_commit_ex(db.get(), 0xdeadbeef);
    header = cb::couchstore::getHeader(*db);
    EXPECT_EQ(0xdeadbeef, header.timestamp);

    // verify that the on disk value is what we set it to
    db = openDb(COUCHSTORE_OPEN_FLAG_RDONLY);
    header = cb::couchstore::getHeader(*db);
    EXPECT_EQ(0xdeadbeef, header.timestamp);
}

TEST_F(CouchstoreCxxTest, GetHeaderJson) {
    auto db = openDb();
    couchstore_commit_ex(db.get(), 0xdeadbeef);
    auto header = cb::couchstore::getHeader(*db);
    ASSERT_EQ(Header::Version::V13, header.version);
    auto json = header.to_json();
    EXPECT_EQ(13, json["version"]);
    EXPECT_EQ("0x0000000000015000", json["header_position"]);
    EXPECT_EQ(3735928559, json["timestamp"]);
    EXPECT_EQ(0, json["purge_seq"]);
    EXPECT_EQ(10, json["doc_count"]);
    EXPECT_NE("", json["filename"]);
    EXPECT_EQ(0, json["deleted_count"]);
    EXPECT_EQ(86103, json["file_size"]);
    EXPECT_EQ(41369, json["space_used"]);
    EXPECT_EQ(10, json["update_seq"]);
}

TEST_F(CouchstoreCxxTest, ReplayOfDeletedDocuments) {
    auto source = openDb();
    auto start = cb::couchstore::getHeader(*source);

    // Store normal document and a temp document
    storeDocument(*source, "alive", "bar");
    storeDocument(*source, "deleted", "value", true);
    storeDocument(*source, "deleted-no-value", "", true);
    couchstore_commit(source.get());
    auto end = cb::couchstore::getHeader(*source);
    ASSERT_EQ(COUCHSTORE_SUCCESS,
              cb::couchstore::seek(*source, start.headerPosition));

    const std::string targetdb = filename + ".ex";
    dbfiles.emplace_back(targetdb);

    auto [status, target] = openDatabase(
            targetdb,
            COUCHSTORE_OPEN_FLAG_CREATE | COUCHSTORE_OPEN_FLAG_UNBUFFERED);
    ASSERT_EQ(COUCHSTORE_SUCCESS, status) << "Failed to open target db";

    ASSERT_EQ(COUCHSTORE_SUCCESS,
              cb::couchstore::replay(
                      *source, *target, uint64_t(-1), end.headerPosition, {}));

    // verify that I can read out the 3 documents
    {
        auto [st, doc] = cb::couchstore::openDocument(*target, "alive");
        ASSERT_EQ(COUCHSTORE_SUCCESS, st);
        ASSERT_EQ("bar", std::string(doc->data.buf, doc->data.size));
    }
    {
        auto [st, docInfo] = cb::couchstore::openDocInfo(*target, "deleted");
        ASSERT_EQ(COUCHSTORE_SUCCESS, st);
        ASSERT_TRUE(docInfo->deleted);
        auto [docstat, doc] = cb::couchstore::openDocument(*target, *docInfo);
        ASSERT_EQ(COUCHSTORE_SUCCESS, docstat);
        ASSERT_EQ("value", std::string(doc->data.buf, doc->data.size));
    }

    {
        auto [st, docInfo] =
                cb::couchstore::openDocInfo(*target, "deleted-no-value");
        ASSERT_EQ(COUCHSTORE_SUCCESS, st);
        ASSERT_TRUE(docInfo->deleted);
        auto [docstat, doc] = cb::couchstore::openDocument(*target, *docInfo);
        ASSERT_EQ(COUCHSTORE_ERROR_DOC_NOT_FOUND, docstat);
        ASSERT_FALSE(doc);
    }
}
