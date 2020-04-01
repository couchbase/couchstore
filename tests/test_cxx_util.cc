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
#include <platform/dirutils.h>

using namespace cb::couchstore;

class CouchstoreCxxTest : public ::testing::Test {
protected:
    void SetUp() override {
        Test::SetUp();
        filename = cb::io::mktemp("CouchstoreCxxTest");
    }

    void TearDown() override {
        Test::TearDown();
        cb::io::rmrf(filename);
    }

    UniqueDbPtr openDb() {
        auto [status, db] = openDatabase(
                filename,
                COUCHSTORE_OPEN_FLAG_CREATE | COUCHSTORE_OPEN_FLAG_UNBUFFERED);
        if (status != COUCHSTORE_SUCCESS) {
            throw std::runtime_error(std::string{"Failed to open database: "} +
                                     couchstore_strerror(status));
        }
        return std::move(db);
    }

    std::string filename;
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
TEST_F(CouchstoreCxxTest, seek) {
    using cb::couchstore::Direction;
    auto db = openDb();
    std::vector<cs_off_t> headers;
    for (int ii = 0; ii < 10; ii++) {
        headers.emplace_back(couchstore_get_header_position(db.get()));
        ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_commit(db.get()));
        ASSERT_LT(headers.back(), couchstore_get_header_position(db.get()));
    }

    // Verify that we can rewind back to the first header in the file
    for (int idx = headers.size() - 1; idx >= 0; --idx) {
        EXPECT_EQ(COUCHSTORE_SUCCESS,
                  cb::couchstore::seek(*db, Direction::Backward));
        EXPECT_EQ(headers[idx], couchstore_get_header_position(db.get()));
    }

    // And fast forward should find the same headers.
    for (int ii = 0; ii < 10; ii++) {
        EXPECT_EQ(headers[ii], couchstore_get_header_position(db.get()));
        EXPECT_EQ(COUCHSTORE_SUCCESS,
                  cb::couchstore::seek(*db, Direction::Forward));
    }
}
