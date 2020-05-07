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

class CouchstoreSeekTest : public ::testing::Test {
protected:
    static void SetUpTestCase() {
        sourceFilename = cb::io::mktemp("CouchstoreSeekTest");
        ;
        auto db = openDb();
        rootHeader = getHeader(*db);
        // Create an "aligned" timestamp so that we don't need to worry about
        // steps which may wrap depending on the start offset
        alignedStartTimestamp =
                rootHeader.timestamp - (rootHeader.timestamp % 1000) + 1000;
        for (int ii = 1; ii < 100; ii++) {
            storeDocument(*db, "key", std::to_string(ii));
            ASSERT_EQ(
                    COUCHSTORE_SUCCESS,
                    couchstore_commit_ex(db.get(), alignedStartTimestamp + ii));
            // Verify that we get the expected sequence number (makes it easier
            // to test later on)
            auto [status, docinfo] = openDocInfo(*db, "key");
            ASSERT_EQ(COUCHSTORE_SUCCESS, status);
            ASSERT_EQ(ii, docinfo->db_seq);
        }
    }

    static void TearDownTestCase() {
        cb::io::rmrf(sourceFilename);
    }

    static UniqueDbPtr openDb() {
        auto [status, db] = openDatabase(
                sourceFilename,
                COUCHSTORE_OPEN_FLAG_CREATE | COUCHSTORE_OPEN_FLAG_UNBUFFERED);
        if (status != COUCHSTORE_SUCCESS) {
            throw std::runtime_error(std::string{"Failed to open database \""} +
                                     sourceFilename +
                                     "\": " + couchstore_strerror(status));
        }
        return std::move(db);
    }

    static void storeDocument(Db& db,
                              std::string_view key,
                              std::string_view value) {
        Doc doc = {};
        doc.id = {const_cast<char*>(key.data()), key.size()};
        doc.data = {const_cast<char*>(value.data()), value.size()};
        DocInfo docInfo = {};
        docInfo.id = doc.id;
        ASSERT_EQ(COUCHSTORE_SUCCESS,
                  couchstore_save_document(&db, &doc, &docInfo, 0));
    }

    static uint64_t alignedStartTimestamp;
    static Header rootHeader;
    static std::string sourceFilename;
};

uint64_t CouchstoreSeekTest::alignedStartTimestamp;
Header CouchstoreSeekTest::rootHeader;
std::string CouchstoreSeekTest::sourceFilename;

/**
 * Try to open a sequence number higher than the one we have (that should
 * return the current head).
 *
 * Given that we start by rewinding one header back we also test that we won't
 * seek beyond the provided header.
 */
TEST_F(CouchstoreSeekTest, OpenTheCurrentHead) {
    auto db = openDb();
    ASSERT_EQ(COUCHSTORE_SUCCESS, seek(*db, Direction::Backward));

    const auto header = getHeader(*db);
    ASSERT_EQ(COUCHSTORE_SUCCESS,
              seekFirstHeaderContaining(*db, header.updateSeqNum + 1, 1));
    ASSERT_EQ(header.headerPosition, getHeader(*db).headerPosition);
}

/**
 * Try to open the database where sequence number 5 exists. Given that we
 * provide a granularity of 1 we should get the exact match
 */
TEST_F(CouchstoreSeekTest, OpenHistorical_ExactRevision) {
    auto db = openDb();
    const uint64_t seqno = 5;

    ASSERT_EQ(COUCHSTORE_SUCCESS, seekFirstHeaderContaining(*db, seqno, 1));
    ASSERT_EQ(seqno, getHeader(*db).updateSeqNum);

    // Verify that we got the correct header by looking up the key
    auto [status, docinfo] = openDocInfo(*db, "key");
    ASSERT_EQ(COUCHSTORE_SUCCESS, status);
    ASSERT_EQ(seqno, docinfo->db_seq);
}

/**
 * Try to open the database where sequence number 5 exists, but we provide
 * a granularity of 10 so we should fast forward to the closest barrier.
 */
TEST_F(CouchstoreSeekTest, OpenHistorical_WithDeduplication) {
    auto db = openDb();
    const uint64_t seqno = 5;
    const uint64_t granularity = 10;

    auto start = alignedStartTimestamp + seqno;
    auto minBarrier = start - start % granularity;
    auto maxBarrier = minBarrier + granularity;

    ASSERT_EQ(COUCHSTORE_SUCCESS,
              seekFirstHeaderContaining(*db, seqno, granularity));
    // The max value is NOT included in the range
    ASSERT_EQ(maxBarrier - 1, getHeader(*db).timestamp);

    const auto ExpectedSequenceNumber = maxBarrier - alignedStartTimestamp - 1;
    ASSERT_EQ(ExpectedSequenceNumber, getHeader(*db).updateSeqNum);

    // Verify that we got the correct header by looking up the key
    auto [status, docinfo] = openDocInfo(*db, "key");
    ASSERT_EQ(COUCHSTORE_SUCCESS, status);
    ASSERT_EQ(ExpectedSequenceNumber, docinfo->db_seq);
}

/**
 * Try to open the database where sequence number X exists, but we provide
 * a granularity of 1000 so we should fast forward to the provided header
 * (and not go beyond that).
 */
TEST_F(CouchstoreSeekTest, OpenHistorical_WithDeduplicationWontSeekintoFuture) {
    auto db = openDb();
    ASSERT_EQ(COUCHSTORE_SUCCESS, seek(*db, Direction::Backward));
    const auto header = getHeader(*db);
    const auto granularity = 1000;
    auto seqno = 1;

    // Make sure that we don't end up with an exact match
    if ((rootHeader.timestamp + seqno % granularity) == 0) {
        ++seqno;
    }

    auto start = alignedStartTimestamp + seqno;
    auto minBarrier = start - start % granularity;
    auto maxBarrier = minBarrier + granularity;

    ASSERT_EQ(COUCHSTORE_SUCCESS,
              seekFirstHeaderContaining(*db, seqno, granularity));
    auto finalHeader = getHeader(*db);
    ASSERT_EQ(header.headerPosition, finalHeader.headerPosition)
            << "Expected header timestamp: " << header.timestamp << std::endl
            << "Root header timestamp    : " << rootHeader.timestamp
            << std::endl
            << "result header timestamp  : " << finalHeader.timestamp
            << std::endl
            << "Range                  :[" << minBarrier << ", " << maxBarrier
            << ">" << std::endl;
}
