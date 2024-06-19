/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

//#include "couchstore_config.h"



#include "bitfield.h"
#include "couchstoretest.h"
#include "documents.h"
#include "internal.h"
#include "node_types.h"
#include "reduces.h"

#include <folly/portability/GTest.h>
#include <libcouchstore/couch_db.h>
#include <platform/cbassert.h>

#include <array>
#include <cstdint>
#include <limits>
#include <random>
#include <thread>
#include <unordered_map>

using ::testing::_;

static void test_raw_08(uint8_t value)
{
    raw_08 raw;
    raw = encode_raw08(value);
    cb_assert(decode_raw08(raw) == value);
}

static void test_raw_16(uint16_t value)
{
    raw_16 raw;
    raw = encode_raw16(value);
    cb_assert(decode_raw16(raw) == value);
}

static void test_raw_32(uint32_t value)
{
    raw_32 raw;
    raw = encode_raw32(value);
    cb_assert(decode_raw32(raw) == value);
}

static void test_raw_40(uint64_t value, const uint8_t expected[8])
{
    union {
        raw_40 raw;
        uint8_t bytes[8];
    } data;
    memset(&data, 0, sizeof(data));
    encode_raw40(value, &data.raw);
    cb_assert(memcmp(data.bytes, expected, 8) == 0);
    cb_assert(decode_raw40(data.raw) == value);
}

static void test_raw_48(uint64_t value, const uint8_t expected[8])
{
    union {
        raw_48 raw;
        uint8_t bytes[8];
    } data;
    memset(&data, 0, sizeof(data));
    encode_raw48(value, &data.raw);
    cb_assert(memcmp(data.bytes, expected, 8) == 0);
    cb_assert(decode_raw48(data.raw) == value);
}

TEST_F(CouchstoreBaseTest, bitfield_fns)
{
    uint8_t expected1[8] = {0x12, 0x34, 0x56, 0x78, 0x90};
    uint8_t expected2[8] = {0x09, 0x87, 0x65, 0x43, 0x21};
    uint8_t expected3[8] = {0x12, 0x34, 0x56, 0x78, 0x90, 0xAB};
    uint8_t expected4[8] = {0xBA, 0x98, 0x76, 0x54, 0x32, 0x10};
    struct {
        raw_08 a;
        raw_48 b;
        raw_16 c;
        raw_40 d;
        raw_32 e;
        raw_08 f;
    } packed;
    raw_kv_length kv;
    uint32_t klen, vlen;

    EXPECT_EQ(sizeof(cs_off_t), 8ul);

    EXPECT_EQ(sizeof(raw_08), 1ul);
    EXPECT_EQ(sizeof(raw_16), 2ul);
    EXPECT_EQ(sizeof(raw_32), 4ul);
    EXPECT_EQ(sizeof(raw_40), 5ul);
    EXPECT_EQ(sizeof(raw_48), 6ul);

    EXPECT_EQ(sizeof(packed), 19ul);

    EXPECT_EQ(sizeof(kv), 5ul);
    kv = encode_kv_length(1234, 123456);
    decode_kv_length(&kv, &klen, &vlen);
    EXPECT_EQ(klen, 1234ul);
    EXPECT_EQ(vlen, 123456ul);

    test_raw_08(0);
    test_raw_08(std::numeric_limits<std::uint8_t>::max());
    test_raw_16(0);
    test_raw_16(12345);
    test_raw_16(std::numeric_limits<std::uint16_t>::max());
    test_raw_32(0);
    test_raw_32(12345678);
    test_raw_32(std::numeric_limits<std::uint32_t>::max());

    test_raw_40(0x1234567890ll, expected1);
    test_raw_40(0x0987654321ll, expected2);
    test_raw_48(0x1234567890ABll, expected3);
    test_raw_48(0xBA9876543210ll, expected4);
}

TEST_P(CouchstoreDocTest, save_docs)
{
    bool smallData = std::get<0>(GetParam());
    int  count = std::get<1>(GetParam());
    std::string small_doc("{\"test_doc_index\":%d}");
    std::string large_doc("{"
                          "\"test_doc_index\":%d,"
                          "\"field1\": \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\","
                          "\"field2\": \"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\","
                          "\"field3\": \"cccccccccccccccccccccccccccccccccccccccccccccccccc"
                          "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                          "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                          "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                          "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                          "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                          "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\""
                          "}");

    Documents documents(count);
    std::mt19937 twister(count);
    std::uniform_int_distribution<> distribute(0, 99999); // controls the length of the key a little
    for (int ii = 0; ii < count; ii++) {
        std::string key = "doc" +
                          std::to_string(ii) +
                          "-" +
                          std::to_string(distribute(twister));
        documents.setDoc(ii, key, smallData ? small_doc : large_doc);
    }

    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_open_db(filePath.c_str(), COUCHSTORE_OPEN_FLAG_CREATE, &db));
    EXPECT_EQ(0, strcmp(couchstore_get_db_filename(db), filePath.c_str()));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_save_documents(db,
                                                            documents.getDocs(),
                                                            documents.getDocInfos(),
                                                            count,
                                                            0));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_commit(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_close_file(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_free_db(db));
    db = nullptr;

    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_open_db(filePath.c_str(), 0, &db));

    /* Read back by doc ID: */
    for (int ii = 0; ii < count; ++ii) {
        DocInfo* out_info;
        ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_docinfo_by_id(db,
                                                               documents.getDoc(ii)->id.buf,
                                                               documents.getDoc(ii)->id.size,
                                                               &out_info));
        // Re-use callback to validate the data.
        SCOPED_TRACE("save_docs - doc by id");
        Documents::checkCallback(db, out_info, &documents);
        couchstore_free_docinfo(out_info);
    }

    /* Read back in bulk by doc ID: */
    {
        documents.resetCounters();
        sized_buf* buf = new sized_buf[count];
        for (int ii = 0; ii < count; ++ii) {
            buf[ii] = documents.getDoc(ii)->id;
        }
        SCOPED_TRACE("save_docs - doc by id (bulk)");
        ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_docinfos_by_id(db,
                                                                buf,
                                                                count,
                                                                0,
                                                                &Documents::docIterCheckCallback,
                                                                &documents));
        EXPECT_EQ(count, documents.getCallbacks());
        EXPECT_EQ(0, documents.getDeleted());
        delete [] buf;
    }

    /* Read back by sequence: */
    uint64_t* sequences = new uint64_t[count];
    for (int ii = 0; ii < count; ++ii) {
        DocInfo* out_info;
        sequences[ii] = documents.getDocInfo(ii)->db_seq;
        EXPECT_EQ((uint64_t)ii + 1, sequences[ii]);
        ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_docinfo_by_sequence(db, sequences[ii], &out_info));
        // Re-use callback to validate the data.
        SCOPED_TRACE("save_docs - doc by sequence");
        Documents::checkCallback(db, out_info, &documents);
        couchstore_free_docinfo(out_info);
    }

    /* Read back in bulk by sequence: */
    {
        documents.resetCounters();
        SCOPED_TRACE("save_docs - doc by sequence (bulk)");
        ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_docinfos_by_sequence(db,
                                                                      sequences,
                                                                      count,
                                                                      0,
                                                                      &Documents::checkCallback,
                                                                      &documents));
        EXPECT_EQ(count, documents.getCallbacks());
        EXPECT_EQ(0, documents.getDeleted());
    }

    delete [] sequences;

    /* Read back using changes_since: */
    {
        documents.resetCounters();
        SCOPED_TRACE("save_docs - doc changes_since");
        ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_changes_since(db,
                                                               0,
                                                               0,
                                                               &Documents::checkCallback,
                                                               &documents));
        EXPECT_EQ(count, documents.getCallbacks());
        EXPECT_EQ(0, documents.getDeleted());
    }

    uint64_t idtreesize = db->header.by_id_root->subtreesize;
    uint64_t seqtreesize = db->header.by_seq_root->subtreesize;
    const raw_by_id_reduce * reduce = (const raw_by_id_reduce*)db->header.by_id_root->reduce_value.buf;
    uint64_t docssize = decode_raw48(reduce->size);
    uint64_t dbfilesize = db->file.pos;

    EXPECT_GT(dbfilesize, 0ull);
    EXPECT_GT(idtreesize, 0ull);
    EXPECT_GT(seqtreesize, 0ull);
    EXPECT_GT(docssize, 0ull);
    EXPECT_LT(idtreesize, dbfilesize);
    EXPECT_LT(seqtreesize,  dbfilesize);
    EXPECT_LT(docssize, dbfilesize);
    EXPECT_EQ(nullptr, db->header.local_docs_root);
    EXPECT_LT((idtreesize + seqtreesize + docssize), dbfilesize);
}

TEST_P(CouchstoreTest, save_doc) {
    DbInfo info;

    const uint32_t docsInTest = 4;
    Documents documents(docsInTest);
    documents.setDoc(0, "doc1", "{\"test_doc_index\":1}");
    documents.setDoc(1, "doc2", "{\"test_doc_index\":2}");
    documents.setDoc(2, "doc3", "{\"test_doc_index\":3}");
    documents.setDoc(3, "doc4", "{\"test_doc_index\":4}");

    ASSERT_EQ(COUCHSTORE_SUCCESS, open_db(COUCHSTORE_OPEN_FLAG_CREATE));

    for (uint32_t ii = 0; ii < docsInTest; ii++) {
         ASSERT_EQ(COUCHSTORE_SUCCESS,
                   couchstore_save_document(db,
                                            documents.getDoc(ii),
                                            documents.getDocInfo(ii),
                                            0));
    }

    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_commit(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_close_file(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_free_db(db));
    db = nullptr;

    /* Check that sequence numbers got filled in */
    for (uint64_t ii = 0; ii < docsInTest; ++ii) {
        EXPECT_EQ(ii+1, documents.getDocInfo(ii)->db_seq);
    }

    /* Read back */
    ASSERT_EQ(COUCHSTORE_SUCCESS, open_db(0));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_changes_since(db,
                                                           0,
                                                           0,
                                                           &Documents::checkCallback,
                                                           &documents));

    EXPECT_EQ(docsInTest, uint32_t(documents.getCallbacks()));
    EXPECT_EQ(0, documents.getDeleted());

    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_db_info(db, &info));

    EXPECT_EQ(docsInTest, info.last_sequence);
    EXPECT_EQ(docsInTest, info.doc_count);
    EXPECT_EQ(0ul, info.deleted_count);
    EXPECT_EQ((GetParam() ? 2 : 1) * COUCH_BLOCK_SIZE, info.header_position);
}

TEST_P(CouchstoreTest, save_del_docs_in_a_batch) {
    const uint32_t numDocs = 2;
    Documents documents(numDocs);
    documents.setDoc(0, "doc1", "{\"foo\":1}");
    documents.setDoc(1, "doc2", "{\"bar\":2}");

    ASSERT_EQ(COUCHSTORE_SUCCESS, open_db(COUCHSTORE_OPEN_FLAG_CREATE));
    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_save_documents(
                      db, documents.getDocs(), documents.getDocInfos(), 2, 0));

    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_commit(db));
    documents.setDoc(0, "doc1", "{\"foo\":2}");
    documents.delDoc(1);

    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_save_documents(
                      db, documents.getDocs(), documents.getDocInfos(), 2, 0));

    // Retrieve "doc1" & check if the val is updated.
    Doc* doc1 = nullptr;
    std::string doc1Key = "doc1";

    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_open_document(
                      db, doc1Key.data(), doc1Key.size(), &doc1, 0));
    auto val = to_string(doc1->data);
    ASSERT_EQ("{\"foo\":2}", val);

    if (doc1) {
        couchstore_free_document(doc1);
    }

    Doc* doc2 = nullptr;
    std::string doc2Key = "doc2";
    ASSERT_EQ(COUCHSTORE_ERROR_DOC_NOT_FOUND,
              couchstore_open_document(
                      db, doc2Key.data(), doc2Key.size(), &doc2, 0));
    // The doc shouldn't be found!
    ASSERT_EQ(nullptr, doc2);
}

TEST_P(CouchstoreTest, compressed_doc_body)
{
    Documents documents(2);
    documents.setDoc(0, "doc1", "{\"test_doc_index\":1, \"val\":\"blah blah blah blah blah blah\"}");
    documents.setDoc(1, "doc2", "{\"test_doc_index\":2, \"val\":\"blah blah blah blah blah blah\"}");
    documents.setContentMeta(1, COUCH_DOC_IS_COMPRESSED);/* Mark doc2 as to be snappied. */

    ASSERT_EQ(COUCHSTORE_SUCCESS, open_db(COUCHSTORE_OPEN_FLAG_CREATE));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_save_documents(db,
                                  documents.getDocs(),
                                  documents.getDocInfos(),
                                  2,
                                  COMPRESS_DOC_BODIES));

    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_commit(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_close_file(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_free_db(db));
    db = nullptr;

    /* Read back */
    ASSERT_EQ(COUCHSTORE_SUCCESS, open_db(0));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_changes_since(db, 0, 0, &Documents::checkCallback, &documents));
    EXPECT_EQ(2, documents.getCallbacks());
    EXPECT_EQ(0, documents.getDeleted());
}

TEST_P(CouchstoreTest, dump_empty_db)
{
    DbInfo info;
    Documents documents(0);

    ASSERT_EQ(COUCHSTORE_SUCCESS, open_db(COUCHSTORE_OPEN_FLAG_CREATE));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_close_file(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_free_db(db));
    db = nullptr;

    ASSERT_EQ(COUCHSTORE_SUCCESS, open_db(0));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_changes_since(db, 0, 0, &Documents::countCallback, &documents));
    EXPECT_EQ(0, documents.getCallbacks());
    EXPECT_EQ(0, documents.getDeleted());
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_db_info(db, &info));

    EXPECT_STREQ(filePath.c_str(), info.filename);
    EXPECT_EQ(0ull, info.last_sequence);
    EXPECT_EQ(0ull, info.doc_count);
    EXPECT_EQ(0ull, info.deleted_count);
    EXPECT_EQ(0ull, info.space_used);
    EXPECT_EQ(GetParam() ? COUCH_BLOCK_SIZE : 0, info.header_position);
}

TEST_P(CouchstoreTest, local_doc) {
    LocalDoc lDocWrite;
    LocalDoc* lDocRead = nullptr;

    ASSERT_EQ(COUCHSTORE_SUCCESS, open_db(COUCHSTORE_OPEN_FLAG_CREATE));
    lDocWrite.id.buf = const_cast<char*>("_local/testlocal");
    lDocWrite.id.size = 16;
    lDocWrite.json.buf = const_cast<char*>("{\"test\":true}");
    lDocWrite.json.size = 13;
    lDocWrite.deleted = 0;
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_save_local_document(db, &lDocWrite));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_commit(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_close_file(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_free_db(db));
    db = nullptr;
    ASSERT_EQ(COUCHSTORE_SUCCESS, open_db(0));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_open_local_document(db, "_local/testlocal", 16, &lDocRead));
    ASSERT_NE(nullptr, lDocRead);
    EXPECT_EQ(13ull, lDocRead->json.size);

    EXPECT_EQ(0, memcmp(lDocRead->json.buf, "{\"test\":true}", 13));
    couchstore_free_local_document(lDocRead);
}

TEST_P(CouchstoreTest, local_docs_write_read_delete_read) {
    // Note: 11 documents is important to cover a failure when the
    // couchstore_save_local_documents wasn't sorting the input
    // lexicographically, having this input sequence was enough to fail at read.
    // This isn't necessarily the smallest input set to generate the failure
    // but good enough.
    const int docs = 11;
    std::vector<LocalDoc> localDocuments(docs);
    std::vector<std::reference_wrapper<LocalDoc>> localDocRefs;
    localDocRefs.reserve(docs);
    std::vector<std::string> ids(docs);
    std::vector<std::string> values(docs);

    // Generate keys and values for the test
    int ii = 0;
    for (auto& doc : localDocuments) {
        ids[ii] = "_local/" + std::to_string(ii);
        values[ii] = "{\"test\":" + std::to_string(ii) + "}";
        doc.id.buf = const_cast<char*>(ids[ii].data());
        doc.id.size = ids[ii].size();
        doc.json.buf = const_cast<char*>(values[ii].data());
        doc.json.size = values[ii].size();
        doc.deleted = 0;
        localDocRefs.push_back(doc);
        ii++;
    }

    // 1) Write all of the documents using couchstore_save_local_documents
    ASSERT_EQ(COUCHSTORE_SUCCESS, open_db(COUCHSTORE_OPEN_FLAG_CREATE));
    ASSERT_EQ(COUCHSTORE_SUCCESS,
              cb::couchstore::saveLocalDocuments(*db, localDocRefs));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_commit(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_close_file(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_free_db(db));

    // 2) Iterate and read back and compare values
    ASSERT_EQ(COUCHSTORE_SUCCESS, open_db(0));
    ii = 0;
    for (auto& id : ids) {
        LocalDoc* lDocRead{};
        ASSERT_EQ(COUCHSTORE_SUCCESS,
                  couchstore_open_local_document(
                          db, id.data(), id.size(), &lDocRead))
                << id;
        ASSERT_NE(nullptr, lDocRead);
        EXPECT_EQ(ids[ii], std::string(lDocRead->id.buf, lDocRead->id.size));
        EXPECT_EQ(values[ii],
                  std::string(lDocRead->json.buf, lDocRead->json.size));
        couchstore_free_local_document(lDocRead);
        ii++;
    }
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_close_file(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_free_db(db));

    // 3) Now re-write 100% - with delete 50%
    ii = 0;
    for (auto& doc : localDocuments) {
        doc.deleted = (ii & 1) == 1;
        localDocRefs[ii] = doc;
        ii++;
    }

    ASSERT_EQ(COUCHSTORE_SUCCESS, open_db(0));
    ASSERT_EQ(COUCHSTORE_SUCCESS,
              cb::couchstore::saveLocalDocuments(*db, localDocRefs));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_commit(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_close_file(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_free_db(db));

    // 4)  Iterate and read back and compare values
    ASSERT_EQ(COUCHSTORE_SUCCESS, open_db(0));
    ii = 0;
    for (auto& id : ids) {
        LocalDoc* lDocRead;
        auto expected = (ii & 1) == 1 ? COUCHSTORE_ERROR_DOC_NOT_FOUND
                                      : COUCHSTORE_SUCCESS;
        ASSERT_EQ(expected,
                  couchstore_open_local_document(
                          db, id.data(), id.size(), &lDocRead))
                << id;
        if (expected == COUCHSTORE_SUCCESS) {
            ASSERT_NE(nullptr, lDocRead);
            EXPECT_EQ(ids[ii],
                      std::string(lDocRead->id.buf, lDocRead->id.size));
            EXPECT_EQ(values[ii],
                      std::string(lDocRead->json.buf, lDocRead->json.size));
            couchstore_free_local_document(lDocRead);
        }
        ii++;
    }
}

TEST_F(CouchstoreBaseTest, open_file_error)
{

    int errcode;
    errcode = couchstore_open_db(filePath.c_str(), 0, &db);

    EXPECT_EQ(errcode, COUCHSTORE_ERROR_NO_SUCH_FILE);

    /* make sure os.c didn't accidentally call close(0): */
#ifndef WIN32
    EXPECT_TRUE(lseek(0, 0, SEEK_CUR) >= 0 || errno != EBADF);
#endif
}

TEST_P(CouchstoreTest, no_commit_at_create) {
    constexpr auto read_only = COUCHSTORE_OPEN_FLAG_RDONLY;
    constexpr auto no_commit = COUCHSTORE_OPEN_FLAG_CREATE |
                               COUCHSTORE_OPEN_FLAG_NO_COMMIT_AT_CREATE;

    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_open_db(filePath.c_str(), no_commit, &db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_close_file(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_free_db(db));
    ASSERT_EQ(COUCHSTORE_ERROR_NO_HEADER,
              couchstore_open_db(filePath.c_str(), read_only, &db));

    ASSERT_EQ(COUCHSTORE_ERROR_NO_HEADER,
              couchstore_open_db(filePath.c_str(), no_commit, &db));
    ASSERT_EQ(COUCHSTORE_ERROR_NO_HEADER,
              couchstore_open_db(filePath.c_str(), 0, &db));

    ::remove(filePath.c_str());

    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_open_db(filePath.c_str(), no_commit, &db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_commit(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_close_file(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_free_db(db));

    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_open_db(filePath.c_str(), read_only, &db));
    DbInfo info;
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_db_info(db, &info));
    EXPECT_EQ(4096, info.header_position);
}

TEST_P(CouchstoreTest, changes_no_dups)
{
    const size_t numdocs = 10000;
    int updatebatch = 1000;
    DbInfo info;

    Documents documents(numdocs);
    for (size_t ii = 0; ii < numdocs; ii++) {
        std::string key = "doc" + std::to_string(ii);
        std::string data = "{\"test_doc_index\":" + std::to_string(ii) + "}";
        documents.setDoc(ii, key, data);
    }

    ASSERT_EQ(COUCHSTORE_SUCCESS, open_db(COUCHSTORE_OPEN_FLAG_CREATE));
    /* only save half the docs at first. */
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_save_documents(db,
                                                            documents.getDocs(),
                                                            documents.getDocInfos(),
                                                            numdocs/2,
                                                            0));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_commit(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_close_file(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_free_db(db));
    db = nullptr;

    for (size_t ii = 0; ii < numdocs/2; ii++) {
        /* increment the rev for already added docs */
        documents.getDocInfo(ii)->rev_seq++;
    }

    /* now shuffle so some bulk updates contain previous docs and new docs */
    documents.shuffle();

    ASSERT_EQ(COUCHSTORE_SUCCESS, open_db(0));

    for (size_t ii=0; ii < numdocs; ii += updatebatch) {
        /* now do bulk updates and check the changes for dups */
        ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_save_documents(db,
                                                                documents.getDocs() + ii,
                                                                documents.getDocInfos() + ii,
                                                                updatebatch,
                                                                0));
        ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_commit(db));
        ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_changes_since(db, 0, 0,
                                                               &Documents::docMapUpdateCallback,
                                                               &documents));
        documents.clearDocumentMap();
    }

    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_db_info(db, &info));
    EXPECT_EQ((uint64_t)(numdocs + numdocs/2), info.last_sequence);
    EXPECT_EQ(numdocs, info.doc_count);
    EXPECT_EQ(0ull, info.deleted_count);
}

TEST_F(CouchstoreBaseTest, mb5086)
{
    Documents documents(1);
    documents.setDoc(0, "hi", "foo");

    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_open_db("mb5085.couch", COUCHSTORE_OPEN_FLAG_CREATE, &db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_save_document(db,
                                                           documents.getDoc(0),
                                                           documents.getDocInfo(0),
                                                           0));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_commit(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_close_file(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_free_db(db));
    ASSERT_EQ(0, remove("mb5085.couch"));
    db = nullptr; // we've closed and deleted the test-case's file
}

TEST_P(CouchstoreTest, mb11104) {
    DbInfo info;
    const int batchSize = 3;
    sized_buf ids[batchSize];
    Documents documents(batchSize * 3);
    for (int ii = 0; ii < batchSize*3; ii++) {
        std::string key = "doc" + std::to_string(ii);
        std::string data = "{\"test_doc_index\":" + std::to_string(ii) + "}";
        documents.setDoc(ii, key, data);
    }
    int storeIndex[4] = {0, 2, 4, 6};

    ASSERT_EQ(COUCHSTORE_SUCCESS, open_db(COUCHSTORE_OPEN_FLAG_CREATE));
    // store some of the documents
    for (int ii = 0; ii < 4; ii++) {
       ASSERT_EQ(COUCHSTORE_SUCCESS,
                 couchstore_save_document(db,
                                          documents.getDoc(storeIndex[ii]),
                                          documents.getDocInfo(storeIndex[ii]),
                                          0));
    }

    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_commit(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_close_file(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_free_db(db));
    db = nullptr;
    ASSERT_EQ(COUCHSTORE_SUCCESS, open_db(0));

    /* Read back in bulk by doc IDs, some of which are not existent */
    {
        Documents callbackCounter(0);
        for (int ii = 0; ii < batchSize; ++ii) { // "doc1", "doc2", "doc3"
            ids[ii].size = documents.getDoc(ii)->id.size;
            ids[ii].buf = documents.getDoc(ii)->id.buf;
        }

        ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_docinfos_by_id(db,
                                                                ids,
                                                                batchSize,
                                                                0,
                                                                &Documents::docIterCheckCallback,
                                                                &callbackCounter));
        EXPECT_EQ(2, callbackCounter.getCallbacks());
        EXPECT_EQ(0, callbackCounter.getDeleted());
    }
    {
        Documents callbackCounter(0);
        for (int ii = 0; ii < batchSize; ++ii) { // "doc2", "doc4", "doc6"
            int idx = ii * 2 + 1;
            ids[ii].size = documents.getDoc(idx)->id.size;
            ids[ii].buf = documents.getDoc(idx)->id.buf;
        }

        ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_docinfos_by_id(db,
                                                                ids,
                                                                batchSize,
                                                                0,
                                                                &Documents::docIterCheckCallback,
                                                                &callbackCounter));
        EXPECT_EQ(0, callbackCounter.getCallbacks());
        EXPECT_EQ(0, callbackCounter.getDeleted());
    }
    {
        Documents callbackCounter(0);
        for (int ii = 0; ii < batchSize; ++ii) { // "doc3", "doc6", "doc9"
            int idx = ii * 3 + 2;
            ids[ii].size = documents.getDoc(idx)->id.size;
            ids[ii].buf = documents.getDoc(idx)->id.buf;
        }

        ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_docinfos_by_id(db,
                                                                ids,
                                                                batchSize,
                                                                0,
                                                                &Documents::docIterCheckCallback,
                                                                &callbackCounter));
        EXPECT_EQ(1, callbackCounter.getCallbacks());
        EXPECT_EQ(0, callbackCounter.getDeleted());
    }


    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_db_info(db, &info));
    EXPECT_EQ(4ull, info.last_sequence);
    EXPECT_EQ(4ull, info.doc_count);
    EXPECT_EQ(0ull, info.deleted_count);
    EXPECT_EQ((GetParam() ? 2 : 1) * COUCH_BLOCK_SIZE, info.header_position);
}

TEST_P(CouchstoreTest, asis_seqs) {
    DocInfo *ir = nullptr;

    Documents documents(3);
    ASSERT_EQ(COUCHSTORE_SUCCESS, open_db(COUCHSTORE_OPEN_FLAG_CREATE));
    documents.setDoc(0, "test", "foo");
    documents.getDocInfo(0)->db_seq = 1;
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_save_document(db,
                                                           documents.getDoc(0),
                                                           documents.getDocInfo(0),
                                                           COUCHSTORE_SEQUENCE_AS_IS));
    EXPECT_EQ(1ull, db->header.update_seq);

    documents.setDoc(1, "test_two", "foo");
    documents.getDocInfo(1)->db_seq = 12;
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_save_document(db,
                                                           documents.getDoc(1),
                                                           documents.getDocInfo(1),
                                                           COUCHSTORE_SEQUENCE_AS_IS));
    EXPECT_EQ(12ull, db->header.update_seq);

    documents.setDoc(2, "test_foo", "foo");
    documents.getDocInfo(2)->db_seq = 6;
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_save_document(db,
                                                           documents.getDoc(2),
                                                           documents.getDocInfo(2),
                                                           COUCHSTORE_SEQUENCE_AS_IS));
    EXPECT_EQ(12ull, db->header.update_seq);

    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_docinfo_by_id(db, "test", 4, &ir));
    EXPECT_EQ(1ull, ir->db_seq);

    couchstore_free_docinfo(ir);

    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_docinfo_by_id(db, "test_two", 8, &ir));
    EXPECT_EQ(12ull, ir->db_seq);
    couchstore_free_docinfo(ir);

    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_docinfo_by_id(db, "test_foo", 8, &ir));
    EXPECT_EQ(6ull, ir->db_seq);
    couchstore_free_docinfo(ir);

}

TEST_F(CouchstoreBaseTest, huge_revseq)
{
    DocInfo *i2;
    Documents documents(1);
    documents.setDoc(0, "hi", "foo");
    documents.getDocInfo(0)->rev_seq = 5294967296;

    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_open_db("bigrevseq.couch", COUCHSTORE_OPEN_FLAG_CREATE, &db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_save_document(db,
                                                           documents.getDoc(0),
                                                           documents.getDocInfo(0),
                                                           0));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_commit(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_docinfo_by_id(db, "hi", 2, &i2));
    EXPECT_EQ(i2->rev_seq, 5294967296ull);
    couchstore_free_docinfo(i2);
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_close_file(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_free_db(db));
    ASSERT_EQ(0, remove("bigrevseq.couch"));
    db = nullptr; // mark as null, as we've cleaned up
}

// Create a new-file(s) and check crc is crc32-c
TEST_F(CouchstoreBaseTest, crc32c) {
    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_open_db(filePath.c_str(),
                                 COUCHSTORE_OPEN_FLAG_CREATE,
                                 &db));
    EXPECT_EQ(CRC32C, db->file.crc_mode);
}

// Create a new-file(s) and test that we can't open again with old CRC
TEST_F(CouchstoreBaseTest, legacy_crc_flags) {
    // Open the new/clean file and ask for 'legacy-CRC'
    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_open_db(filePath.c_str(),
                                 COUCHSTORE_OPEN_FLAG_CREATE |
                                 COUCHSTORE_OPEN_WITH_LEGACY_CRC,
                                 &db));

    EXPECT_EQ(CRC32, db->file.crc_mode);
    EXPECT_GE(uint64_t(COUCH_DISK_VERSION_11), db->header.disk_version);

    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_close_file(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_free_db(db));
    db = nullptr;

    // Open the now existing file and we should be allowed if ask for legacy-crc
    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_open_db(filePath.c_str(),
                                 COUCHSTORE_OPEN_FLAG_CREATE |
                                 COUCHSTORE_OPEN_WITH_LEGACY_CRC,
                                 &db));

    EXPECT_EQ(CRC32, db->file.crc_mode);
    EXPECT_GE(uint64_t(COUCH_DISK_VERSION_11), db->header.disk_version);

    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_close_file(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_free_db(db));
    db = nullptr;

    // Open the now existing file and we should be allowed, legacy crc will be auto-selected
    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_open_db(filePath.c_str(),
                                 COUCHSTORE_OPEN_FLAG_CREATE,
                                 &db));

    EXPECT_EQ(CRC32, db->file.crc_mode);
    EXPECT_GE(uint64_t(COUCH_DISK_VERSION_11), db->header.disk_version);

    // Close and delete.
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_close_file(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_free_db(db));
    db = nullptr;

    ASSERT_EQ(0, remove(filePath.c_str()));

    // Open the a new file without legacy CRC
    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_open_db(filePath.c_str(),
                                 COUCHSTORE_OPEN_FLAG_CREATE,
                                 &db));

    // Should be in crc32c
    EXPECT_EQ(CRC32C, db->file.crc_mode);
    EXPECT_GE(uint64_t(COUCH_DISK_VERSION_14), db->header.disk_version);

    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_close_file(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_free_db(db));
    db = nullptr;

    // Open it again and we should not be allowed.
    ASSERT_EQ(COUCHSTORE_ERROR_INVALID_ARGUMENTS,
              couchstore_open_db(filePath.c_str(),
                                 COUCHSTORE_OPEN_FLAG_CREATE |
                                 COUCHSTORE_OPEN_WITH_LEGACY_CRC,
                                 &db));

    // no open file for destruction...
    db = nullptr;
}

// Test compaction doesn't upgrade (no upgrade flag specified)
TEST_F(CouchstoreBaseTest, no_crc_upgrade) {

    const int docCount = 100;
    Documents documents(docCount);
    documents.generateDocs();

    // Open file in legacy mode
    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_open_db(filePath.c_str(),
                                 COUCHSTORE_OPEN_FLAG_CREATE |
                                 COUCHSTORE_OPEN_WITH_LEGACY_CRC,
                                 &db));
    EXPECT_EQ(CRC32, db->file.crc_mode);

    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_save_documents(db,
                                                            documents.getDocs(),
                                                            documents.getDocInfos(),
                                                            docCount,
                                                            0));

    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_commit(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_close_file(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_free_db(db));
    db = nullptr;

    // re-open, we're going to compact the file
    ASSERT_EQ(COUCHSTORE_SUCCESS,
        couchstore_open_db(filePath.c_str(),
                           0,
                           &db));
    EXPECT_EQ(CRC32, db->file.crc_mode);
    // new file should 11 or less
    EXPECT_LE(db->header.disk_version, uint64_t(COUCH_DISK_VERSION_11));

    std::string target("compacted.couch");
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_compact_db_ex(db,
                                                           target.c_str(),
                                                           0,
                                                           nullptr,
                                                           nullptr,
                                                           nullptr,
                                                           couchstore_get_default_file_ops()));

    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_close_file(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_free_db(db));
    db = nullptr;

    // Open target...
    ASSERT_EQ(COUCHSTORE_SUCCESS,
        couchstore_open_db(target.c_str(),
                           0,
                           &db));

    EXPECT_EQ(CRC32, db->file.crc_mode); // new file still uses old CRC
    EXPECT_LE(db->header.disk_version, uint64_t(COUCH_DISK_VERSION_11)); // compacted file still 11 or less
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_close_file(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_free_db(db));
    db = nullptr;
    ASSERT_EQ(0, remove(target.c_str()));
}

// Test compaction upgrades when upgrade flag specified.
TEST_F(CouchstoreBaseTest, crc_upgrade) {
    const int docCount = 100;
    Documents documents(docCount);
    documents.generateDocs();

    // Open file in legacy mode
    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_open_db(filePath.c_str(),
                                 COUCHSTORE_OPEN_FLAG_CREATE |
                                 COUCHSTORE_OPEN_WITH_LEGACY_CRC,
                                 &db));
    EXPECT_EQ(CRC32, db->file.crc_mode);
    // new file must be version 11 or less
    EXPECT_LE(db->header.disk_version, uint64_t(COUCH_DISK_VERSION_11));

    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_save_documents(db,
                                                            documents.getDocs(),
                                                            documents.getDocInfos(),
                                                            docCount,
                                                            0));

    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_commit(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_close_file(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_free_db(db));
    db = nullptr;

    // re-open, we're going to compact the file
    ASSERT_EQ(COUCHSTORE_SUCCESS,
        couchstore_open_db(filePath.c_str(),
                           COUCHSTORE_OPEN_FLAG_CREATE,
                           &db));
    EXPECT_EQ(CRC32, db->file.crc_mode);

    std::string target("compacted.couch");
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_compact_db_ex(db,
                                                           target.c_str(),
                                                           COUCHSTORE_COMPACT_FLAG_UPGRADE_DB,
                                                           nullptr,
                                                           nullptr,
                                                           nullptr,
                                                           couchstore_get_default_file_ops()));

    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_close_file(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_free_db(db));
    db = nullptr;

    // Open target...
    ASSERT_EQ(COUCHSTORE_SUCCESS,
        couchstore_open_db(target.c_str(),
                           0,
                           &db));

    // File now with CRC32-C
    EXPECT_EQ(CRC32C, db->file.crc_mode);
    EXPECT_GE(db->header.disk_version, uint64_t(COUCH_DISK_VERSION_12)); // upgraded to 12
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_close_file(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_free_db(db));
    db = nullptr;
    ASSERT_EQ(0, remove(target.c_str()));
}

// Test compaction upgrades has no ill effect when upgrade flag specified and the file
// is already at version 12/crc32c
TEST_F(CouchstoreBaseTest, crc_upgrade2) {
    const size_t docCount = 100;
    Documents documents(docCount);
    documents.generateDocs();

    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_open_db(filePath.c_str(),
                                 COUCHSTORE_OPEN_FLAG_CREATE,
                                 &db));
    EXPECT_EQ(CRC32C, db->file.crc_mode);
    // Source file must already be version 12 or greater
    EXPECT_GE(db->header.disk_version, uint64_t(COUCH_DISK_VERSION_12));

    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_save_documents(db,
                                                            documents.getDocs(),
                                                            documents.getDocInfos(),
                                                            docCount,
                                                            0));

    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_commit(db));

    std::string target("compacted.couch");
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_compact_db_ex(db,
                                                           target.c_str(),
                                                           COUCHSTORE_COMPACT_FLAG_UPGRADE_DB,
                                                           nullptr,
                                                           nullptr,
                                                           nullptr,
                                                           couchstore_get_default_file_ops()));

    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_close_file(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_free_db(db));
    db = nullptr;

    // Open target...
    ASSERT_EQ(COUCHSTORE_SUCCESS,
        couchstore_open_db(target.c_str(),
                           0,
                           &db));

    // File should still be v12 with crc32C
    EXPECT_EQ(CRC32C, db->file.crc_mode);
    EXPECT_GE(db->header.disk_version, uint64_t(COUCH_DISK_VERSION_12)); // still version 12

    // Now use callback to validate new file.
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_changes_since(db,
                                                           0,
                                                           0,
                                                           &Documents::checkCallback,
                                                           &documents));

    EXPECT_EQ(docCount, size_t(documents.getCallbacks()));
    EXPECT_EQ(0, documents.getDeleted());

    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_close_file(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_free_db(db));
    db = nullptr;
    ASSERT_EQ(0, remove(target.c_str()));
}

TEST_P(CouchstoreTest, MB40415_precommit_hook) {
    const size_t docCount = 10;
    Documents documents(docCount);
    documents.generateDocs();
    ASSERT_EQ(COUCHSTORE_SUCCESS, open_db(COUCHSTORE_OPEN_FLAG_CREATE));
    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_save_documents(db,
                                        documents.getDocs(),
                                        documents.getDocInfos(),
                                        docCount,
                                        0));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_commit(db));

    std::string target("compacted.couch");
    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_compact_db_ex(
                      db,
                      target.c_str(),
                      0,
                      nullptr,
                      nullptr,
                      nullptr,
                      couchstore_get_default_file_ops(),
                      [](Db&, Db& mdb) -> couchstore_error_t {
                          LocalDoc ldoc;
                          ldoc.id.buf = const_cast<char*>("_local/mb-40415");
                          ldoc.id.size = 15;
                          ldoc.json.buf = const_cast<char*>("{\"test\":true}");
                          ldoc.json.size = 13;
                          ldoc.deleted = 0;
                          return couchstore_save_local_document(&mdb, &ldoc);
                      }));

    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_close_file(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_free_db(db));

    // Open target and verify there is a single header in the file and
    // the local doc is present
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_open_db(target.c_str(), 0, &db));

    LocalDoc* ldoc;
    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_open_local_document(db, "_local/mb-40415", 15, &ldoc));
    couchstore_free_local_document(ldoc);

    // There should not be any previous header
    ASSERT_EQ(COUCHSTORE_ERROR_DB_NO_LONGER_VALID,
              couchstore_rewind_db_header(db));
    ASSERT_EQ(0, remove(target.c_str()));
    db = nullptr;
}

// Parameters for MT_save_worker.
struct MT_save_args {
    size_t worker_id;
    Db* db;
    std::string file_path_prefix;
};

// Worker thread for MT_save test.
void MT_save_worker(void* voidargs) {
    MT_save_args *args = static_cast<MT_save_args*>(voidargs);
    std::string file_path = args->file_path_prefix
                            + std::to_string(args->worker_id);
    remove(file_path.c_str());

    const uint32_t docsInTest = 100;
    std::string key_str, value_str;
    Documents documents(docsInTest);

    for (uint32_t ii = 0; ii < docsInTest; ii++) {
        key_str = "doc" + std::to_string(ii);
        value_str = "{\"test_doc_index\":" + std::to_string(ii) + "}";
        documents.setDoc(ii, key_str, value_str);
    }

    // Save docs.
    couchstore_open_db(file_path.c_str(),
                       COUCHSTORE_OPEN_FLAG_CREATE, &args->db);

    for (uint32_t ii = 0; ii < docsInTest; ii++) {
        couchstore_save_document(args->db,
                                 documents.getDoc(ii),
                                 documents.getDocInfo(ii),
                                 0);
    }

    couchstore_commit(args->db);
    couchstore_close_file(args->db);
    couchstore_free_db(args->db);

    // Check docs.
    couchstore_open_db(file_path.c_str(),
                       COUCHSTORE_OPEN_FLAG_CREATE, &args->db);

    documents.resetCounters();
    std::vector<sized_buf> buf(docsInTest);
    for (uint32_t ii = 0; ii < docsInTest; ++ii) {
        buf[ii] = documents.getDoc(ii)->id;
    }
    couchstore_docinfos_by_id(args->db,
                              &buf[0],
                              docsInTest,
                              0,
                              &Documents::docIterCheckCallback,
                              &documents);
    couchstore_close_file(args->db);
    couchstore_free_db(args->db);
}

// Context for callback function of latency collector.
struct MT_save_callback_ctx {
    // Number of threads.
    size_t num_threads;
};

int MT_save_callback(const char* stat_name,
                     CouchLatencyHisto* latencies,
                     const CouchLatencyMicroSecRep elapsed_time,
                     void* ctx) {
    struct MT_save_callback_ctx *actual_ctx =
            static_cast<MT_save_callback_ctx*>(ctx);
    uint64_t count_total = 0;
    for (auto& itr_hist : *latencies) {
        count_total += itr_hist->count();
    }

    // # calls of all APIs should be
    // the multiplication of # threads.
    EXPECT_EQ(static_cast<size_t>(0), count_total % actual_ctx->num_threads);

    return 0;
}

// Multi-threaded document saving and loading test.
// Check if latency collector registers latency timer
// for each API correctly, under the racing condition.
TEST_P(CouchstoreMTTest, MT_save)
{
    const size_t numRepeat = 4;
    const bool enable_collector = std::get<0>(GetParam());
    for (size_t rpt = 0; rpt < numRepeat; ++rpt) {
        if (enable_collector) {
            couchstore_latency_collector_start();
        }

        std::vector<std::thread> t_handles(numThreads);
        std::vector<MT_save_args> args(numThreads);

        for (size_t ii = 0; ii < numThreads; ++ii) {
            args[ii].worker_id = ii;
            args[ii].db = dbs[ii];
            args[ii].file_path_prefix = filePath;
            t_handles[ii] = std::thread(MT_save_worker, &args[ii]);
        }

        for (size_t ii = 0; ii < numThreads; ++ii) {
            t_handles[ii].join();
            // 'dbs[ii]' is already closed at the end of above thread.
            dbs[ii] = nullptr;
        }

        if (enable_collector) {
            couchstore_latency_dump_options options;
            MT_save_callback_ctx ctx = {numThreads};
            couchstore_get_latency_info(MT_save_callback,
                                        options,
                                        &ctx);
            couchstore_latency_collector_stop();
        }
    }
}

/* Test to check that retrieving an item with value of zero length
 * doesn't result in a memory leak
 */
TEST_F(CouchstoreBaseTest, mb23697) {
    DocInfo* ir = nullptr;
    Doc* doc = nullptr;

    Documents documents(1);
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_open_db(filePath.c_str(),
              COUCHSTORE_OPEN_FLAG_CREATE, &db));
    documents.setDoc(0, "test", "");
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_save_document(db,
                                                           documents.getDoc(0),
                                                           documents.getDocInfo(0),
                                                           0));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_docinfo_by_id(db, "test", 4, &ir));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_open_doc_with_docinfo(db, ir, &doc,
                                                      DECOMPRESS_DOC_BODIES));
    EXPECT_EQ(static_cast<size_t>(0), doc->data.size);
    couchstore_free_docinfo(ir);
    couchstore_free_document(doc);
}

static int time_purge_hook_impl(Db* target, DocInfo* info, sized_buf item) {
    if (item.buf == nullptr) {
        return COUCHSTORE_COMPACT_NEED_BODY;
    }

    return COUCHSTORE_SUCCESS;
}

class CompactionHookInterface {
    public:
        virtual int time_purge_hook(Db* target, DocInfo* info, sized_buf item) = 0;
};

class CompactionHook : CompactionHookInterface {
    public:
        virtual int time_purge_hook(Db* target, DocInfo* info, sized_buf item) {
            return time_purge_hook_impl(target, info, item);
        }
};

class MockTimePurgeHook : CompactionHook {
    public:
        MOCK_METHOD3(time_purge_hook, int(Db* target, DocInfo* info, sized_buf item));
};

int mockTimePurgeHook(Db* target, DocInfo* info, sized_buf item, void* ctx_p) {
    auto* ctx = reinterpret_cast<MockTimePurgeHook*>(ctx_p);
    return ctx->time_purge_hook(target, info, item);
}

/* Test to check that the compaction will send the full body in case the
 * client requests the same
 */
TEST_F(CouchstoreBaseTest, compact_need_body) {
    Documents documents(1);
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_open_db(filePath.c_str(),
              COUCHSTORE_OPEN_FLAG_CREATE, &db));
    documents.setDoc(0, "key", "value");
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_save_document(db,
                                                           documents.getDoc(0),
                                                           documents.getDocInfo(0),
                                                           0));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_commit(db));

    MockTimePurgeHook tph;
    std::string target("compacted.couch");
    EXPECT_CALL(tph, time_purge_hook(_,_,_)).Times(3)
                                            .WillOnce(testing::Return(COUCHSTORE_COMPACT_NEED_BODY))
                                            .WillOnce(testing::Return(COUCHSTORE_SUCCESS))
                                            .WillOnce(testing::Return(COUCHSTORE_SUCCESS));

    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_compact_db_ex(db,
                                                           target.c_str(),
                                                           0,
                                                           mockTimePurgeHook,
                                                           nullptr,
                                                           &tph,
                                                           couchstore_get_default_file_ops()));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_close_file(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_free_db(db));
    db = nullptr;
    ASSERT_EQ(0, remove(target.c_str()));
}


/** verify couchstore_changes_count() returns correct values
 *
 * couchstore_changes_count() will return the # of unique documents
 * that have been inserted between 2 sequence #s. The sequence # will
 * increase for updated and deleted documents but the count of original
 * documents between the 2 sequence #'s remains the same
 */
TEST_P(CouchstoreTest, test_changes_count) {
    ASSERT_EQ(COUCHSTORE_SUCCESS, open_db(COUCHSTORE_OPEN_FLAG_CREATE));

    /**
     * add some documents to the database and make sure the count =
     * the number of documents added
     */
    const int ndocs = 5; // use a value at least >= 5
    Documents documents(ndocs);
    const std::string ori_doc = "{\"test_doc\":\"original\"}";

    for (int ii = 0; ii < ndocs; ++ii) {
        std::string key = "doc" + std::to_string(ii);
        documents.setDoc(ii, key, ori_doc);
    }
    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_save_documents(db,
                                        documents.getDocs(),
                                        documents.getDocInfos(),
                                        ndocs,
                                        0));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_commit(db));

    /**
     * count from the first seq # of the first doc added until the end
     */
    uint64_t count;
    uint64_t start_seq = documents.getDocInfo(0)->db_seq;
    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_changes_count(
                      db, start_seq, db->header.update_seq, &count));
    ASSERT_EQ(count, ndocs);

    /**
     * update a few docs... count should stay the same
     */
    documents.resetCounters();

    std::string upd_doc = "{\"test_doc\":\"updated\"}";
    documents.setDoc(0, "doc0", upd_doc);
    documents.setDoc(1, "doc3", upd_doc);
    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_save_documents(
                      db, documents.getDocs(), documents.getDocInfos(), 2, 0));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_commit(db));

    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_changes_count(
                      db, start_seq, db->header.update_seq, &count));
    ASSERT_EQ(count, ndocs);

    /**
     * delete a few docs... count should stay the same
     */
    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_save_documents(
                      db, nullptr, documents.getDocInfos(), 2, 0));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_commit(db));

    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_changes_count(
                      db, start_seq, db->header.update_seq, &count));
    ASSERT_EQ(count, ndocs);

    /**
     * add some more documents
     */
    documents.resetCounters();
    for (int ii = 0; ii < ndocs; ++ii) {
        std::string key = "doc" + std::to_string(ii + ndocs);
        documents.setDoc(ii, key, ori_doc);
    }
    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_save_documents(db,
                                        documents.getDocs(),
                                        documents.getDocInfos(),
                                        ndocs,
                                        0));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_commit(db));

    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_changes_count(
                      db, start_seq, db->header.update_seq, &count));
    ASSERT_EQ(count, ndocs + ndocs);

    /**
     * we updated the first doc in the sequence which moved its seq #
     * so there are still 10 changed docs between the sequence #'s
     */
    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_changes_count(
                      db, start_seq + 1, db->header.update_seq, &count));
    ASSERT_EQ(count, ndocs + ndocs);

    /**
     * the 2nd doc was untouched so if we ask for changed docs
     * past it, we should get total - 1
     */
    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_changes_count(
                      db, start_seq + 2, db->header.update_seq, &count));
    ASSERT_EQ(count, ndocs + ndocs - 1);

    /* don't include the last document */
    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_changes_count(
                      db, start_seq, db->header.update_seq - 1, &count));
    ASSERT_EQ(count, ndocs + ndocs - 1);

    DbInfo info;
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_db_info(db, &info));

    /* deleted 2 docs */
    EXPECT_EQ(ndocs + ndocs - 2, info.doc_count);
    EXPECT_EQ(2, info.deleted_count);

    /* ndocs + ndocs + 2 updates + 2 deletes */
    EXPECT_EQ(ndocs + ndocs + 2 + 2, info.last_sequence);

    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_close_file(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_free_db(db));
    db = nullptr;
}

/**
 * verify that couchstore_set_purge_seq() sets the purge_seq and retains
 * that value if the file is closed and reopened.
 */
TEST_F(CouchstoreBaseTest, test_set_purge_seq) {
    const int ndocs = 100; // use a value at least >= 5
    Documents documents(ndocs);

    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_open_db(
                      filePath.c_str(), COUCHSTORE_OPEN_FLAG_CREATE, &db));

    for (int ii = 0; ii < ndocs; ++ii) {
        std::string key = "doc" + std::to_string(ii);
        std::string doc = "{\"test_doc\":\"original\"}";
        documents.setDoc(ii, key, doc);
    }
    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_save_documents(db,
                                        documents.getDocs(),
                                        documents.getDocInfos(),
                                        ndocs,
                                        0));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_commit(db));

    DbInfo info1;
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_db_info(db, &info1));

    /**
     * verify the purge_seq is 0
     */
    ASSERT_EQ(0, info1.purge_seq);

    /**
     * set the purge_seq to 1/2 of the last_sequence
     */
    uint64_t pseq = info1.last_sequence / 2;
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_set_purge_seq(db, pseq));

    /**
     * commit and close the file
     */
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_commit(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_close_file(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_free_db(db));
    db = nullptr;

    /**
     * reopen the file and verify the purge_seq is set to the correct value
     */
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_open_db(filePath.c_str(), 0, &db));
    DbInfo info2;
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_db_info(db, &info2));
    ASSERT_EQ(info2.purge_seq, pseq);
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_close_file(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_free_db(db));
    db = nullptr;
}

static int readDocInfos(Db *db, DocInfo *docinfo, void *ctx) {
    auto counter = reinterpret_cast<int*>(ctx);
    (*counter)++;
    return 0;
}

TEST_P(CouchstoreTest, MB_29816) {
    {
        const int ndocs = 1;
        Documents documents(ndocs);

        ASSERT_EQ(COUCHSTORE_SUCCESS, open_db(COUCHSTORE_OPEN_FLAG_CREATE));


        documents.setDoc(0, "00005", "value");
        ASSERT_EQ(COUCHSTORE_SUCCESS,
                  couchstore_save_documents(db,
                                            documents.getDocs(),
                                            documents.getDocInfos(),
                                            ndocs,
                                            0));
        ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_commit(db));
        ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_close_file(db));
        ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_free_db(db));
    }
    // Now create and update overlapping
    {
        ASSERT_EQ(COUCHSTORE_SUCCESS, open_db(COUCHSTORE_OPEN_FLAG_CREATE));
        const int ndocs = 2;
        Documents documents(ndocs);

        // The order here is what triggers the bug.
        // In this input 00004 < 00005
        // If we changed it so 00006 instead of 00004 the MB issue won't trigger
        // Basically after sorting the inputs the inners of couchstore skips
        // evaluating 00005 as the failure to find of 00004 helps to terminate
        // a search loop when it should of kept going.
        documents.setDoc(0, "00005", "value");
        documents.setDoc(1, "00004", "value");
        std::vector<sized_buf> sbuf;
        for (int ii = 0; ii < ndocs; ++ii) {
            sbuf.push_back(documents.getDoc(ii)->id);
        }
        int callbackCounter = 0;
        ASSERT_EQ(COUCHSTORE_SUCCESS,
                  couchstore_docinfos_by_id(db,
                                            sbuf.data(),
                                            sbuf.size(),
                                            0,
                                            readDocInfos,
                                            &callbackCounter));

        ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_close_file(db));
        ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_free_db(db));
        // Expect we got 1 callback for our key
        EXPECT_EQ(1, callbackCounter);
    }
    db = nullptr;
}

/// Test that a range scan doesn't scan past the ed of the given set of keys.
TEST_F(CouchstoreBaseTest, MB33373_RangeScan) {
    // Setup - store 5 keys (0..4)
    Documents documents(5);
    documents.generateDocs("");

    // store all of the documents
    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_open_db(
                      filePath.c_str(), COUCHSTORE_OPEN_FLAG_CREATE, &db));
    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_save_documents(db,
                                        documents.getDocs(),
                                        documents.getDocInfos(),
                                        documents.getDocsCount(),
                                        0));

    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_commit(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_close_file(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_free_db(db));
    db = nullptr;
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_open_db(filePath.c_str(), 0, &db));

    // Test: attempt to read back the range 1..3. Should return 1, 2 & 3.
    const std::array<sized_buf, 2> keys = {
            {documents.getDoc(1)->id, documents.getDoc(3)->id}};
    Documents expected(3);
    expected.setDoc(0, "1", "1-data");
    expected.setDoc(1, "2", "2-data");
    expected.setDoc(2, "3", "3-data");

    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_docinfos_by_id(db,
                                        keys.data(),
                                        keys.size(),
                                        RANGES,
                                        &Documents::checkCallback,
                                        &expected));
}

/// Test that multiple range scans work correctly.
TEST_F(CouchstoreBaseTest, RangeScanMulti) {
    // Setup - store 10 keys (0..9)
    Documents documents(10);
    documents.generateDocs("");

    // store all of the documents
    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_open_db(
                      filePath.c_str(), COUCHSTORE_OPEN_FLAG_CREATE, &db));
    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_save_documents(db,
                                        documents.getDocs(),
                                        documents.getDocInfos(),
                                        documents.getDocsCount(),
                                        0));

    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_commit(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_close_file(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_free_db(db));
    db = nullptr;
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_open_db(filePath.c_str(), 0, &db));

    // Test: attempt to read back the ranges 2..4 and 6..8.
    // Should return 2, 3, 4, 6, 7, 8
    const std::array<sized_buf, 4> keys = {{documents.getDoc(2)->id,
                                            documents.getDoc(3)->id,
                                            documents.getDoc(6)->id,
                                            documents.getDoc(8)->id}};

    Documents expected(6);
    expected.setDoc(0, "2", "2-data");
    expected.setDoc(1, "3", "3-data");
    expected.setDoc(2, "4", "4-data");
    expected.setDoc(3, "6", "6-data");
    expected.setDoc(4, "7", "7-data");
    expected.setDoc(5, "8", "8-data");

    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_docinfos_by_id(db,
                                        keys.data(),
                                        keys.size(),
                                        RANGES,
                                        &Documents::checkCallback,
                                        &expected));
}

// Test demonstrating inclusive range
TEST_F(CouchstoreBaseTest, RangeScanIsInclusive) {
    Documents documents(4);
    documents.generateDocs();

    // store all of the documents
    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_open_db(
                      filePath.c_str(), COUCHSTORE_OPEN_FLAG_CREATE, &db));
    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_save_documents(db,
                                        documents.getDocs(),
                                        documents.getDocInfos(),
                                        documents.getDocsCount(),
                                        0));

    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_commit(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_close_file(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_free_db(db));
    db = nullptr;
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_open_db(filePath.c_str(), 0, &db));

    // expected result is inclusive of end - [doc0, doc2]
    std::string start = "doc0";
    std::string end = "doc2";
    std::vector<sized_buf> ranges;
    ranges.emplace_back(sized_buf{start.data(), start.size()});
    ranges.emplace_back(sized_buf{end.data(), end.size()});

    Documents expected0(3);
    expected0.setDoc(0, "doc0", "0-data");
    expected0.setDoc(1, "doc1", "1-data");
    expected0.setDoc(2, "doc2", "2-data");

    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_docinfos_by_id(db,
                                        ranges.data(),
                                        ranges.size(),
                                        RANGES,
                                        &Documents::checkCallback,
                                        &expected0));

    EXPECT_EQ(3, expected0.getCallbacks());

    // Assuming start is a prefix, we can create and end key from start and
    // get all doc prefixed documents
    ranges.clear();
    start = "doc";
    end = start;
    end.append("\xff");
    ranges.emplace_back(sized_buf{start.data(), start.size()});
    ranges.emplace_back(sized_buf{end.data(), end.size()});
    Documents expected1(4);
    expected1.setDoc(0, "doc0", "0-data");
    expected1.setDoc(1, "doc1", "1-data");
    expected1.setDoc(2, "doc2", "2-data");
    expected1.setDoc(3, "doc3", "3-data");

    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_docinfos_by_id(db,
                                        ranges.data(),
                                        ranges.size(),
                                        RANGES,
                                        &Documents::checkCallback,
                                        &expected1));

    EXPECT_EQ(4, expected1.getCallbacks());
}

// Minimal reproducer for MB-52010. Here 1 key exists in the kvstore and is
// incorrectly returned by a range scan.
TEST_F(CouchstoreBaseTest, MB_52010) {
    // Generate 1 document "d0"
    Documents documents(1);
    documents.generateDocs("d");

    // store all of the documents
    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_open_db(
                      filePath.c_str(), COUCHSTORE_OPEN_FLAG_CREATE, &db));
    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_save_documents(db,
                                        documents.getDocs(),
                                        documents.getDocInfos(),
                                        documents.getDocsCount(),
                                        0));

    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_commit(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_close_file(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_free_db(db));
    db = nullptr;
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_open_db(filePath.c_str(), 0, &db));

    // Scan for a to c, d0 is not in this range
    std::string start = "a";
    std::string end = "c";
    EXPECT_GT(documents.getKey(0), start);
    EXPECT_GT(documents.getKey(0), end);

    std::vector<sized_buf> ranges;
    ranges.emplace_back(sized_buf{start.data(), start.size()});
    ranges.emplace_back(sized_buf{end.data(), end.size()});

    Documents expected0(0);

    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_docinfos_by_id(db,
                                        ranges.data(),
                                        ranges.size(),
                                        RANGES,
                                        &Documents::countCallback,
                                        &expected0));

    // Should be no callbacks, doc0 is not in our range
    EXPECT_EQ(0, expected0.getCallbacks());
}

class RangeScanTest : public CouchstoreBaseTest,
                      public ::testing::WithParamInterface<int> {
public:
    void SetUp() override {
        documents.generateLexicographicalSequence();
        // store all of the documents
        ASSERT_EQ(COUCHSTORE_SUCCESS,
                  couchstore_open_db(
                          filePath.c_str(), COUCHSTORE_OPEN_FLAG_CREATE, &db));
        ASSERT_EQ(COUCHSTORE_SUCCESS,
                  couchstore_save_documents(db,
                                            documents.getDocs(),
                                            documents.getDocInfos(),
                                            documents.getDocsCount(),
                                            0));

        ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_commit(db));
    }
    Documents documents{GetParam()};
};

TEST_P(RangeScanTest, scan_all) {
    auto start = documents.getKey(0);
    std::string end = "\xFF";

    std::array<sized_buf, 2> ids;
    ids[0] = sized_buf{
            const_cast<char*>(reinterpret_cast<const char*>(start.data())),
            start.size()};
    ids[1] = sized_buf{
            const_cast<char*>(reinterpret_cast<const char*>(end.data())),
            end.size()};

    documents.setRange(start, end);
    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_docinfos_by_id(db,
                                        ids.data(),
                                        ids.size(),
                                        RANGES,
                                        &Documents::inRangeAndCountCallback,
                                        &documents));
    EXPECT_EQ(GetParam(), documents.getCallbacks());
}

TEST_P(RangeScanTest, scan_upper_half) {
    // start from index 2 for size 4 etc... for odd inputs adjust by 1
    size_t in = (GetParam() / 2) + (GetParam() & 1);
    auto start = documents.getKey(in);
    // end at max of all keys
    std::string end = "\xFF";

    std::array<sized_buf, 2> ids;
    ids[0] = sized_buf{
            const_cast<char*>(reinterpret_cast<const char*>(start.data())),
            start.size()};
    ids[1] = sized_buf{
            const_cast<char*>(reinterpret_cast<const char*>(end.data())),
            end.size()};

    documents.setRange(start, end);
    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_docinfos_by_id(db,
                                        ids.data(),
                                        ids.size(),
                                        RANGES,
                                        &Documents::inRangeAndCountCallback,
                                        &documents));

    EXPECT_EQ(GetParam() / 2, documents.getCallbacks());
}

TEST_P(RangeScanTest, scan_lower_half) {
    auto end = documents.getKey((GetParam() / 2) - 1);
    auto start = documents.getKey(0);

    std::array<sized_buf, 2> ids;
    ids[0] = sized_buf{
            const_cast<char*>(reinterpret_cast<const char*>(start.data())),
            start.size()};
    ids[1] = sized_buf{
            const_cast<char*>(reinterpret_cast<const char*>(end.data())),
            end.size()};

    documents.setRange(start, end);
    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_docinfos_by_id(db,
                                        ids.data(),
                                        ids.size(),
                                        RANGES,
                                        &Documents::inRangeAndCountCallback,
                                        &documents));
    EXPECT_EQ(GetParam() / 2, documents.getCallbacks());
}

// Test fixture for the add or replace callback exposed by save_docs
class SaveCallbackTest : public CouchstoreTest {
public:
    SaveCallbackTest() {
    }

    void SetUp() override {
        ASSERT_TRUE(open());
    }

    ::testing::AssertionResult open() {
        auto status = couchstore_open_db(
                filePath.c_str(), COUCHSTORE_OPEN_FLAG_CREATE, &db);
        if (status != COUCHSTORE_SUCCESS) {
            return ::testing::AssertionFailure()
                   << "couchstore_open_db failed status:" << status;
        }
        return ::testing::AssertionSuccess();
    }

    ::testing::AssertionResult close() {
        auto status = couchstore_close_file(db);
        if (status != COUCHSTORE_SUCCESS) {
            return ::testing::AssertionFailure()
                   << "couchstore_close_file failed status:" << status;
        }
        status = couchstore_free_db(db);
        if (status != COUCHSTORE_SUCCESS) {
            return ::testing::AssertionFailure()
                   << "couchstore_free_db failed status:" << status;
        }
        db = nullptr;
        return ::testing::AssertionSuccess();
    }

    ::testing::AssertionResult reopen() {
        if (db) {
            auto status = close();
            if (status != ::testing::AssertionSuccess()) {
                return status;
            }
        }
        return open();
    }

    ::testing::AssertionResult save(Documents& documents,
                                    couchstore_save_options options = 0) {
        auto status =
                couchstore_save_documents_and_callback(db,
                                                       documents.getDocs(),
                                                       documents.getDocInfos(),
                                                       documents.getUserReqs(),
                                                       documents.getDocsCount(),
                                                       options,
                                                       &update_callback,
                                                       this);

        if (status != COUCHSTORE_SUCCESS) {
            return ::testing::AssertionFailure()
                   << "couchstore_save_documents_and_callback failed status:"
                   << status;
        }
        return ::testing::AssertionSuccess();
    }

    ::testing::AssertionResult checkAddedSeqnos(Documents& documents) {
        for (int ii = 0; ii < documents.getDocsCount(); ii++) {
            auto* info = documents.getDocInfo(ii);
            if (addedKeys.count({info->id.buf, info->id.size}) == 0) {
                return ::testing::AssertionFailure()
                       << "Cannot find "
                       << std::string(info->id.buf, info->id.size);
            }
            if (info->db_seq != addedKeys[{info->id.buf, info->id.size}]) {
                return ::testing::AssertionFailure()
                       << "seqno mismatch for index:" << ii << " "
                       << info->db_seq
                       << " != " << addedKeys[{info->id.buf, info->id.size}];
            }
        }
        return ::testing::AssertionSuccess();
    }

    static void update_callback(const DocInfo* oldInfo,
                                const DocInfo* newInfo,
                                void* ctx,
                                void* userReq) {
        SaveCallbackTest* addedAndReplaced =
                reinterpret_cast<SaveCallbackTest*>(ctx);
        ASSERT_NE(nullptr, newInfo);
        if (oldInfo) {
            EXPECT_GT(newInfo->db_seq, oldInfo->db_seq);
            addedAndReplaced
                    ->replacedKeys[{newInfo->id.buf, newInfo->id.size}] =
                    newInfo->db_seq;
        } else {
            addedAndReplaced->addedKeys[{newInfo->id.buf, newInfo->id.size}] =
                newInfo->db_seq;
        }
    }

protected:
    std::unordered_map<std::string, uint64_t> addedKeys;
    std::unordered_map<std::string, uint64_t> replacedKeys;
};

TEST_F(SaveCallbackTest, basic) {
    DbInfo info;

    const uint32_t docsInTest = 4;
    Documents documents(docsInTest);
    documents.setDoc(0, "doc1", "{\"test_doc_index\":1}");
    documents.setDoc(1, "doc2", "{\"test_doc_index\":2}");
    documents.setDoc(2, "doc3", "{\"test_doc_index\":3}");
    documents.setDoc(3, "doc4", "{\"test_doc_index\":4}");

    ASSERT_TRUE(save(documents));

    EXPECT_EQ(4, addedKeys.size());
    EXPECT_TRUE(checkAddedSeqnos(documents));

    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_commit(db));

    ASSERT_TRUE(reopen());

    ASSERT_TRUE(save(documents));

    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_commit(db));

    EXPECT_EQ(4, replacedKeys.size());

    /* Check that sequence numbers got filled in */
    for (uint64_t ii = 0; ii < docsInTest; ++ii) {
        EXPECT_EQ(docsInTest + ii + 1, documents.getDocInfo(ii)->db_seq);
    }

    ASSERT_TRUE(reopen());

    /* Read back */
    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_changes_since(
                      db, 0, 0, &Documents::checkCallback, &documents));

    EXPECT_EQ(docsInTest, uint32_t(documents.getCallbacks()));
    EXPECT_EQ(0, documents.getDeleted());

    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_db_info(db, &info));

    EXPECT_EQ(docsInTest * 2, info.last_sequence);
    EXPECT_EQ(docsInTest, info.doc_count);
    EXPECT_EQ(0ul, info.deleted_count);
    EXPECT_EQ(8192ll, info.header_position);
}

TEST_F(SaveCallbackTest, basic2) {
    const uint32_t docsInTest = 4;
    Documents documents1(docsInTest);
    documents1.setDoc(0, "doc1", "{\"test_doc_index\":1}");
    documents1.setDoc(1, "doc2", "{\"test_doc_index\":2}");
    documents1.setDoc(2, "doc3", "{\"test_doc_index\":3}");
    documents1.setDoc(3, "doc4", "{\"test_doc_index\":4}");

    // the internal callback is at different > or < compare points, so pass keys
    // =, > and < than what's in the file
    Documents documents2(docsInTest);
    documents2.setDoc(0, "doc1", "{\"test_doc_index\":1}"); // == doc1
    documents2.setDoc(1, "adoc2", "{\"test_doc_index\":2}"); // < doc*
    documents2.setDoc(2, "edoc3", "{\"test_doc_index\":3}"); // > doc*
    documents2.setDoc(3, "bdoc4", "{\"test_doc_index\":4}"); // < doc*

    ASSERT_TRUE(save(documents1));

    EXPECT_EQ(docsInTest, addedKeys.size());

    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_commit(db));

    ASSERT_TRUE(reopen());

    ASSERT_TRUE(save(documents2));

    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_commit(db));

    EXPECT_EQ(7, addedKeys.size());
    EXPECT_EQ(1, replacedKeys.size());
}

TEST_F(SaveCallbackTest, basic_seqno) {
    const uint32_t docsInTest = 4;
    Documents documents(docsInTest);
    for (uint32_t ii = 0; ii < docsInTest; ii++) {
        documents.setDoc(ii, "doc" + std::to_string(ii), "value");
        documents.getDocInfo(ii)->db_seq = ii * 20;
    }

    // Save and preserve seqnos
    ASSERT_TRUE(save(documents, COUCHSTORE_SEQUENCE_AS_IS));
    EXPECT_EQ(docsInTest, addedKeys.size());
    EXPECT_TRUE(checkAddedSeqnos(documents));
    EXPECT_EQ(0, replacedKeys.size());
}

// Add two "blocks" of documents that have no overlap, we should see only adds
TEST_F(SaveCallbackTest, large1) {
    const uint32_t docsInTest = 2000;
    Documents documents1(docsInTest);
    documents1.generateDocs();
    Documents documents2(docsInTest);
    documents2.generateDocs("others");

    ASSERT_TRUE(save(documents1));

    EXPECT_EQ(docsInTest, addedKeys.size());
    EXPECT_TRUE(checkAddedSeqnos(documents1));

    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_commit(db));

    ASSERT_TRUE(reopen());

    ASSERT_TRUE(save(documents2));

    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_commit(db));

    EXPECT_EQ(docsInTest * 2, addedKeys.size());
    EXPECT_EQ(0, replacedKeys.size());
}

// Add two blocks of documents with 100% overlap, so we expect adds and replaces
TEST_F(SaveCallbackTest, large2) {
    const uint32_t docsInTest = 2000;
    Documents documents1(docsInTest);
    documents1.generateRandomDocs(2, {}, {});

    ASSERT_TRUE(save(documents1));

    EXPECT_EQ(docsInTest, addedKeys.size());
    EXPECT_TRUE(checkAddedSeqnos(documents1));

    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_commit(db));

    ASSERT_TRUE(reopen());

    // Change the insert order
    documents1.shuffle();

    ASSERT_TRUE(save(documents1));

    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_commit(db));

    EXPECT_EQ(docsInTest, replacedKeys.size());
}

// Add two "blocks" of documents that have no overlap, we should see only adds
// But use the generateRandomDocs to help hit many of the >,< and = code paths
TEST_F(SaveCallbackTest, large3) {
    const uint32_t docsInTest = 5000;
    Documents documents1(docsInTest);
    documents1.generateRandomDocs(1, {}, "d1");

    // Generate a new random space of keys which with the suffix, won't clash
    Documents documents2(docsInTest);
    documents2.generateRandomDocs(2, {}, "d2");

    ASSERT_TRUE(save(documents1));

    EXPECT_EQ(docsInTest, addedKeys.size());
    EXPECT_TRUE(checkAddedSeqnos(documents1));

    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_commit(db));

    ASSERT_TRUE(reopen());

    ASSERT_TRUE(save(documents2));

    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_commit(db));

    EXPECT_EQ(docsInTest * 2, addedKeys.size());
    EXPECT_EQ(0, replacedKeys.size());
}

#ifndef WIN32
TEST_F(CouchstoreBaseTest, mprotect) {
    DbInfo info;

    const uint32_t docsInTest = 4;
    Documents documents(docsInTest);
    documents.setDoc(0, "doc1", "{\"test_doc_index\":1}");
    documents.setDoc(1, "doc2", "{\"test_doc_index\":2}");
    documents.setDoc(2, "doc3", "{\"test_doc_index\":3}");
    documents.setDoc(3, "doc4", "{\"test_doc_index\":4}");

    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_open_db(filePath.c_str(),
                                 COUCHSTORE_OPEN_FLAG_CREATE |
                                         COUCHSTORE_OPEN_WITH_MPROTECT,
                                 &db));

    for (uint32_t ii = 0; ii < docsInTest; ii++) {
        ASSERT_EQ(
                COUCHSTORE_SUCCESS,
                couchstore_save_document(
                        db, documents.getDoc(ii), documents.getDocInfo(ii), 0));
    }

    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_commit(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_close_file(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_free_db(db));
    db = nullptr;

    /* Check that sequence numbers got filled in */
    for (uint64_t ii = 0; ii < docsInTest; ++ii) {
        EXPECT_EQ(ii + 1, documents.getDocInfo(ii)->db_seq);
    }

    /* Read back */
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_open_db(filePath.c_str(), 0, &db));
    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_changes_since(
                      db, 0, 0, &Documents::checkCallback, &documents));

    EXPECT_EQ(docsInTest, uint32_t(documents.getCallbacks()));
    EXPECT_EQ(0, documents.getDeleted());

    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_db_info(db, &info));

    EXPECT_EQ(docsInTest, info.last_sequence);
    EXPECT_EQ(docsInTest, info.doc_count);
    EXPECT_EQ(0ul, info.deleted_count);
    EXPECT_EQ(4096ll, info.header_position);
}
#endif /* WIN32 */

INSTANTIATE_TEST_SUITE_P(
        DocTest,
        CouchstoreDocTest,
        ::testing::Combine(::testing::Bool(),
                           ::testing::Values(4, 69, 666, 4090),
                           ::testing::Bool()),
        [](const ::testing::TestParamInfo<std::tuple<bool, int, bool>>&
                   testInfo) {
            std::stringstream fmt;
            fmt << (std::get<0>(testInfo.param) ? "Small" : "Large") << 'x'
                << std::get<1>(testInfo.param)
                << (std::get<2>(testInfo.param) ? "Encrypted"
                                                : "Unencrypted");
            return fmt.str();
        });

INSTANTIATE_TEST_SUITE_P(
        CouchstoreTest,
        CouchstoreTest,
        ::testing::Bool(),
        [](const ::testing::TestParamInfo<bool>& testInfo) -> std::string {
            return testInfo.param ? "Encrypted" : "Unencrypted";
        });

INSTANTIATE_TEST_SUITE_P(RangeScanTest,
                         RangeScanTest,
                         ::testing::Values(4, 69, 666),
                         [](const ::testing::TestParamInfo<int>& testInfo) {
                             std::stringstream fmt;
                             fmt << "x" << testInfo.param;
                             return fmt.str();
                         });

INSTANTIATE_TEST_SUITE_P(
        MTLatencyCollectTest,
        CouchstoreMTTest,
        ::testing::Combine(::testing::Values(true, false),
                           ::testing::Values(8)),
        [](const ::testing::TestParamInfo<std::tuple<bool, size_t>>& testInfo) {
            std::stringstream fmt;
            fmt << "collector_"
                << ((std::get<0>(testInfo.param)) ? "enabled" : "disabled")
                << "_" << std::get<1>(testInfo.param);
            return fmt.str();
        });

int main(int argc, char ** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
