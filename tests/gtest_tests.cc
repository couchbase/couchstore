/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

//#include "config.h"



#include "bitfield.h"
#include "couchstoretest.h"
#include "couchstoredoctest.h"
#include "documents.h"
#include "internal.h"
#include "node_types.h"
#include "reduces.h"

#include <gtest/gtest.h>
#include <libcouchstore/couch_db.h>

#include <cstdint>
#include <limits>
#include <random>
#include <thread>

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

TEST_F(CouchstoreTest, bitfield_fns)
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

TEST_P(CouchstoreDoctest, save_docs)
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

TEST_F(CouchstoreTest, save_doc)
{
    DbInfo info;

    const uint32_t docsInTest = 4;
    Documents documents(docsInTest);
    documents.setDoc(0, "doc1", "{\"test_doc_index\":1}");
    documents.setDoc(1, "doc2", "{\"test_doc_index\":2}");
    documents.setDoc(2, "doc3", "{\"test_doc_index\":3}");
    documents.setDoc(3, "doc4", "{\"test_doc_index\":4}");

    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_open_db(filePath.c_str(), COUCHSTORE_OPEN_FLAG_CREATE, &db));

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
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_open_db(filePath.c_str(), 0, &db));
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
    EXPECT_EQ(4096ll, info.header_position);
}

TEST_F(CouchstoreTest, compressed_doc_body)
{
    Documents documents(2);
    documents.setDoc(0, "doc1", "{\"test_doc_index\":1, \"val\":\"blah blah blah blah blah blah\"}");
    documents.setDoc(1, "doc2", "{\"test_doc_index\":2, \"val\":\"blah blah blah blah blah blah\"}");
    documents.setContentMeta(1, COUCH_DOC_IS_COMPRESSED);/* Mark doc2 as to be snappied. */

    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_open_db(filePath.c_str(), COUCHSTORE_OPEN_FLAG_CREATE, &db));
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
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_open_db(filePath.c_str(), 0, &db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_changes_since(db, 0, 0, &Documents::checkCallback, &documents));
    EXPECT_EQ(2, documents.getCallbacks());
    EXPECT_EQ(0, documents.getDeleted());
}

TEST_F(CouchstoreTest, dump_empty_db)
{
    DbInfo info;
    Documents documents(0);

    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_open_db(filePath.c_str(), COUCHSTORE_OPEN_FLAG_CREATE, &db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_close_file(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_free_db(db));
    db = nullptr;

    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_open_db(filePath.c_str(), 0, &db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_changes_since(db, 0, 0, &Documents::countCallback, &documents));
    EXPECT_EQ(0, documents.getCallbacks());
    EXPECT_EQ(0, documents.getDeleted());
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_db_info(db, &info));

    EXPECT_STREQ(filePath.c_str(), info.filename);
    EXPECT_EQ(0ull, info.last_sequence);
    EXPECT_EQ(0ull, info.doc_count);
    EXPECT_EQ(0ull, info.deleted_count);
    EXPECT_EQ(0ull, info.space_used);
    EXPECT_EQ(0ll, info.header_position);
}

TEST_F(CouchstoreTest, local_docs)
{
    LocalDoc lDocWrite;
    LocalDoc *lDocRead = NULL;

    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_open_db(filePath.c_str(), COUCHSTORE_OPEN_FLAG_CREATE, &db));
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
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_open_db(filePath.c_str(), 0, &db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_open_local_document(db, "_local/testlocal", 16, &lDocRead));
    ASSERT_NE(nullptr, lDocRead);
    EXPECT_EQ(13ull, lDocRead->json.size);

    EXPECT_EQ(0, memcmp(lDocRead->json.buf, "{\"test\":true}", 13));
    couchstore_free_local_document(lDocRead);
}

TEST_F(CouchstoreTest, open_file_error)
{

    int errcode;
    errcode = couchstore_open_db(filePath.c_str(), 0, &db);

    EXPECT_EQ(errcode, COUCHSTORE_ERROR_NO_SUCH_FILE);

    /* make sure os.c didn't accidentally call close(0): */
#ifndef WIN32
    EXPECT_TRUE(lseek(0, 0, SEEK_CUR) >= 0 || errno != EBADF);
#endif
}

TEST_F(CouchstoreTest, changes_no_dups)
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

    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_open_db(filePath.c_str(), COUCHSTORE_OPEN_FLAG_CREATE, &db));
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

    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_open_db(filePath.c_str(), 0, &db));

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

TEST_F(CouchstoreTest, mb5086)
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

TEST_F(CouchstoreTest, mb11104)
{
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

    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_open_db(filePath.c_str(), COUCHSTORE_OPEN_FLAG_CREATE, &db));
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
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_open_db(filePath.c_str(), 0, &db));

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
    EXPECT_EQ(4096ll, info.header_position);
}

TEST_F(CouchstoreTest, asis_seqs)
{
    DocInfo *ir = nullptr;

    Documents documents(3);
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_open_db(filePath.c_str(), COUCHSTORE_OPEN_FLAG_CREATE, &db));
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

TEST_F(CouchstoreTest, huge_revseq)
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
TEST_F(CouchstoreTest, crc32c) {
    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_open_db(filePath.c_str(),
                                 COUCHSTORE_OPEN_FLAG_CREATE,
                                 &db));
    EXPECT_EQ(CRC32C, db->file.crc_mode);
}

// Create a new-file(s) and test that we can't open again with old CRC
TEST_F(CouchstoreTest, legacy_crc_flags) {
    // Open the new/clean file and ask for 'legacy-CRC'
    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_open_db(filePath.c_str(),
                                 COUCHSTORE_OPEN_FLAG_CREATE |
                                 COUCHSTORE_OPEN_WITH_LEGACY_CRC,
                                 &db));

    EXPECT_EQ(CRC32, db->file.crc_mode);

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

    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_close_file(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_free_db(db));
    db = nullptr;

    // Open the now existing file and we should be allowed, legacy crc will be auto-selected
    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_open_db(filePath.c_str(),
                                 COUCHSTORE_OPEN_FLAG_CREATE,
                                 &db));

    EXPECT_EQ(CRC32, db->file.crc_mode);

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
    EXPECT_GE(uint64_t(COUCH_DISK_VERSION_12), db->header.disk_version);

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
TEST_F(CouchstoreTest, no_crc_upgrade) {

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
TEST_F(CouchstoreTest, crc_upgrade) {
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
TEST_F(CouchstoreTest, crc_upgrade2) {
    const size_t docCount = 100;
    Documents documents(docCount);
    documents.generateDocs();

    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_open_db(filePath.c_str(),
                                 COUCHSTORE_OPEN_FLAG_CREATE,
                                 &db));
    EXPECT_EQ(CRC32C, db->file.crc_mode);
    // new file must be version 11 or less
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
                     Histogram<CouchLatencyMicroSec> *latencies,
                     const CouchLatencyMicroSec elapsed_time,
                     void *ctx) {
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
TEST_F(CouchstoreTest, mb23697) {
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
TEST_F(CouchstoreTest, compact_need_body) {
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
TEST_F(CouchstoreTest, test_changes_count) {
    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_open_db(
                      filePath.c_str(), COUCHSTORE_OPEN_FLAG_CREATE, &db));

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
    ASSERT_EQ(
            COUCHSTORE_SUCCESS,
            couchstore_save_documents(db, NULL, documents.getDocInfos(), 2, 0));
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
TEST_F(CouchstoreTest, test_set_purge_seq) {
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

#ifndef WIN32
TEST_F(CouchstoreTest, mprotect) {
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

INSTANTIATE_TEST_CASE_P(DocTest,
                        CouchstoreDoctest,
                        ::testing::Combine(::testing::Bool(), ::testing::Values(4, 69, 666, 4090)),
                        [] (const ::testing::TestParamInfo<std::tuple<bool, int>>& info) {
                            std::stringstream fmt;
                            fmt << ((std::get<0>(info.param))?"Small":"Large")
                                << "x" << std::get<1>(info.param);
                            return fmt.str();
                        });



INSTANTIATE_TEST_CASE_P(
        MTLatencyCollectTest,
        CouchstoreMTTest,
        ::testing::Combine(::testing::Values(true, false),
                           ::testing::Values(8)),
        [] (const ::testing::TestParamInfo<std::tuple<bool, size_t>>& info) {
            std::stringstream fmt;
            fmt << "collector_"
                << ((std::get<0>(info.param))?"enabled":"disabled")
                << "_" << std::get<1>(info.param);
            return fmt.str();
        });


int main(int argc, char ** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
