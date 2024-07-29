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

/*
 * This test file is for GTest tests which test the internal API.
 *
 * This is in contrast to gtest_tests.cc which runs tests using
 * just the external API.
 */

#include <folly/portability/GTest.h>

#include "couchstoretest.h"
#include "documents.h"

#include <libcouchstore/couch_db.h>
#include <platform/dirutils.h>

/**
 * Note: below internal Couchstore header files should be located
 *       at the end of all above includes. Otherwise it causes
 *       compilation failure (in file_ops.h) on Windows.
 */
#include "src/couch_btree.h"
#include "src/internal.h"
#include "src/tree_writer.h"

using namespace testing;

/** corrupt_header Corrupt the trailing header to make sure we go back
 * to a good header.
 */
TEST_F(CouchstoreInternalTest, corrupt_header) {
    couchstore_error_info_t errinfo;
    DocInfo* out_info;
    cs_off_t pos;
    ssize_t written;

    /* create database and load 1 doc */
    ASSERT_EQ(COUCHSTORE_SUCCESS, open_db(COUCHSTORE_OPEN_FLAG_CREATE));
    Documents documents(1);
    documents.setDoc(0, "doc1", "oops");
    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_save_documents(
                      db, documents.getDocs(), documents.getDocInfos(), 1, 0));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_commit(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_close_file(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_free_db(db));
    db = nullptr;

    /* make sure the doc is loaded */
    ASSERT_EQ(COUCHSTORE_SUCCESS, open_db(0));
    EXPECT_EQ(COUCHSTORE_SUCCESS,
              couchstore_docinfo_by_id(db,
                                       documents.getDoc(0)->id.buf,
                                       documents.getDoc(0)->id.size,
                                       &out_info));
    Documents::checkCallback(db, out_info, &documents);
    couchstore_free_docinfo(out_info);
    out_info = nullptr;

    /* update the doc */
    documents.resetCounters();
    documents.setDoc(0, "doc1", "yikes");
    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_save_documents(
                      db, documents.getDocs(), documents.getDocInfos(), 1, 0));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_commit(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_close_file(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_free_db(db));
    db = nullptr;

    /* verify the doc changed */
    ASSERT_EQ(COUCHSTORE_SUCCESS, open_db(0));
    EXPECT_EQ(COUCHSTORE_SUCCESS,
              couchstore_docinfo_by_id(db,
                                       documents.getDoc(0)->id.buf,
                                       documents.getDoc(0)->id.size,
                                       &out_info));
    Documents::checkCallback(db, out_info, &documents);
    couchstore_free_docinfo(out_info);
    out_info = nullptr;

    /* corrupt the header block */
    pos = db->file.ops->goto_eof(&errinfo, db->file.handle);
    written = db->file.ops->pwrite(
            &errinfo, db->file.handle, "deadbeef", 8, pos - 8);
    ASSERT_EQ(written, 8);
    ASSERT_EQ(COUCHSTORE_SUCCESS,
              db->file.ops->sync(&db->file.lastError, db->file.handle));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_close_file(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_free_db(db));
    db = nullptr;

    /* verify that the last version was invalidated and we went back to
     * the 1st version
     */
    ASSERT_EQ(COUCHSTORE_SUCCESS, open_db(0));
    documents.resetCounters();
    documents.setDoc(0, "doc1", "oops");
    EXPECT_EQ(COUCHSTORE_SUCCESS,
              couchstore_docinfo_by_id(db,
                                       documents.getDoc(0)->id.buf,
                                       documents.getDoc(0)->id.size,
                                       &out_info));
    Documents::checkCallback(db, out_info, &documents);
    couchstore_free_docinfo(out_info);
    out_info = nullptr;

    clean_up();
}

/**
 * The commit alignment test checks that the file size following
 * these situations are all the same:
 *
 * - Precommit
 * - Write Header
 * - Commit (= Precommit followed by a Write Header)
 *
 * This is done to verify that the precommit has extended the
 * file long enough to encompass the subsequently written header
 * (which avoids a metadata flush when we sync).
 */
TEST_F(CouchstoreInternalTest, commit_alignment) {
    couchstore_error_info_t errinfo;

    open_db_and_populate(COUCHSTORE_OPEN_FLAG_CREATE, 100);

    EXPECT_EQ(COUCHSTORE_SUCCESS, precommit(db));
    cs_off_t precommit_size = db->file.ops->goto_eof(&errinfo, db->file.handle);

    clean_up();

    /* Get the size from actually writing a header without a precommit */
    open_db_and_populate(COUCHSTORE_OPEN_FLAG_CREATE, 100);

    ASSERT_EQ(COUCHSTORE_SUCCESS, db_write_header(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, db->file.ops->sync(&db->file.lastError, db->file.handle));

    /* Compare */
    EXPECT_EQ(precommit_size,
              db->file.ops->goto_eof(&errinfo, db->file.handle));

    clean_up();

    /* Get the size from actually doing a full commit */
    open_db_and_populate(COUCHSTORE_OPEN_FLAG_CREATE, 100);

    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_commit(db));
    /* Compare */
    EXPECT_EQ(precommit_size,
              db->file.ops->goto_eof(&errinfo, db->file.handle));
}

TEST_F(CouchstoreInternalTest, rewind_db_header) {
    open_db_and_populate(COUCHSTORE_OPEN_FLAG_CREATE, 200);
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_commit(db));
    const auto lastHeader = couchstore_get_header_position(db);
    EXPECT_GT(lastHeader, COUCH_BLOCK_SIZE * 2);

    EXPECT_EQ(COUCHSTORE_SUCCESS,
              cb::couchstore::seek(*db, cb::couchstore::Direction::End));
    EXPECT_EQ(lastHeader, couchstore_get_header_position(db));
    {
        auto [status, info] =
                cb::couchstore::openDocInfo(*db, documents.getKey(0));
        EXPECT_EQ(COUCHSTORE_SUCCESS, status);
    }
    {
        InSequence s;
        EXPECT_CALL(ops, pread(_, _, _, _, 0)).Times(1);
        EXPECT_CALL(ops, pread(_, _, _, _, 1)).Times(1);
        EXPECT_CALL(ops, pread(_, _, _, _, _)).Times(1);
        EXPECT_EQ(COUCHSTORE_SUCCESS, couchstore_rewind_db_header(db));
        EXPECT_EQ(0, couchstore_get_header_position(db));
    }
    {
        auto [status, info] =
                cb::couchstore::openDocInfo(*db, documents.getKey(0));
        EXPECT_EQ(COUCHSTORE_ERROR_DOC_NOT_FOUND, status);
    }
    {
        InSequence s;
        EXPECT_CALL(ops, pread(_, _, _, _, _)).Times(0);
        auto errcode = couchstore_rewind_db_header(db);
        if (errcode == COUCHSTORE_ERROR_DB_NO_LONGER_VALID) {
            db = nullptr;
        }
        EXPECT_EQ(COUCHSTORE_ERROR_DB_NO_LONGER_VALID, errcode);
    }
}

/**
 * Test to check whether or not buffered IO configurations passed to
 * open_db() API correctly set internal file options.
 */
TEST_F(CouchstoreInternalTest, buffered_io_options)
{
    const uint32_t docsInTest = 100;
    std::string key_str, value_str;
    Documents documents(docsInTest);
    documents.generateDocs();

    for (uint64_t flags = 0; flags <= 0xff; ++flags) {
        uint32_t exp_kp_nodesize = DB_KP_CHUNK_THRESHOLD;
        uint32_t exp_kv_nodesize = DB_KV_CHUNK_THRESHOLD;

        uint32_t kp_flag = (flags >> 4) & 0xf;
        if (kp_flag) {
            exp_kp_nodesize = kp_flag * 1024;
        }
        uint32_t kv_flag = flags & 0xf;
        if (kv_flag) {
            exp_kv_nodesize = kv_flag * 1024;
        }

        ASSERT_EQ(COUCHSTORE_SUCCESS,
                  couchstore_open_db(
                        filePath.c_str(),
                        (flags << 16) | COUCHSTORE_OPEN_FLAG_CREATE,
                        &db));

        ASSERT_EQ(exp_kp_nodesize, db->file.options.kp_nodesize);
        ASSERT_EQ(exp_kv_nodesize, db->file.options.kv_nodesize);

        for (uint32_t ii = 0; ii < docsInTest; ii++) {
             ASSERT_EQ(COUCHSTORE_SUCCESS,
                       couchstore_save_document(db,
                                                documents.getDoc(ii),
                                                documents.getDocInfo(ii),
                                                0));
        }
        ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_commit(db));

        { // Check if reading docs works correctly with given node settings.
            documents.resetCounters();
            std::vector<sized_buf> buf(docsInTest);
            for (uint32_t ii = 0; ii < docsInTest; ++ii) {
                buf[ii] = documents.getDoc(ii)->id;
            }
            SCOPED_TRACE("save_docs - doc by id (bulk)");
            ASSERT_EQ(COUCHSTORE_SUCCESS,
                      couchstore_docinfos_by_id(db,
                                                &buf[0],
                                                docsInTest,
                                                0,
                                                &Documents::docIterCheckCallback,
                                                &documents));
            EXPECT_EQ(static_cast<int>(docsInTest),
                      documents.getCallbacks());
            EXPECT_EQ(0, documents.getDeleted());
        }
        ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_close_file(db));
        ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_free_db(db));
        db = nullptr;

        remove(filePath.c_str());
    }
}

/* Test to verify pwrite returning less bytes than passed in
   is handled for buffered and unbuffered case.
   return 0 or write 1 byte at a time */
typedef ParameterisedFileOpsErrorInjectionTest PwriteReturnTest;
TEST_P(PwriteReturnTest, CheckLessPwriteReturn) {
    remove(filePath.c_str());

    const uint32_t docsInTest = 100;
    std::string key_str, value_str;
    Documents documents(docsInTest);
    bool buffered = GetParam();

    for (uint32_t ii = 0; ii < docsInTest; ii++) {
        key_str = "doc" + std::to_string(ii);
        value_str = "test_doc_body:" + std::to_string(ii);
        documents.setDoc(ii, key_str, value_str);
    }

    // open with the requested option
    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_open_db_ex(filePath.c_str(),
                                    buffered ? COUCHSTORE_OPEN_FLAG_CREATE:
                                    COUCHSTORE_OPEN_FLAG_CREATE | COUCHSTORE_OPEN_FLAG_UNBUFFERED,
                                    {}, &ops, &db));

    // make pwrite return 0 some times and write 1 byte other times
    EXPECT_CALL(ops, pwrite(_, _, _, _, _)).WillRepeatedly(Invoke(
         [this](couchstore_error_info_t* errinfo, couch_file_handle handle,
                const void* buf, size_t nbytes, cs_off_t offset) {
             static int x=0;

             if (x++ % 5 == 0)
                 return 0;
             return (int)ops.get_wrapped()->pwrite(errinfo, handle, buf, 1, offset);
          }));

    // add a doc and commit to trigger pwrite more times
    for (uint32_t ii = 0; ii < docsInTest; ii++) {
        ASSERT_EQ(COUCHSTORE_SUCCESS,
                  couchstore_save_document(db,
                                           documents.getDoc(ii),
                                           documents.getDocInfo(ii),
                                           0));
        ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_commit(db));
    }
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_close_file(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_free_db(db));

    // Check docs.
    ASSERT_EQ(COUCHSTORE_SUCCESS, open_db(COUCHSTORE_OPEN_FLAG_CREATE));
    documents.resetCounters();
    std::vector<sized_buf> buf(docsInTest);
    for (uint32_t ii = 0; ii < docsInTest; ++ii) {
        buf[ii] = documents.getDoc(ii)->id;
    }
    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_docinfos_by_id(db,
                                        &buf[0],
                                        docsInTest,
                                        0,
                                        &Documents::docIterCheckCallback,
                                        &documents));
    EXPECT_EQ(static_cast<int>(docsInTest),
              documents.getCallbacks());
}

INSTANTIATE_TEST_SUITE_P(Parameterised, PwriteReturnTest,
                       ::testing::Values(true, false),
                       ::testing::PrintToStringParamName());
/**
 * Test to check whether or not custom B+tree node size passed to
 * open_db() API correctly set internal file options.
 */
TEST_F(CouchstoreInternalTest, custom_btree_node_size)
{
    const uint32_t docsInTest = 100;
    std::string key_str, value_str;
    Documents documents(docsInTest);
    for (uint32_t ii = 0; ii < docsInTest; ii++) {
        key_str = "doc" + std::to_string(ii);
        value_str = "{\"test_doc_index\":" + std::to_string(ii) + "}";
        documents.setDoc(ii, key_str, value_str);
    }

    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_open_db(filePath.c_str(),
                                 COUCHSTORE_OPEN_FLAG_CREATE, &db));

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

    for (uint64_t flags = 0; flags <= 0xff; ++flags) {
        uint32_t exp_unit_size = READ_BUFFER_CAPACITY;
        uint32_t exp_buffers = MAX_READ_BUFFERS;

        uint32_t unit_index = (flags >> 4) & 0xf;
        if (unit_index) {
            // unit_index    1     2     3     4     ...   15
            // unit size     1KB   2KB   4KB   8KB   ...   16MB
            exp_unit_size = 1024 * (1 << (unit_index -1));
        }
        uint32_t count_index = flags & 0xf;
        if (count_index) {
            // count_index   1     2     3     4     ...   15
            // # buffers     8     16    32    64    ...   128K
            exp_buffers = 8 * (1 << (count_index-1));
        }

        ASSERT_EQ(COUCHSTORE_SUCCESS,
                  couchstore_open_db(filePath.c_str(), flags << 8, &db));

        ASSERT_EQ(exp_buffers, db->file.options.buf_io_read_buffers);
        ASSERT_EQ(exp_unit_size, db->file.options.buf_io_read_unit_size);

        { // Check if reading docs works correctly with given buffer settings.
            documents.resetCounters();
            std::vector<sized_buf> buf(docsInTest);
            for (uint32_t ii = 0; ii < docsInTest; ++ii) {
                buf[ii] = documents.getDoc(ii)->id;
            }
            SCOPED_TRACE("save_docs - doc by id (bulk)");
            ASSERT_EQ(COUCHSTORE_SUCCESS,
                      couchstore_docinfos_by_id(db,
                                                &buf[0],
                                                docsInTest,
                                                0,
                                                &Documents::docIterCheckCallback,
                                                &documents));
            EXPECT_EQ(static_cast<int>(docsInTest),
                      documents.getCallbacks());
            EXPECT_EQ(0, documents.getDeleted());
        }

        ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_close_file(db));
        ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_free_db(db));
        db = nullptr;
    }
}

struct corrupted_btree_node_cb_param {
    void reset() {
        last_doc_bp = 0;
        num_called = 0;
    }

    uint64_t last_doc_bp{0};
    size_t num_called{0};
};

int corrupted_btree_node_cb(Db *db, DocInfo *info, void *ctx) {
    corrupted_btree_node_cb_param* param =
            reinterpret_cast<corrupted_btree_node_cb_param*>(ctx);
    if (param->last_doc_bp < info->bp) {
        param->last_doc_bp = info->bp;
    }
    param->num_called++;
    return 0;
}

/**
 * Test to check whether or not B+tree corrupted node is well tolerated.
 */
TEST_F(CouchstoreInternalTest, corrupted_btree_node)
{
    remove(filePath.c_str());

    const uint32_t docsInTest = 100;
    std::string key_str, value_str;
    Documents documents(docsInTest);

    for (uint32_t ii = 0; ii < docsInTest; ii++) {
        key_str = "doc" + std::to_string(ii);
        value_str = "test_doc_body:" + std::to_string(ii);
        documents.setDoc(ii, key_str, value_str);
    }

    // Save docs.
    ASSERT_EQ(COUCHSTORE_SUCCESS, open_db(COUCHSTORE_OPEN_FLAG_CREATE));
    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_save_documents(db, documents.getDocs(),
                                        documents.getDocInfos(),
                                        docsInTest, 0));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_commit(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_close_file(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_free_db(db));

    // Check docs.
    ASSERT_EQ(COUCHSTORE_SUCCESS, open_db(COUCHSTORE_OPEN_FLAG_CREATE));
    documents.resetCounters();
    std::vector<sized_buf> buf(docsInTest);
    for (uint32_t ii = 0; ii < docsInTest; ++ii) {
        buf[ii] = documents.getDoc(ii)->id;
    }
    corrupted_btree_node_cb_param param;
    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_docinfos_by_id(db,
                                        &buf[0],
                                        docsInTest,
                                        0,
                                        corrupted_btree_node_cb,
                                        &param));
    ASSERT_EQ(docsInTest, param.num_called);

    couchstore_error_info_t errinfo;
    // Inject corruption into one of B+tree nodes
    // (located at right next to the last doc).
    db->file.ops->pwrite(&errinfo, db->file.handle,
                         "corruption", 10, param.last_doc_bp+32);

    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_close_file(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_free_db(db));

    ASSERT_EQ(COUCHSTORE_SUCCESS, open_db(COUCHSTORE_OPEN_FLAG_CREATE));
    param.reset();
    // Should fail.
    ASSERT_NE(COUCHSTORE_SUCCESS,
              couchstore_docinfos_by_id(db,
                                        &buf[0],
                                        docsInTest,
                                        0,
                                        corrupted_btree_node_cb,
                                        &param));
    // Without TOLERATE flag: should not retrieve any docs.
    ASSERT_EQ(static_cast<size_t>(0), param.num_called);

    param.reset();
    // Should fail.
    ASSERT_NE(COUCHSTORE_SUCCESS,
              couchstore_docinfos_by_id(db,
                                        &buf[0],
                                        docsInTest,
                                        COUCHSTORE_TOLERATE_CORRUPTION,
                                        corrupted_btree_node_cb,
                                        &param));

    // With TOLERATE flag: should retrieve some docs,
    // the number should be: '0 < # docs < docsInTest'.
    ASSERT_LT(static_cast<size_t>(0), param.num_called);
    ASSERT_GT(docsInTest, param.num_called);

    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_close_file(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_free_db(db));

    db = nullptr;
}

/**
 * Test for couch_dbck tool.
 */
TEST_F(CouchstoreInternalTest, couch_dbck)
{
    remove(filePath.c_str());

    const uint32_t docsInTest = 100;
    std::string key_str, value_str;
    Documents documents(docsInTest);

    ASSERT_EQ(COUCHSTORE_SUCCESS, open_db(COUCHSTORE_OPEN_FLAG_CREATE));

    // Save docs (1st commit).
    for (uint32_t ii = 0; ii < docsInTest; ii++) {
        key_str = "doc" + std::to_string(ii);
        value_str = "test_doc_body:" + std::to_string(ii);
        documents.setDoc(ii, key_str, value_str);
    }

    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_save_documents(db, documents.getDocs(),
                                        documents.getDocInfos(),
                                        docsInTest, 0));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_commit(db));

    // Save docs (2nd commit).
    for (uint32_t ii = 0; ii < docsInTest; ii++) {
        key_str = "doc" + std::to_string(ii);
        value_str = "test_doc_body_ver2:" + std::to_string(ii);
        documents.setDoc(ii, key_str, value_str);
    }

    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_save_documents(db, documents.getDocs(),
                                        documents.getDocInfos(),
                                        docsInTest, 0));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_commit(db));

    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_close_file(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_free_db(db));

    // Check docs.
    ASSERT_EQ(COUCHSTORE_SUCCESS, open_db(COUCHSTORE_OPEN_FLAG_CREATE));
    documents.resetCounters();
    std::vector<sized_buf> buf(docsInTest);
    for (uint32_t ii = 0; ii < docsInTest; ++ii) {
        buf[ii] = documents.getDoc(ii)->id;
    }
    corrupted_btree_node_cb_param param;
    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_docinfos_by_id(db,
                                        &buf[0],
                                        docsInTest,
                                        0,
                                        corrupted_btree_node_cb,
                                        &param));
    ASSERT_EQ(docsInTest, param.num_called);

    couchstore_error_info_t errinfo;
    // Inject corruption into one of seq-tree nodes
    // (located at next to id-tree root).
    db->file.ops->pwrite(&errinfo, db->file.handle,
                         "corruption", 10, db->header.by_id_root->pointer+200);

    // Inject corruption into the last doc.
    db->file.ops->pwrite(&errinfo, db->file.handle,
                         "corruption", 10, param.last_doc_bp);

    // Close and reopen.
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_close_file(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_free_db(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, open_db(COUCHSTORE_OPEN_FLAG_CREATE));

    std::vector<uint64_t> seq_nums(docsInTest);
    for (uint32_t ii = 0; ii < docsInTest; ++ii) {
        seq_nums[ii] = docsInTest + ii + 1;
    }

    // Should fail.
    param.reset();
    ASSERT_NE(COUCHSTORE_SUCCESS,
              couchstore_docinfos_by_sequence(
                      db,
                      &seq_nums[0],
                      docsInTest,
                      COUCHSTORE_TOLERATE_CORRUPTION,
                      corrupted_btree_node_cb,
                      &param));
    // Some docs should be lost.
    ASSERT_GT(docsInTest, param.num_called);

    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_close_file(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_free_db(db));

    std::string cmd;
#ifdef _MSC_VER
    cmd = "couch_dbck --stale ";
#else
    cmd = "./couch_dbck --stale ";
#endif
    cmd += filePath;
    ASSERT_EQ(0, system(cmd.c_str()));

    // Open recovered file.
    std::string recovered_file = filePath + ".recovered";
    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_open_db(recovered_file.c_str(),
                                 COUCHSTORE_OPEN_FLAG_RDONLY, &db));

    // All docs should be retrieved.
    param.reset();
    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_docinfos_by_id(db,
                                        &buf[0],
                                        docsInTest,
                                        0,
                                        corrupted_btree_node_cb,
                                        &param));
    ASSERT_EQ(docsInTest, param.num_called);

    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_close_file(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_free_db(db));

    remove(recovered_file.c_str());

    db = nullptr;
}

/**
 * Verifies that couchstore_open fails if EXCL is specifies without CREAT
 */
TEST_F(CouchstoreInternalTest, OpenFails_EXCL) {
    ASSERT_FALSE(cb::io::isFile(filePath));
    EXPECT_EQ(COUCHSTORE_ERROR_INVALID_ARGUMENTS,
              couchstore_open_db(
                      filePath.c_str(), COUCHSTORE_OPEN_FLAG_EXCL, &db));
    EXPECT_FALSE(cb::io::isFile(filePath));
}

TEST_F(CouchstoreInternalTest, OpenFails_FileAlreadyExists) {
    ASSERT_FALSE(cb::io::isFile(filePath));

    // Create the file
    const auto flags = COUCHSTORE_OPEN_FLAG_CREATE | COUCHSTORE_OPEN_FLAG_EXCL;
    EXPECT_EQ(COUCHSTORE_SUCCESS,
              couchstore_open_db(filePath.c_str(), flags, &db));
    EXPECT_TRUE(cb::io::isFile(filePath));

    // Try to create it again
    EXPECT_EQ(COUCHSTORE_ERROR_OPEN_FILE,
              couchstore_open_db(filePath.c_str(), flags, &db));
#ifdef WIN32
    EXPECT_EQ(ERROR_FILE_EXISTS, GetLastError());
#else
    EXPECT_EQ(EEXIST, errno);
#endif
}

/**
 * Verifies that compaction will not open an existing target file
 */
TEST_F(CouchstoreInternalTest, CompactFails_FileAlreadyExists) {
    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_open_db(
                      compactPath.c_str(), COUCHSTORE_OPEN_FLAG_CREATE, &db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_close_file(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_free_db(db));
    db = nullptr;
    ASSERT_TRUE(cb::io::isFile(compactPath));

    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_open_db(
                      filePath.c_str(), COUCHSTORE_OPEN_FLAG_CREATE, &db));

    EXPECT_EQ(COUCHSTORE_ERROR_OPEN_FILE,
              couchstore_compact_db(db, compactPath.c_str()));
    EXPECT_TRUE(cb::io::isFile(compactPath));
#ifdef WIN32
    EXPECT_EQ(ERROR_FILE_EXISTS, GetLastError());
#else
    EXPECT_EQ(EEXIST, errno);
#endif
}

class CouchstoreMetadataTest : public CouchstoreInternalTest,
                               public ::testing::WithParamInterface<size_t> {};

TEST_P(CouchstoreMetadataTest, Metadata) {
    const std::string keyId(GetParam(), 'i');
    auto encryptionKeyCB = [&keyId](std::string_view)
            -> cb::couchstore::SharedEncryptionKey {
        return std::make_shared<cb::crypto::DataEncryptionKey>(
                cb::crypto::DataEncryptionKey{keyId,
                                              cb::crypto::Cipher::AES_256_GCM,
                                              std::string(32, 'k')});
    };

    if (GetParam() == 0 || GetParam() > UINT8_MAX) {
        ASSERT_EQ(COUCHSTORE_ERROR_INVALID_ARGUMENTS,
                  couchstore_open_db_ex(filePath.c_str(),
                                        COUCHSTORE_OPEN_FLAG_CREATE,
                                        encryptionKeyCB,
                                        couchstore_get_default_file_ops(),
                                        &db));
        return;
    }

    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_open_db_ex(filePath.c_str(),
                                    COUCHSTORE_OPEN_FLAG_CREATE,
                                    encryptionKeyCB,
                                    couchstore_get_default_file_ops(),
                                    &db));
    ASSERT_EQ(keyId, cb::couchstore::getEncryptionKeyId(*db));

    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_close_file(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_free_db(db));

    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_open_db_ex(filePath.c_str(),
                                    COUCHSTORE_OPEN_FLAG_RDONLY,
                                    encryptionKeyCB,
                                    couchstore_get_default_file_ops(),
                                    &db));
    ASSERT_EQ(keyId, cb::couchstore::getEncryptionKeyId(*db));
}

INSTANTIATE_TEST_SUITE_P(Parameterised, CouchstoreMetadataTest,
                         ::testing::Values(0, 1, 127, 128, 255, 256),
                         ::testing::PrintToStringParamName());

/**
 * Tests for automatic periodic sync() functionality.
 *
 * TODO: Currently just the argument parsing and calling to enable sync via
 * set_period_sync() is tested; no testing is performed of /if/ the extra
 * sync() calls are made as the Mock FileOps operates "in front" of the real
 * Posix/Windows file ops, and hence when those classes make extra sync
 * calls they are not recorded by the Mock. Ideally we'd have a way of mocking
 * the low-level fdatasync() method.
 */
class CouchstorePeriodicSyncTest : public CouchstoreInternalTest {
};

/**
 * Test that default behaviour is off.
 */
TEST_F(CouchstorePeriodicSyncTest, Off)
{
    EXPECT_CALL(ops, set_periodic_sync(_, _)).Times(0);

    ASSERT_EQ(COUCHSTORE_SUCCESS, open_db(COUCHSTORE_OPEN_FLAG_CREATE));
    EXPECT_EQ(0, db->file.options.periodic_sync_bytes);

    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_close_file(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_free_db(db));
    db = nullptr;

    remove(filePath.c_str());
}

/**
 * Test that periodic sync can enabled (to 1KB).
 */
TEST_F(CouchstorePeriodicSyncTest, Enable1KB)
{
    EXPECT_CALL(ops, set_periodic_sync(_, 1024)).Times(1);

    couchstore_open_flags flags = (1 << 24) | COUCHSTORE_OPEN_FLAG_CREATE;
    ASSERT_EQ(COUCHSTORE_SUCCESS, open_db(flags));
    EXPECT_EQ(1024, db->file.options.periodic_sync_bytes);
}

/**
 * Test that periodic sync can enabled (to 1MB).
 */
TEST_F(CouchstorePeriodicSyncTest, Enable1MB)
{
    EXPECT_CALL(ops, set_periodic_sync(_, 1024 * 1024)).Times(1);

    couchstore_open_flags flags = (11 << 24) | COUCHSTORE_OPEN_FLAG_CREATE;
    ASSERT_EQ(COUCHSTORE_SUCCESS, open_db(flags));
    EXPECT_EQ(1024 * 1024, db->file.options.periodic_sync_bytes);
}

/**
 * Test that periodic sync can enabled (to maximum of 1TB)
 */
TEST_F(CouchstorePeriodicSyncTest, EnableMaximum)
{
    EXPECT_CALL(ops, set_periodic_sync(_, 1024ull * 1024 * 1024 * 1024))
            .Times(1);

    couchstore_open_flags flags = (0x1f << 24) | COUCHSTORE_OPEN_FLAG_CREATE;
    ASSERT_EQ(COUCHSTORE_SUCCESS, open_db(flags));
    EXPECT_EQ(1024ull * 1024 * 1024 * 1024, db->file.options.periodic_sync_bytes);
}

/**
 * Tests whether the unbuffered file ops flag actually
 * prevents the buffered file operations from being used.
 */
TEST_F(CouchstoreInternalTest, unbuffered_fileops) {
    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_open_db_ex(filePath.c_str(),
                                    COUCHSTORE_OPEN_FLAG_CREATE |
                                            COUCHSTORE_OPEN_FLAG_UNBUFFERED,
                                    {},
                                    couchstore_get_default_file_ops(),
                                    &db));
    EXPECT_EQ(db->file.ops, couchstore_get_default_file_ops());
}

TEST_F(FileOpsErrorInjectionTest, dbopen_fileopen_fail) {
    EXPECT_CALL(ops, open(_, _, _, _)).WillOnce(Return(COUCHSTORE_ERROR_OPEN_FILE));
    EXPECT_EQ(COUCHSTORE_ERROR_OPEN_FILE, open_db(COUCHSTORE_OPEN_FLAG_CREATE));
}

TEST_F(FileOpsErrorInjectionTest, dbopen_filegoto_eof_fail) {
    EXPECT_CALL(ops, goto_eof(_, _)).WillOnce(Return(-1));
    EXPECT_CALL(ops, pread(_, _, _, _, _)).Times(0);
    EXPECT_EQ(COUCHSTORE_ERROR_OPEN_FILE, open_db(COUCHSTORE_OPEN_FLAG_CREATE));
}

/**
 * Test to check whether or not B+tree corrupted node is well tolerated.
 */
TEST_F(CouchstoreInternalTest, corrupted_btree_node2)
{
    remove(filePath.c_str());

    const uint32_t docsInTest = 100;
    std::string key_str, value_str;
    Documents documents(docsInTest);
    uint32_t size = htonl(0 | 0x80000000);
    uint32_t crc32 = htonl(0);
    char info[4 + 4];

    // Write the header's block header
    memcpy(&info[0], &size, 4);
    memcpy(&info[4], &crc32, 4);

    for (uint32_t ii = 0; ii < docsInTest; ii++) {
        key_str = "doc" + std::to_string(ii);
        value_str = "test_doc_body:" + std::to_string(ii);
        documents.setDoc(ii, key_str, value_str);
    }

    // Save docs.
    ASSERT_EQ(COUCHSTORE_SUCCESS, open_db(COUCHSTORE_OPEN_FLAG_CREATE));
    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_save_documents(db, documents.getDocs(),
                                        documents.getDocInfos(),
                                        docsInTest, 0));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_commit(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_close_file(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_free_db(db));

    // Check docs.
    ASSERT_EQ(COUCHSTORE_SUCCESS, open_db(COUCHSTORE_OPEN_FLAG_CREATE));
    documents.resetCounters();
    std::vector<sized_buf> buf(docsInTest);
    for (uint32_t ii = 0; ii < docsInTest; ++ii) {
        buf[ii] = documents.getDoc(ii)->id;
    }
    corrupted_btree_node_cb_param param;
    ASSERT_EQ(COUCHSTORE_SUCCESS,
              couchstore_docinfos_by_id(db,
                                        &buf[0],
                                        docsInTest,
                                        0,
                                        corrupted_btree_node_cb,
                                        &param));
    ASSERT_EQ(docsInTest, param.num_called);

    couchstore_error_info_t errinfo;
    // Inject corruption into one of B+tree nodes length by making it 0.

    db->file.ops->pwrite(&errinfo, db->file.handle,
                         &info, sizeof(info), param.last_doc_bp+24);

    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_close_file(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_free_db(db));

    ASSERT_EQ(COUCHSTORE_SUCCESS, open_db(COUCHSTORE_OPEN_FLAG_CREATE));
    param.reset();
    // Should fail.
    ASSERT_NE(COUCHSTORE_SUCCESS,
              couchstore_docinfos_by_id(db,
                                        &buf[0],
                                        docsInTest,
                                        0,
                                        corrupted_btree_node_cb,
                                        &param));
    // Without TOLERATE flag: should not retrieve any docs.
    ASSERT_EQ(static_cast<size_t>(0), param.num_called);

    param.reset();
    // Should fail.
    ASSERT_NE(COUCHSTORE_SUCCESS,
              couchstore_docinfos_by_id(db,
                                        &buf[0],
                                        docsInTest,
                                        COUCHSTORE_TOLERATE_CORRUPTION,
                                        corrupted_btree_node_cb,
                                        &param));

    // With TOLERATE flag: should retrieve some docs,
    // the number should be: '0 < # docs < docsInTest'.
    ASSERT_LT(static_cast<size_t>(0), param.num_called);
    ASSERT_GT(docsInTest, param.num_called);

    ASSERT_EQ(
            "'Couchstore::pread_compressed() Invalid compressed buffer "
            "length:0 pos:" +
                    std::to_string(param.last_doc_bp + 24) + "'",
            cb::couchstore::getLastInternalError());

    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_close_file(db));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_free_db(db));

    db = nullptr;
}
/**
 * This is a parameterised test which injects errors on specific
 * calls to the file ops object.
 *
 * In this example pwrite(..) is set up to pass through to a
 * non-mock implementation of FileOpsInterface for the first
 * `GetParam()` # of calls, then to inject an error on the
 * `GetParam() + 1` call.
 *
 * For this example GetParam() will be the range of values from
 * 0 to 2 (i.e. {0, 1}). Therefore pwrite(..) will return
 * a COUCHSTORE_ERROR_WRITE on the 1st and 2nd calls in each
 * instance.
 */
typedef ParameterisedFileOpsErrorInjectionTest NewOpenWrite;
TEST_P(NewOpenWrite, fail) {
    InSequence s;

    EXPECT_CALL(ops, pwrite(_, _, _, _, _)).Times(GetParam());
    EXPECT_CALL(ops, pwrite(_, _, _, _, _)).WillOnce(Return(COUCHSTORE_ERROR_WRITE));
    EXPECT_EQ(COUCHSTORE_ERROR_WRITE, open_db(COUCHSTORE_OPEN_FLAG_CREATE));
}
INSTANTIATE_TEST_SUITE_P(Parameterised, NewOpenWrite,
                        ::testing::Range(0, 2),
                        ::testing::PrintToStringParamName());

TEST_F(FileOpsErrorInjectionTest, dbdropfile_fileclose_fail) {
    ASSERT_EQ(COUCHSTORE_SUCCESS, open_db(COUCHSTORE_OPEN_FLAG_CREATE));
    {
        InSequence s;
        EXPECT_CALL(ops, close(_, _)).WillOnce(Invoke(
            [this](couchstore_error_info_t* errinfo, couch_file_handle handle) {
            // We need to actually close the file otherwise we'll get
            // a file handle leak and Windows won't be able to reopen
            // a file with the same name.
            ops.get_wrapped()->close(errinfo, handle);
            return COUCHSTORE_ERROR_WRITE;
        }));
        EXPECT_EQ(COUCHSTORE_ERROR_WRITE, couchstore_close_file(db));
    }
}

typedef ParameterisedFileOpsErrorInjectionTest SaveDocsWrite;
TEST_P(SaveDocsWrite, fail) {
    ASSERT_EQ(COUCHSTORE_SUCCESS, open_db(COUCHSTORE_OPEN_FLAG_CREATE));
    const size_t docCount = 1;
    documents = Documents(docCount);
    documents.generateDocs();
    {
        InSequence s;
        EXPECT_CALL(ops, pwrite(_, _, _, _, _)).Times(GetParam());
        EXPECT_CALL(ops, pwrite(_, _, _, _, _)).WillOnce(Return(COUCHSTORE_ERROR_WRITE));
        EXPECT_EQ(COUCHSTORE_ERROR_WRITE,
                  couchstore_save_documents(db, documents.getDocs(),
                                            documents.getDocInfos(), docCount, 0));
    }
}
INSTANTIATE_TEST_SUITE_P(Parameterised, SaveDocsWrite,
                        ::testing::Range(0, 6),
                        ::testing::PrintToStringParamName());

typedef ParameterisedFileOpsErrorInjectionTest CommitSync;
TEST_P(CommitSync, fail) {
    open_db_and_populate(COUCHSTORE_OPEN_FLAG_CREATE, 1);
    {
        InSequence s;
        EXPECT_CALL(ops, sync(_, _)).Times(GetParam());
        EXPECT_CALL(ops, sync(_, _)).WillOnce(Return(COUCHSTORE_ERROR_WRITE));
        EXPECT_EQ(COUCHSTORE_ERROR_WRITE, couchstore_commit(db));
    }
}
INSTANTIATE_TEST_SUITE_P(Parameterised, CommitSync,
                        ::testing::Range(0, 2),
                        ::testing::PrintToStringParamName());

typedef ParameterisedFileOpsErrorInjectionTest CommitWrite;
TEST_P(CommitWrite, fail) {
    open_db_and_populate(COUCHSTORE_OPEN_FLAG_CREATE, 1);
    {
        InSequence s;
        EXPECT_CALL(ops, pwrite(_, _, _, _, _)).Times(GetParam());
        EXPECT_CALL(ops, pwrite(_, _, _, _, _)).WillOnce(Return(COUCHSTORE_ERROR_WRITE));
        EXPECT_EQ(COUCHSTORE_ERROR_WRITE, couchstore_commit(db));
    }
}
INSTANTIATE_TEST_SUITE_P(Parameterised, CommitWrite,
                        ::testing::Range(0, 4),
                        ::testing::PrintToStringParamName());

typedef ParameterisedFileOpsErrorInjectionTest SaveDocWrite;
TEST_P(SaveDocWrite, fail) {
    ASSERT_EQ(COUCHSTORE_SUCCESS, open_db(COUCHSTORE_OPEN_FLAG_CREATE));
    Documents documents(1);
    documents.generateDocs();
    {
        InSequence s;
        EXPECT_CALL(ops, pwrite(_, _, _, _, _)).Times(GetParam());
        EXPECT_CALL(ops, pwrite(_, _, _, _, _)).WillOnce(Return(COUCHSTORE_ERROR_WRITE));
        EXPECT_EQ(COUCHSTORE_ERROR_WRITE,
                  couchstore_save_document(db, documents.getDoc(0),
                                           documents.getDocInfo(0), 0));
    }
}
INSTANTIATE_TEST_SUITE_P(Parameterised, SaveDocWrite,
                        ::testing::Range(0, 6),
                        ::testing::PrintToStringParamName());

typedef ParameterisedFileOpsErrorInjectionTest DocInfoById;
TEST_P(DocInfoById, fail) {
    open_db_and_populate(COUCHSTORE_OPEN_FLAG_CREATE, 10);
    EXPECT_EQ(COUCHSTORE_SUCCESS, couchstore_commit(db));
    {
        InSequence s;
        EXPECT_CALL(ops, pread(_, _, _, _, _)).Times(GetParam());
        EXPECT_CALL(ops, pread(_, _, _, _, _)).WillOnce(Return(COUCHSTORE_ERROR_READ));
        EXPECT_EQ(COUCHSTORE_ERROR_READ,
                  couchstore_docinfo_by_id(db, documents.getDocInfo(0)->id.buf,
                                           documents.getDocInfo(0)->id.size,
                                           &info));

    }
}
INSTANTIATE_TEST_SUITE_P(Parameterised, DocInfoById,
                        ::testing::Range(0, 2),
                        ::testing::PrintToStringParamName());

typedef ParameterisedFileOpsErrorInjectionTest DocInfoBySeq;
TEST_P(DocInfoBySeq, fail) {
    open_db_and_populate(COUCHSTORE_OPEN_FLAG_CREATE, 10);
    EXPECT_EQ(COUCHSTORE_SUCCESS, couchstore_commit(db));
    couchstore_docinfo_by_id(db, documents.getDocInfo(0)->id.buf,
                             documents.getDocInfo(0)->id.size, &info);
    {
        InSequence s;
        EXPECT_CALL(ops, pread(_, _, _, _, _)).Times(GetParam());
        EXPECT_CALL(ops, pread(_, _, _, _, _)).WillOnce(Return(COUCHSTORE_ERROR_READ));
        EXPECT_EQ(COUCHSTORE_ERROR_READ,
                  couchstore_docinfo_by_sequence(db, info->db_seq, &info));

    }
    couchstore_free_docinfo(info);
}
INSTANTIATE_TEST_SUITE_P(Parameterised, DocInfoBySeq,
                        ::testing::Range(0, 2),
                        ::testing::PrintToStringParamName());

typedef ParameterisedFileOpsErrorInjectionTest OpenDocRead;
TEST_P(OpenDocRead, fail) {
    open_db_and_populate(COUCHSTORE_OPEN_FLAG_CREATE, 10);
    EXPECT_EQ(COUCHSTORE_SUCCESS, couchstore_commit(db));
    {
        InSequence s;
        EXPECT_CALL(ops, pread(_, _, _, _, _)).Times(GetParam());
        EXPECT_CALL(ops, pread(_, _, _, _, _)).WillOnce(Return(COUCHSTORE_ERROR_READ));
        EXPECT_EQ(COUCHSTORE_ERROR_READ,
                  couchstore_open_document(db, documents.getDocInfo(0)->id.buf,
                                           documents.getDocInfo(0)->id.size,
                                           &doc, DECOMPRESS_DOC_BODIES));
    }
}
INSTANTIATE_TEST_SUITE_P(Parameterised, OpenDocRead,
                        ::testing::Range(0, 2),
                        ::testing::PrintToStringParamName());

typedef ParameterisedFileOpsErrorInjectionTest DocByInfoRead;
TEST_P(DocByInfoRead, fail) {
    open_db_and_populate(COUCHSTORE_OPEN_FLAG_CREATE, 10);
    EXPECT_EQ(COUCHSTORE_SUCCESS, couchstore_commit(db));
    couchstore_docinfo_by_id(db, documents.getDocInfo(0)->id.buf,
                             documents.getDocInfo(0)->id.size, &info);
    {
        InSequence s;
        EXPECT_CALL(ops, pread(_, _, _, _, _)).Times(GetParam());
        EXPECT_CALL(ops, pread(_, _, _, _, _)).WillOnce(Return(COUCHSTORE_ERROR_READ));
        EXPECT_EQ(COUCHSTORE_ERROR_READ,
                  couchstore_open_doc_with_docinfo(db, info, &doc, DECOMPRESS_DOC_BODIES));

    }
    couchstore_free_docinfo(info);
}
INSTANTIATE_TEST_SUITE_P(Parameterised, DocByInfoRead,
                        ::testing::Range(0, 2),
                        ::testing::PrintToStringParamName());

static int changes_callback(Db *db, DocInfo *docinfo, void *ctx) {
    return 0;
}

typedef ParameterisedFileOpsErrorInjectionTest ChangesSinceRead;
TEST_P(ChangesSinceRead, fail) {
    open_db_and_populate(COUCHSTORE_OPEN_FLAG_CREATE, 10);
    EXPECT_EQ(COUCHSTORE_SUCCESS, couchstore_commit(db));
    couchstore_docinfo_by_id(db, documents.getDocInfo(0)->id.buf,
                             documents.getDocInfo(0)->id.size, &info);
    {
        InSequence s;
        EXPECT_CALL(ops, pread(_, _, _, _, _)).Times(GetParam());
        EXPECT_CALL(ops, pread(_, _, _, _, _)).WillOnce(Return(COUCHSTORE_ERROR_READ));
        EXPECT_EQ(COUCHSTORE_ERROR_READ,
                  couchstore_changes_since(db, info->db_seq, 0,
                                           changes_callback, nullptr));

    }
    couchstore_free_docinfo(info);
}
INSTANTIATE_TEST_SUITE_P(Parameterised, ChangesSinceRead,
                        ::testing::Range(0, 2),
                        ::testing::PrintToStringParamName());

typedef ParameterisedFileOpsErrorInjectionTest AllDocsRead;
TEST_P(AllDocsRead, fail) {
    open_db_and_populate(COUCHSTORE_OPEN_FLAG_CREATE, 10);
    EXPECT_EQ(COUCHSTORE_SUCCESS, couchstore_commit(db));
    couchstore_docinfo_by_id(db, documents.getDocInfo(0)->id.buf,
                             documents.getDocInfo(0)->id.size, &info);
    {
        InSequence s;
        EXPECT_CALL(ops, pread(_, _, _, _, _)).Times(GetParam());
        EXPECT_CALL(ops, pread(_, _, _, _, _)).WillOnce(Return(COUCHSTORE_ERROR_READ));
        EXPECT_EQ(COUCHSTORE_ERROR_READ,
                  couchstore_all_docs(db, nullptr, 0,
                                      changes_callback, nullptr));

    }
    couchstore_free_docinfo(info);
}
INSTANTIATE_TEST_SUITE_P(Parameterised, AllDocsRead,
                        ::testing::Range(0, 2),
                        ::testing::PrintToStringParamName());

typedef ParameterisedFileOpsErrorInjectionTest DocInfosByIdRead;
TEST_P(DocInfosByIdRead, fail) {
    open_db_and_populate(COUCHSTORE_OPEN_FLAG_CREATE, 10);
    EXPECT_EQ(COUCHSTORE_SUCCESS, couchstore_commit(db));

    {
        InSequence s;
        EXPECT_CALL(ops, pread(_, _, _, _, _)).Times(GetParam());
        EXPECT_CALL(ops, pread(_, _, _, _, _)).WillOnce(Return(COUCHSTORE_ERROR_READ));
        EXPECT_EQ(COUCHSTORE_ERROR_READ,
                  couchstore_docinfos_by_id(db, &documents.getDocInfo(0)->id,
                                            1, 0, changes_callback, nullptr));

    }
}
INSTANTIATE_TEST_SUITE_P(Parameterised, DocInfosByIdRead,
                        ::testing::Range(0, 2),
                        ::testing::PrintToStringParamName());

typedef ParameterisedFileOpsErrorInjectionTest DocInfosBySeqRead;
TEST_P(DocInfosBySeqRead, fail) {
    open_db_and_populate(COUCHSTORE_OPEN_FLAG_CREATE, 10);
    EXPECT_EQ(COUCHSTORE_SUCCESS, couchstore_commit(db));
    couchstore_docinfo_by_id(db, documents.getDocInfo(0)->id.buf,
                             documents.getDocInfo(0)->id.size, &info);
    {
        InSequence s;
        EXPECT_CALL(ops, pread(_, _, _, _, _)).Times(GetParam());
        EXPECT_CALL(ops, pread(_, _, _, _, _)).WillOnce(Return(COUCHSTORE_ERROR_READ));
        EXPECT_EQ(COUCHSTORE_ERROR_READ,
                  couchstore_docinfos_by_sequence(db, &info->db_seq, 1, 0,
                                                  changes_callback, nullptr));

    }
    couchstore_free_docinfo(info);
}
INSTANTIATE_TEST_SUITE_P(Parameterised, DocInfosBySeqRead,
                        ::testing::Range(0, 2),
                        ::testing::PrintToStringParamName());

static int tree_walk_callback(Db *db, int depth, const DocInfo* doc_info,
                       uint64_t subtree_size, const sized_buf* reduce_value,
                       void *ctx) {
    return 0;
}

typedef ParameterisedFileOpsErrorInjectionTest WalkIdTreeRead;
TEST_P(WalkIdTreeRead, fail) {
    open_db_and_populate(COUCHSTORE_OPEN_FLAG_CREATE, 10);
    EXPECT_EQ(COUCHSTORE_SUCCESS, couchstore_commit(db));
    couchstore_docinfo_by_id(db, documents.getDocInfo(0)->id.buf,
                             documents.getDocInfo(0)->id.size, &info);
    {
        InSequence s;
        EXPECT_CALL(ops, pread(_, _, _, _, _)).Times(GetParam());
        EXPECT_CALL(ops, pread(_, _, _, _, _)).WillOnce(Return(COUCHSTORE_ERROR_READ));
        EXPECT_EQ(COUCHSTORE_ERROR_READ,
                  couchstore_walk_id_tree(db, nullptr, 0,
                                          tree_walk_callback, nullptr));

    }
    couchstore_free_docinfo(info);
}
INSTANTIATE_TEST_SUITE_P(Parameterised, WalkIdTreeRead,
                        ::testing::Range(0, 2),
                        ::testing::PrintToStringParamName());

typedef ParameterisedFileOpsErrorInjectionTest WalkSeqTreeRead;
TEST_P(WalkSeqTreeRead, fail) {
    open_db_and_populate(COUCHSTORE_OPEN_FLAG_CREATE, 10);
    EXPECT_EQ(COUCHSTORE_SUCCESS, couchstore_commit(db));
    couchstore_docinfo_by_id(db, documents.getDocInfo(0)->id.buf,
                             documents.getDocInfo(0)->id.size, &info);
    {
        InSequence s;
        EXPECT_CALL(ops, pread(_, _, _, _, _)).Times(GetParam());
        EXPECT_CALL(ops, pread(_, _, _, _, _)).WillOnce(Return(COUCHSTORE_ERROR_READ));
        EXPECT_EQ(COUCHSTORE_ERROR_READ,
                  couchstore_walk_seq_tree(db, 0, 0,
                                           tree_walk_callback, nullptr));

    }
    couchstore_free_docinfo(info);
}
INSTANTIATE_TEST_SUITE_P(Parameterised, WalkSeqTreeRead,
                        ::testing::Range(0, 2),
                        ::testing::PrintToStringParamName());

typedef ParameterisedFileOpsErrorInjectionTest LocalDocFileWrite;
TEST_P(LocalDocFileWrite, fail) {
    ASSERT_EQ(COUCHSTORE_SUCCESS, open_db(COUCHSTORE_OPEN_FLAG_CREATE));
    std::string id("Hello");
    std::string json("\"World\"");
    LocalDoc doc(create_local_doc(id, json));

    {
        InSequence s;
        EXPECT_CALL(ops, pwrite(_, _, _, _, _)).Times(GetParam());
        EXPECT_CALL(ops, pwrite(_, _, _, _, _)).WillOnce(Return(COUCHSTORE_ERROR_WRITE));
        EXPECT_EQ(COUCHSTORE_ERROR_WRITE, couchstore_save_local_document(db, &doc));
    }
}
INSTANTIATE_TEST_SUITE_P(Parameterised, LocalDocFileWrite,
                        ::testing::Range(0, 2),
                        ::testing::PrintToStringParamName());

typedef ParameterisedFileOpsErrorInjectionTest LocalDocFileRead;
TEST_P(LocalDocFileRead, fail) {
    ASSERT_EQ(COUCHSTORE_SUCCESS, open_db(COUCHSTORE_OPEN_FLAG_CREATE));

    std::string id("Hello");
    std::string json("\"World\"");
    LocalDoc doc(create_local_doc(id, json));
    ASSERT_EQ(COUCHSTORE_SUCCESS, couchstore_save_local_document(db, &doc));

    {
        InSequence s;
        EXPECT_CALL(ops, pread(_, _, _, _, _)).Times(GetParam());
        EXPECT_CALL(ops, pread(_, _, _, _, _)).WillOnce(Return(COUCHSTORE_ERROR_READ));
        LocalDoc* ldoc;
        EXPECT_EQ(COUCHSTORE_ERROR_READ,
                  couchstore_open_local_document(db, &id[0],
                                                 strlen(&id[0]), &ldoc));
    }
}
INSTANTIATE_TEST_SUITE_P(Parameterised, LocalDocFileRead,
                        ::testing::Range(0, 2),
                        ::testing::PrintToStringParamName());

typedef ParameterisedFileOpsErrorInjectionTest CompactSourceRead;
TEST_P(CompactSourceRead, fail) {
    open_db_and_populate(COUCHSTORE_OPEN_FLAG_CREATE, 1);
    {
        InSequence s;
        EXPECT_CALL(ops, pread(_, _, _, _, _)).Times(GetParam());
        EXPECT_CALL(ops, pread(_, _, _, _, _)).WillOnce(Return(COUCHSTORE_ERROR_READ));
        EXPECT_EQ(COUCHSTORE_ERROR_READ,
                  couchstore_compact_db_ex(db,
                                           compactPath.c_str(),
                                           COUCHSTORE_COMPACT_FLAG_UNBUFFERED,
                                           {},
                                           nullptr,
                                           nullptr,
                                           nullptr,
                                           &ops));
    }
}
INSTANTIATE_TEST_SUITE_P(Parameterised, CompactSourceRead,
                        ::testing::Range(0, 4),
                        ::testing::PrintToStringParamName());

typedef ParameterisedFileOpsErrorInjectionTest CompactTargetWrite;
TEST_P(CompactTargetWrite, fail) {
    open_db_and_populate(COUCHSTORE_OPEN_FLAG_CREATE, 1);
    {
        InSequence s;
        EXPECT_CALL(ops, pwrite(_, _, _, _, _)).Times(GetParam());
        EXPECT_CALL(ops, pwrite(_, _, _, _, _)).WillOnce(Return(COUCHSTORE_ERROR_WRITE));
        EXPECT_EQ(COUCHSTORE_ERROR_WRITE,
                  couchstore_compact_db_ex(db,
                                           compactPath.c_str(),
                                           COUCHSTORE_COMPACT_FLAG_UNBUFFERED,
                                           {},
                                           nullptr,
                                           nullptr,
                                           nullptr,
                                           &ops));
    }
}
INSTANTIATE_TEST_SUITE_P(Parameterised, CompactTargetWrite,
                        ::testing::Range(0, 6),
                        ::testing::PrintToStringParamName());

class MockTreeWriter : public TreeWriter {
public:
    using TreeWriter::cipher;
    using TreeWriter::file;
    using TreeWriter::read_record;
};

class TreeWriterTest : public ::testing::Test {
protected:
    void SetUp() override {
        treeWriter = std::make_unique<MockTreeWriter>();
        ASSERT_EQ(
                COUCHSTORE_SUCCESS,
                treeWriter->open(
                        "tree_writer.tmp", nullptr, nullptr, nullptr, nullptr));
    }

    void TearDown() override {
        if (treeWriter) {
            treeWriter->close();
            treeWriter.reset();
        }
    }

    void populate() {
        for (size_t ii = 0; ii < 128; ++ii) {
            auto key = std::to_string(ii ^ 41);
            auto value = "value" + key;
            ASSERT_EQ(COUCHSTORE_SUCCESS,
                      treeWriter->add({key.data(), key.size()},
                                      {value.data(), value.size()}));
        }
    }

    void sortAndVerify() {
        ASSERT_EQ(COUCHSTORE_SUCCESS, treeWriter->sort());
        ::rewind(treeWriter->file);
        std::string previous;
        size_t count = 0;
        for (;; ++count) {
            TreeWriter::KeyValue record;
            auto ret = MockTreeWriter::read_record(
                    treeWriter->file, &record, treeWriter.get());
            if (ret == 0) {
                break;
            }
            ASSERT_EQ(1, ret);
            EXPECT_GT(record.key, previous);
            EXPECT_EQ("value" + record.key, record.value);
            previous = std::move(record.key);
        }
        EXPECT_EQ(128, count);
    }

    std::unique_ptr<MockTreeWriter> treeWriter;
};

TEST_F(TreeWriterTest, Unencrypted) {
    populate();
    sortAndVerify();
}

TEST_F(TreeWriterTest, Encrypted) {
    ASSERT_EQ(COUCHSTORE_SUCCESS, treeWriter->enable_encryption());
    populate();
    sortAndVerify();
}

TEST_F(TreeWriterTest, DecryptNotEncrypted) {
    populate();
    ASSERT_EQ(COUCHSTORE_SUCCESS, treeWriter->sort());
    ASSERT_EQ(COUCHSTORE_SUCCESS, treeWriter->enable_encryption());
    ::rewind(treeWriter->file);
    TreeWriter::KeyValue record;
    EXPECT_EQ(-1,
              MockTreeWriter::read_record(
                      treeWriter->file, &record, treeWriter.get()));
}

TEST_F(TreeWriterTest, ReadWithWrongKey) {
    ASSERT_EQ(COUCHSTORE_SUCCESS, treeWriter->enable_encryption());
    populate();
    ASSERT_EQ(COUCHSTORE_SUCCESS, treeWriter->sort());
    treeWriter->cipher.reset();
    ASSERT_EQ(COUCHSTORE_SUCCESS, treeWriter->enable_encryption());
    ::rewind(treeWriter->file);
    TreeWriter::KeyValue record;
    EXPECT_EQ(-1,
              MockTreeWriter::read_record(
                      treeWriter->file, &record, treeWriter.get()));
}

TEST_F(TreeWriterTest, SortWithWrongKey) {
    ASSERT_EQ(COUCHSTORE_SUCCESS, treeWriter->enable_encryption());
    populate();
    treeWriter->cipher.reset();
    ASSERT_EQ(COUCHSTORE_SUCCESS, treeWriter->enable_encryption());
    ASSERT_EQ(COUCHSTORE_ERROR_READ, treeWriter->sort());
}
