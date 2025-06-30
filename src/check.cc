/*
 *     Copyright 2025-Present Couchbase, Inc.
 *
 *   Use of this software is governed by the Business Source License included
 *   in the file licenses/BSL-Couchbase.txt.  As of the Change Date specified
 *   in that file, in accordance with the Business Source License, use of this
 *   software will be governed by the Apache License, Version 2.0, included in
 *   the file licenses/APL2.txt.
 */

/**
 * Intentionally quiet and simple program that intends to read as much of a
 * couchstore file as possible and find any checksum/malformed data errors.
 *
 * The program runs through all 3 indexes as follows.
 *
 * 1) Local index and local documents.
 * 2) seq-number index and documents.
 * 3) id index (no documents because 2 reads them all).
 *
 * The program will exit with a non-zero exit code if any error occurs and print
 * to STDERR information about the problem.
 */

#include <libcouchstore/couch_db.h>
#include <iostream>
#include <string>

// filename that the program is checking
static std::string filename;

static void print_error(Db* db, couchstore_error_t err, std::string_view msg) {
    std::cerr << filename << ": " << std::string(msg)
              << ": couchstore_error_t:" << couchstore_strerror(err)
              << " last_error:" << cb::couchstore::getLastInternalError()
              << " last_os_error:" << cb::couchstore::getLastOsError(*db)
              << std::endl;
}

static int callback_and_access_document(Db* db, DocInfo* docinfo, void*) {
    Doc* doc = nullptr;
    auto docerr = couchstore_open_doc_with_docinfo(
            db, docinfo, &doc, DECOMPRESS_DOC_BODIES);
    if (docerr != COUCHSTORE_SUCCESS) {
        if (docinfo->deleted && docerr == COUCHSTORE_ERROR_DOC_NOT_FOUND) {
            return COUCHSTORE_SUCCESS;
        }
        print_error(db,
                    docerr,
                    "couchstore_open_doc_with_docinfo returned error for key:" +
                            std::string{docinfo->id.buf, docinfo->id.size});
        exit(1);
    }

    couchstore_free_document(doc);
    return COUCHSTORE_SUCCESS;
}

static int callback_and_access_local_document(Db* db,
                                              int depth,
                                              const DocInfo* docinfo,
                                              uint64_t subtreeSize,
                                              const sized_buf* reduceValue,
                                              void* ctx) {
    if (!docinfo) {
        return 0;
    }
    LocalDoc* lDoc = nullptr;
    auto err = couchstore_open_local_document(
            db, docinfo->id.buf, docinfo->id.size, &lDoc);
    if (err != COUCHSTORE_SUCCESS && err != COUCHSTORE_ERROR_DOC_NOT_FOUND) {
        print_error(db, err, "couchstore_open_local_document returned error");
        exit(1);
    }
    couchstore_free_local_document(lDoc);
    return 0;
}

static int callback(Db* db, DocInfo* docinfo, void* ctx) {
    return COUCHSTORE_SUCCESS;
}

static void usage(const char* progname) {
    std::cout << progname
              << " is a program that will iterate through all the indexes and "
                 "documents in a couchstore file and exit(1) if there are any "
                 "errors."
              << std::endl;
    std::cout << "Usage: " << progname << " <filename>" << std::endl;
}

int main(int argc, char** argv) {
    if (argc != 2) {
        usage(argv[0]);
        return 1;
    }

    filename = argv[1];

    Db* db = nullptr;

    // Open the database
    auto err = couchstore_open_db(
            filename.c_str(), COUCHSTORE_OPEN_FLAG_RDONLY, &db);
    if (err != COUCHSTORE_SUCCESS) {
        print_error(db, err, "couchstore_open_db returned error");
        return 1;
    }
    int seq_count = 0;
    int id_count = 0;

    err = couchstore_walk_local_tree(
            db, nullptr, 0, callback_and_access_local_document, nullptr);
    if (err != COUCHSTORE_SUCCESS) {
        print_error(db, err, "couchstore_walk_local_tree returned error");
        return 1;
    }

    // Process seq-index
    err = couchstore_changes_since(
            db, 0, 0, callback_and_access_document, &seq_count);
    if (err != COUCHSTORE_SUCCESS) {
        print_error(db, err, "couchstore_changes_since returned error");
        return 1;
    }

    // Process key-index
    err = couchstore_all_docs(db, nullptr, 0, callback, &id_count);
    if (err != COUCHSTORE_SUCCESS) {
        print_error(db, err, "couchstore_all_docs returned error");
        return 1;
    }

    couchstore_close_file(db);
    couchstore_free_db(db);

    if (seq_count != id_count) {
        std::cerr << filename << ": The sequence index count (" << seq_count
                  << ") does not match the id index count (" << id_count << ")"
                  << std::endl;
        return 1;
    }

    return 0;
}