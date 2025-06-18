/*
 *     Copyright 2025-Present Couchbase, Inc.
 *
 *   Use of this software is governed by the Business Source License included
 *   in the file licenses/BSL-Couchbase.txt.  As of the Change Date specified
 *   in that file, in accordance with the Business Source License, use of this
 *   software will be governed by the Apache License, Version 2.0, included in
 *   the file licenses/APL2.txt.
 */

#include "internal.h"

#include <cstdlib>
#include <iostream>
#include <string_view>

static int usage(const char* progname) {
    std::cerr << "usage: " << progname
              << " --file FILE"
                 " [--byid POS]"
                 " [--byseq POS]"
                 " [--local POS]"
                 "\n\n"
                 "Adds a new commit, optionally changing index root pointers.\n"
                 "Note that reduce values will not be re-computed.\n"
                 "Intended only for testing and investigations.\n";
    return 1;
}

static int print_error(const char* func, couchstore_error_t errcode) {
    std::cerr << "Error in " << func << ": " << couchstore_strerror(errcode)
              << " last_error:" << cb::couchstore::getLastInternalError()
              << std::endl;
    return 2;
}

int main(int argc, char** argv) {
    const char* file = nullptr;
    cs_off_t byid_root = 0;
    cs_off_t byseq_root = 0;
    cs_off_t local_root = 0;

    for (int ii = 1; ii < argc; ++ii) {
        std::string_view arg = argv[ii++];
        if (ii >= argc) {
            return usage(argv[0]);
        }
        if (arg == "--file") {
            file = argv[ii];
        } else if (arg == "--byid") {
            byid_root = std::strtoll(argv[ii], nullptr, 0);
        } else if (arg == "--byseq") {
            byseq_root = std::strtoll(argv[ii], nullptr, 0);
        } else if (arg == "--local") {
            local_root = std::strtoll(argv[ii], nullptr, 0);
        } else {
            return usage(argv[0]);
        }
    }

    if (file == nullptr) {
        return usage(argv[0]);
    }

    Db* db = nullptr;
    auto errcode = couchstore_open_db(file, 0, &db);
    if (errcode) {
        return print_error("open_db", errcode);
    }

    auto& header = db->header;
    if (header.by_id_root) {
        if (byid_root > 0) {
            header.by_id_root->pointer = byid_root;
            std::cout << '*';
        }
        std::cout << "byid: " << header.by_id_root->pointer << std::endl;
    }
    if (header.by_seq_root) {
        if (byseq_root > 0) {
            header.by_seq_root->pointer = byseq_root;
            std::cout << '*';
        }
        std::cout << "byseq: " << header.by_seq_root->pointer << std::endl;
    }
    if (header.local_docs_root) {
        if (local_root > 0) {
            header.local_docs_root->pointer = local_root;
            std::cout << '*';
        }
        std::cout << "local: " << header.local_docs_root->pointer << std::endl;
    }

    errcode = couchstore_commit(db);
    if (errcode) {
        return print_error("commit", errcode);
    }

    return 0;
}
