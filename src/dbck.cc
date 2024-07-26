/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2017 Couchbase, Inc
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

#include "internal.h"
#include "util.h"

#include <libcouchstore/couch_db.h>

#include <getopt.h>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

static void usage() {
    printf("USAGE: couch_dbck [options] "
           "source_filename [destination_filename]\n");
    printf("\nOptions:\n");
    printf("    -s, --stale       "
           "Recover from stale commits if corruption detected.\n");
    printf("    -v, --verbose     "
           "Display detailed messages.\n");
    printf("    -j, --json        "
           "Display corrupt document info as JSON objects "
           "(one per line).\n");
    exit(EXIT_FAILURE);
}

struct recovery_options {
    // Source file name.
    std::string src_filename;
    // Destination (recovered) file name.
    std::string dst_filename;
    // If set, recover using old data from stale commits.
    bool enable_rewind = false;
    // If set, print out detailed messages.
    bool verbose_msg = false;
    // If set, print verbose messages as JSON objects.
    bool json = false;
};

struct recover_file_hook_param {
    // Number of documents referred to by index.
    uint64_t num_visited_docs = 0;
    // Number of corrupted documents.
    uint64_t num_corrupted_docs = 0;
    // Recovery options.
    recovery_options* options = nullptr;
    // DB handle for source file.
    Db* db_src = nullptr;
};

std::string get_printable_string(const sized_buf& buf) {
    std::string ret;
    for (size_t i=0; i<buf.size; ++i) {
        if (0x20 <= buf.buf[i] && buf.buf[i] <= 0x7d) {
            // Printable character.
            ret += buf.buf[i];
        } else {
            // Otherwise: dump hex.
            std::stringstream ss;
            ss << "(0x" << std::setfill('0') << std::setw(2)
               << std::hex << static_cast<size_t>(buf.buf[i]) << ") ";
            ret += ss.str();
        }
    }
    return ret;
}

static int recover_file_hook(Db*, DocInfo* docinfo, sized_buf, void* ctx) {
    auto* param = reinterpret_cast<recover_file_hook_param*>(ctx);
    if (!docinfo) {
        // End of compaction.
        return 0;
    }

    param->num_visited_docs++;

    couchstore_error_t errcode;
    Doc* cur_doc;

    if (docinfo->deleted) {
        // Deleted doc.
        return 0;
    }

    // Open doc body.
    errcode = couchstore_open_doc_with_docinfo(
            param->db_src, docinfo, &cur_doc, 0x0);
    if (errcode != COUCHSTORE_SUCCESS) {
        // Document is corrupted.
        if (param->options->verbose_msg) {
            std::string fmt;
            if (param->options->json) {
                fmt = "{"
                      R"("type":"corrupted document",)"
                      R"("error code":%d,)"
                      R"("error message":"%s",)"
                      R"("id":"%s",)"
                      R"("bp")" ":%" PRIu64 ","
                      R"("physical size":%zu,)"
                      R"("seq")" ":%" PRIu64
                      "}\n";
            } else {
                fmt = "Corrupted document "
                      "(error code %d, %s): "
                      "id '%s', "
                      "bp %" PRIu64 ", "
                      "physical size %zu, "
                      "seq %" PRIu64
                      "\n";
            }

            fprintf(stdout, fmt.c_str(),
                    errcode, couchstore_strerror(errcode),
                    get_printable_string(docinfo->id).c_str(),
                    docinfo->bp,
                    docinfo->physical_size,
                    docinfo->db_seq);
        }
        param->num_corrupted_docs++;
    } else {
        couchstore_free_document(cur_doc);
    }

    return 0;
}

struct rewind_request {
    // Recovery options.
    recovery_options* options = nullptr;
    // DB handle for source file.
    Db *db_src = nullptr;
    // DB handle for recovered file.
    Db *db_recovered = nullptr;
    // Total number of old documents recovered from all stale commits.
    uint64_t total_num_docs_recovered = 0;
};

struct rewind_hook_param {
    // Recovery options.
    recovery_options* options = nullptr;
    // DB handle for source file.
    Db *db_src = nullptr;
    // DB handle for recovered file.
    Db *db_dst = nullptr;
    // Number of documents recovered from this specific commit.
    uint64_t num_docs_recovered = 0;
};

static int rewind_hook(Db*,
                       int,
                       const DocInfo* doc_info,
                       uint64_t,
                       const sized_buf*,
                       void* ctx) {
    auto* param = reinterpret_cast<rewind_hook_param*>(ctx);
    if (!doc_info) {
        return 0;
    }

    DocInfo* doc_info_dst;
    couchstore_error_t errcode;
    errcode = couchstore_docinfo_by_id(param->db_dst,
                                       doc_info->id.buf,
                                       doc_info->id.size,
                                       &doc_info_dst);
    if (errcode != COUCHSTORE_SUCCESS) {
        // The doc exists in stale commit (of corrupted file) only.
        // Copy it into the destination file.
        Doc* cur_doc;
        errcode = couchstore_open_doc_with_docinfo(
                param->db_src, (DocInfo*)doc_info, &cur_doc, 0x0);
        if (errcode != COUCHSTORE_SUCCESS) {
            return 0;
        }

        if (param->options->verbose_msg) {
            std::string fmt;
            if (param->options->json) {
                fmt = "{"
                      R"("type":"recovered document",)"
                      R"("id":"%s",)"
                      R"("bp")" ":%" PRIu64 ","
                      R"("size")" ":%zu,"
                      R"("seq")" ":%" PRIu64
                      "}\n";
            } else {
                fmt = "Recovered document '%s', "
                      "prev bp %" PRIu64 ", "
                      "prev size %zu, "
                      "prev seq num %" PRIu64
                      "\n";
            }

            fprintf(stdout, fmt.c_str(),
                    get_printable_string(doc_info->id).c_str(),
                    doc_info->bp,
                    doc_info->physical_size,
                    doc_info->db_seq);
        }

        couchstore_save_document(param->db_dst,
                                 cur_doc,
                                 (DocInfo*)doc_info,
                                 COUCHSTORE_SEQUENCE_AS_IS);
        param->num_docs_recovered++;
        couchstore_free_document(cur_doc);
    } else {
        couchstore_free_docinfo(doc_info_dst);
    }
    return 0;
}

static void rewind_and_get_stale_data(rewind_request& rq) {
    couchstore_error_t errcode;
    size_t num_rewind = 0;
    Db *db = nullptr;

    errcode = couchstore_open_db_ex(rq.options->src_filename.c_str(),
                                    COUCHSTORE_OPEN_FLAG_RDONLY,
                                    {},
                                    couchstore_get_default_file_ops(),
                                    &db);

    while (errcode == COUCHSTORE_SUCCESS) {
        errcode = couchstore_rewind_db_header(db);
        if (errcode != COUCHSTORE_SUCCESS) {
            db = nullptr;
            break;
        }
        num_rewind++;

        rewind_hook_param rewind_param;
        rewind_param.options = rq.options;
        rewind_param.db_dst = rq.db_recovered;
        rewind_param.db_src = rq.db_src;

        // Walk ID tree and find any documents
        // that exist in stale commit only.
        couchstore_walk_id_tree(db,
                                nullptr,
                                COUCHSTORE_TOLERATE_CORRUPTION,
                                rewind_hook,
                                &rewind_param);
        if (rewind_param.num_docs_recovered) {
            fprintf(stderr, "%" PRIu64 " documents recovered "
                    "from stale header #%zu.\n",
                    rewind_param.num_docs_recovered,
                    num_rewind);
            rq.total_num_docs_recovered += rewind_param.num_docs_recovered;
        }
    };

    if (!num_rewind) {
        fprintf(stderr, "No stale header to read.\n");
    }

    if (db) {
        couchstore_close_file(db);
        couchstore_free_db(db);
    }
}

static int recover_file(recovery_options& options) {
    fprintf(stderr, "Recover from file %s to file %s\n",
            options.src_filename.c_str(),
            options.dst_filename.c_str());

    if (options.src_filename == options.dst_filename) {
        // Both filenames shouldn't be the same.
        usage();
    }

    // Source (may be corrupted) DB.
    Db *db_src = nullptr;
    // DB after recovery.
    Db *db_recovered = nullptr;
    // Another handle for source DB.
    Db *db_src_alt = nullptr;

    couchstore_error_t errcode;
    couchstore_error_t errcode_compaction;
    bool error_detected = false;

    recover_file_hook_param param;
    param.options = &options;

    // Open source file.
    error_pass(couchstore_open_db_ex(options.src_filename.c_str(),
                                     COUCHSTORE_OPEN_FLAG_RDONLY,
                                     {},
                                     couchstore_get_default_file_ops(),
                                     &db_src));

    // Open source file for rewind.
    error_pass(couchstore_open_db_ex(options.src_filename.c_str(),
                                     COUCHSTORE_OPEN_FLAG_RDONLY,
                                     {},
                                     couchstore_get_default_file_ops(),
                                     &db_src_alt));
    param.db_src = db_src_alt;

    // Compact with recovery mode.
    errcode_compaction =
            couchstore_compact_db_ex(db_src,
                                     options.dst_filename.c_str(),
                                     COUCHSTORE_COMPACT_RECOVERY_MODE,
                                     {},
                                     recover_file_hook,
                                     nullptr,
                                     &param,
                                     couchstore_get_default_file_ops());

    // Open recovered file.
    errcode = couchstore_open_db_ex(options.dst_filename.c_str(),
                                    0x0,
                                    {},
                                    couchstore_get_default_file_ops(),
                                    &db_recovered);
    DbInfo dbinfo;
    couchstore_db_info(db_recovered, &dbinfo);

    if (errcode_compaction == COUCHSTORE_SUCCESS) {
        fprintf(stderr, "No corruption detected in index.\n");
    } else {
        fprintf(stderr,
                "Corrupted index node detected "
                "(error code %d, %s).\n",
                errcode_compaction,
                couchstore_strerror(errcode_compaction));
        error_detected = true;
    }
    fprintf(stderr, "Total %" PRIu64 " documents are referred to by index.\n",
            param.num_visited_docs);

    if (param.num_corrupted_docs) {
        fprintf(stderr, "Total %" PRIu64 " documents corrupted.\n",
                param.num_corrupted_docs);
        error_detected = true;
    } else {
        fprintf(stderr, "No corruption detected in documents.\n");
    }

    fprintf(stderr, "Total %" PRIu64 " documents recovered.\n",
            dbinfo.doc_count);

    // If error detected, and flag is set, traverse stale commits.
    if (error_detected && options.enable_rewind) {
        rewind_request rwrq;
        rwrq.options = &options;
        rwrq.db_recovered = db_recovered;
        rwrq.db_src = db_src_alt;

        fprintf(stderr,
                "We are going to recover missing documents "
                "from stale commits..\n");
        rewind_and_get_stale_data(rwrq);

        if (rwrq.total_num_docs_recovered) {
            fprintf(stderr,
                    "Total %" PRIu64 " documents recovered "
                    "from stale headers.\n",
                    rwrq.total_num_docs_recovered);
            error_pass(couchstore_commit(db_recovered));
        }
    }

cleanup:
    if (db_src) {
        couchstore_close_file(db_src);
        couchstore_free_db(db_src);
    }
    if (db_recovered) {
        couchstore_close_file(db_recovered);
        couchstore_free_db(db_recovered);
    }
    if (db_src_alt) {
        couchstore_close_file(db_src_alt);
        couchstore_free_db(db_src_alt);
    }

    return errcode;
}

int main(int argc, char** argv) {
    const std::vector<option> long_options = {
            {"stale", no_argument, nullptr, 's'},
            {"verbose", no_argument, nullptr, 'v'},
            {"json", no_argument, nullptr, 'j'},
            {nullptr, 0, nullptr, 0}};

    recovery_options options;
    int opt;

    while ((opt = getopt_long(
                    argc, argv, "svj", long_options.data(), nullptr)) != -1) {
        switch (opt) {
        case 's': // stale
            options.enable_rewind = true;
            break;
        case 'v': // verbose
            options.verbose_msg = true;
            break;
        case 'j': // json
            options.json = true;
            break;

        default:
            usage();
        }
    }

    if (argc - optind < 1) {
        // After option fields, one or two more fields
        // (for src/dst files) should exist.
        usage();
    }

    options.src_filename = argv[optind];
    if (argc - optind == 1) {
        // Destination file name is not given, automatically set it.
        options.dst_filename = options.src_filename + ".recovered";
    } else {
        options.dst_filename = argv[optind+1];
    }

    int errcode = recover_file(options);

    if (errcode == 0) {
        return EXIT_SUCCESS;
    } else {
        return EXIT_FAILURE;
    }
}
