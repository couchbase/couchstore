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

#include "bitfield.h"
#include <getopt.h>
#include <libcouchstore/couch_db.h>
#include <cstdio>
#include <cstdlib>
#include <iostream>

static void exit_error(couchstore_error_t errcode) {
    fprintf(stderr, "Couchstore error: %s\n", couchstore_strerror(errcode));
    exit(-1);
}

static void usage() {
    std::cerr << R"(Usage: couch_compact [options] <input file> <output file>
Options:
    -p / --purge-before <timestamp>
    -s / --purge-only-upto-seq <seq>
    -d / --dropdeletes
    -u / --upgrade
)";
    exit(-1);
}

typedef struct {
    raw_64 cas;
    raw_32 expiry;
    raw_32 flags;
} CouchbaseRevMeta;

static int time_purge_hook(Db* target, DocInfo* info, sized_buf, void* ctx_p) {
    auto* ctx = static_cast<time_purge_ctx*>(ctx_p);

    if (info == nullptr) {
        /* Compaction finished */
        target->header.purge_seq = ctx->max_purged_seq;
        return COUCHSTORE_SUCCESS;
    }

    if (info->deleted && info->rev_meta.size >= 16) {
        const auto* meta =
                reinterpret_cast<const CouchbaseRevMeta*>(info->rev_meta.buf);
        uint32_t exptime = decode_raw32(meta->expiry);
        if (exptime < ctx->purge_before_ts &&
            (!ctx->purge_before_seq || info->db_seq <= ctx->purge_before_seq)) {
            if (ctx->max_purged_seq < info->db_seq) {
                ctx->max_purged_seq = info->db_seq;
            }
            return COUCHSTORE_COMPACT_DROP_ITEM;
        }
    }

    return COUCHSTORE_COMPACT_KEEP_ITEM;
}

int main(int argc, char** argv) {
    Db* source;
    couchstore_error_t errcode;
    time_purge_ctx timepurge = {0, 0, 0};
    couchstore_compact_hook hook = nullptr;
    couchstore_docinfo_hook dhook = nullptr;
    void* hook_ctx = nullptr;
    couchstore_compact_flags flags = 0;
    FileOpsInterface* target_io_ops = couchstore_get_default_file_ops();
    if (argc < 3) {
        usage();
    }

    struct option long_options[] = {
            {"purge-before", required_argument, nullptr, 'p'},
            {"purge-only-upto-seq", required_argument, nullptr, 's'},
            {"dropdeletes", no_argument, nullptr, 'd'},
            {"upgrade", no_argument, nullptr, 'u'},
            {"help", no_argument, nullptr, '?'},
            {nullptr, 0, nullptr, 0}};

    int cmd;
    while ((cmd = getopt_long(argc, argv, "p:s:du", long_options, nullptr)) !=
           EOF) {
        switch (cmd) {
        case 'p':
            hook = time_purge_hook;
            hook_ctx = &timepurge;
            timepurge.purge_before_ts = std::stoi(optarg);
            printf("Purging items before timestamp %" PRIu64 "\n",
                   timepurge.purge_before_ts);
            break;
        case 's':
            timepurge.purge_before_seq = std::stoull(optarg);
            printf("Purging items only up-to seq %" PRIu64 "\n",
                   timepurge.purge_before_seq);
            break;
        case 'd':
            flags |= COUCHSTORE_COMPACT_FLAG_DROP_DELETES;
            break;
        case 'u':
            flags |= COUCHSTORE_COMPACT_FLAG_UPGRADE_DB;
            break;
        default:
            usage();
        }
    }

    if (optind + 2 > argc) {
        usage();
    }

    errcode = couchstore_open_db(
            argv[optind], COUCHSTORE_OPEN_FLAG_RDONLY, &source);
    if (errcode) {
        exit_error(errcode);
    }
    errcode = couchstore_compact_db_ex(source,
                                       argv[optind + 1],
                                       flags,
                                       hook,
                                       dhook,
                                       hook_ctx,
                                       target_io_ops);
    if (errcode) {
        exit_error(errcode);
    }

    printf("Compacted %s -> %s\n", argv[optind], argv[optind + 1]);

    errcode = couchstore_close_file(source);
    couchstore_free_db(source);
    if (errcode) {
        exit_error(errcode);
    }

    return 0;
}
