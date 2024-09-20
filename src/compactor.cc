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
#include "program_getopt.h"

#include <fmt/format.h>
#include <libcouchstore/couch_db.h>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <iostream>

static cb::couchstore::ProgramGetopt program_options;

static void exit_error(couchstore_error_t errcode) {
    fprintf(stderr, "Couchstore error: %s\n", couchstore_strerror(errcode));
    exit(-1);
}

static void usage(int exitcode) {
    std::cerr << R"(Usage: couch_compact [options] <input file> <output file>

Options:

)" << program_options
              << std::endl
              << std::endl;
    std::exit(exitcode);
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

    program_options.addOption(
            {[&hook, &hook_ctx, &timepurge](auto value) {
                 hook = time_purge_hook;
                 hook_ctx = &timepurge;
                 timepurge.purge_before_ts = std::stoi(std::string(value));
                 printf("Purging items before timestamp %" PRIu64 "\n",
                        timepurge.purge_before_ts);
             },
             'p',
             "purge-before",
             cb::getopt::Argument::Required,
             "<timestamp>",
             "Purge items before timestamp"});

    program_options.addOption(
            {[&timepurge](auto value) {
                 timepurge.purge_before_seq = std::stoull(std::string(value));
                 printf("Purging items only up-to seq %" PRIu64 "\n",
                        timepurge.purge_before_seq);
             },
             's',
             "purge-only-upto-seq",
             cb::getopt::Argument::Required,
             "<seq>",
             "Purge items only up to provided sequence number"});

    program_options.addOption(
            {[&flags](auto) { flags |= COUCHSTORE_COMPACT_FLAG_DROP_DELETES; },
             'd',
             "dropdeletes",
             "Drop deletes as part of compaction"});

    program_options.addOption(
            {[&flags](auto) { flags |= COUCHSTORE_COMPACT_FLAG_UPGRADE_DB; },
             'u',
             "upgrade",
             "Upgrade to latest version of file format"});

    program_options.addOption(
            {[](auto) { usage(EXIT_SUCCESS); }, "help", "This help text "});

    auto arguments =
            program_options.parse(argc, argv, [] { usage(EXIT_FAILURE); });
    if (arguments.size() != 2) {
        usage(EXIT_FAILURE);
    }

    errcode = couchstore_open_db_ex(std::string(arguments[0]).c_str(),
                                    COUCHSTORE_OPEN_FLAG_RDONLY,
                                    program_options.getKeyLookupFunction(),
                                    couchstore_get_default_file_ops(),
                                    &source);
    if (errcode) {
        exit_error(errcode);
    }
    errcode = couchstore_compact_db_ex(source,
                                       std::string(arguments[1]).c_str(),
                                       flags,
                                       program_options.getKeyLookupFunction(),
                                       hook,
                                       dhook,
                                       hook_ctx,
                                       couchstore_get_default_file_ops());
    if (errcode) {
        exit_error(errcode);
    }

    fmt::println("Compacted {} -> {}", arguments[0], arguments[1]);

    errcode = couchstore_close_file(source);
    couchstore_free_db(source);
    if (errcode) {
        exit_error(errcode);
    }

    return 0;
}
