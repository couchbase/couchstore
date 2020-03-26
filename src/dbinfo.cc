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

#include <getopt.h>
#include <inttypes.h>
#include <libcouchstore/couch_db.h>
#include <platform/string_hex.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <optional>

#include "internal.h"

static char *size_str(double size)
{
    static char rfs[256];
    int i = 0;
    const char *units[] = {"bytes", "kB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"};
    while (size > 1024) {
        size /= 1024;
        i++;
    }
    snprintf(rfs, sizeof(rfs), "%.*f %s", i, size, units[i]);
    return rfs;
}

static void print_db_info(Db* db)
{
    DbInfo info;
    couchstore_db_info(db, &info);
    printf("   doc count: %" PRIu64 "\n", info.doc_count);
    printf("   deleted doc count: %" PRIu64 "\n", info.deleted_count);
    printf("   data size: %s\n", size_str(info.space_used));
}

static int process_file(const char* file,
                        int iterate_headers,
                        const std::optional<cs_off_t>& header_offset) {
    Db *db;
    couchstore_error_t errcode;
    const char* crc_strings[3] = {"warning crc is set to unknown",
                                  "CRC-32",
                                  "CRC-32C"};

    errcode = couchstore_open_db(file, COUCHSTORE_OPEN_FLAG_RDONLY, &db);
    if (errcode != COUCHSTORE_SUCCESS) {
        fprintf(stderr, "Failed to open \"%s\": %s\n",
                file, couchstore_strerror(errcode));
        return -1;
    }

    if (header_offset) {
        errcode = cb::couchstore::seek(*db, header_offset.value());
        if (errcode != COUCHSTORE_SUCCESS) {
            fprintf(stderr,
                    "Failed to open \"%s\" at offset 0x%" PRIx64 ": %s\n",
                    file,
                    header_offset.value(),
                    couchstore_strerror(errcode));
            return -1;
        }
    }

    printf("DB Info (%s) - total disk size: %s\n\n",
           file,
           size_str(db->file.pos));

next_header:
    printf("Header at file offset %" PRIu64 "\n", db->header.position);
    printf("   file format version: %" PRIu64 "\n", db->header.disk_version);
    printf("   update_seq: %" PRIu64 "\n", db->header.update_seq);
    printf("   purge_seq: %" PRIu64 "\n", db->header.purge_seq);

    if (db->file.crc_mode < 3) {
        printf("   crc: %s\n", crc_strings[db->file.crc_mode]);
    } else {
        printf("   crc: warning crc_mode is out of range %" PRIu32 "\n",  db->file.crc_mode);
    }

    print_db_info(db);
    const auto id_tree_size =
            db->header.by_id_root ? db->header.by_id_root->subtreesize : 0;
    const auto seqno_tree_size =
            db->header.by_seq_root ? db->header.by_seq_root->subtreesize : 0;
    const auto local_tree_size =
            db->header.local_docs_root ? db->header.local_docs_root->subtreesize
                                       : 0;
    const auto btreesize = id_tree_size + seqno_tree_size + local_tree_size;

    printf("   B-tree size:       %s\n", size_str(btreesize));
    printf("   └── by-id tree:    %s\n", size_str(id_tree_size));
    printf("   └── by-seqno tree: %s\n", size_str(seqno_tree_size));
    printf("   └── local size:    %s\n", size_str(local_tree_size));
    if (iterate_headers) {
        if (couchstore_rewind_db_header(db) == COUCHSTORE_SUCCESS) {
            printf("\n");
            goto next_header;
        }
    } else {
        couchstore_close_file(db);
        couchstore_free_db(db);
    }

    return 0;
}

static void usage() {
    std::cerr << R"(Usage: couch_dbinfo [options] <file> [<file2> <file3>]
Options:
   -i / --iterate-headers         Dump all headers in the file
   -o / --header-offset <offset>  Specify the offset of the header to use
)";
    exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{
    int error = 0;
    int ii;
    int iterate_headers = getenv("ITERATE_HEADERS") != nullptr;
    int cmd;
    std::optional<cs_off_t> header_offset;

    struct option long_options[] = {
            {"header-offset", required_argument, nullptr, 'o'},
            {"iterate-headers", no_argument, nullptr, 'i'},
            {"help", no_argument, nullptr, '?'},
            {nullptr, 0, nullptr, 0}};

    while ((cmd = getopt_long(argc, argv, "io:", long_options, nullptr)) !=
           EOF) {
        switch (cmd) {
        case 'i':
            iterate_headers = 1;
            break;
        case 'o':
            if (strcmp(optarg, "0x") == 0) {
                header_offset.emplace(cb::from_hex(optarg));
            } else {
                header_offset.emplace(std::atoi(optarg));
            }
            break;
        default:
            usage();
            /* NOTREACHED */
        }
    }

    if (optind == argc) {
        usage();
    }

    for (ii = optind; ii < argc; ++ii) {
        error += process_file(argv[ii], iterate_headers, header_offset);
    }

    if (error) {
        exit(EXIT_FAILURE);
    } else {
        exit(EXIT_SUCCESS);
    }
}
