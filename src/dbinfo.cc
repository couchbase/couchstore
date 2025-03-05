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

#include <inttypes.h>
#include <libcouchstore/couch_db.h>
#include <platform/cbassert.h>
#include <platform/string_hex.h>
#include <platform/timeutils.h>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <optional>

#include "internal.h"
#include "program_getopt.h"

static cb::couchstore::ProgramGetopt program_options;

static bool format_timestamp = false;

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
                        const std::optional<cs_off_t>& header_offset,
                        cb::couchstore::Direction direction) {
    const char* crc_strings[3] = {"warning crc is set to unknown",
                                  "CRC-32",
                                  "CRC-32C"};

    auto [errcode, db] =
            cb::couchstore::openDatabase(file,
                                         COUCHSTORE_OPEN_FLAG_RDONLY,
                                         program_options.getKeyLookupFunction(),
                                         {},
                                         header_offset);
    if (errcode != COUCHSTORE_SUCCESS) {
        fprintf(stderr,
                "Failed to open \"%s\": %s\n",
                file,
                couchstore_strerror(errcode));
        return -1;
    }

    printf("DB Info (%s) - total disk size: %s\n",
           file,
           size_str(db->file.pos));
    if (db->file.crc_mode < 3) {
        printf("   crc: %s\n", crc_strings[db->file.crc_mode]);
    } else {
        printf("   crc: warning crc_mode is out of range %" PRIu32 "\n",
               db->file.crc_mode);
    }
    if (db->header.disk_version >= COUCH_DISK_VERSION_14) {
        std::string key;
        if (cb::couchstore::isEncrypted(*db)) {
            key = cb::couchstore::getEncryptionKeyId(*db);
        } else {
            key = cb::crypto::DataEncryptionKey::UnencryptedKeyId;
        }
        printf("   Encryption key: %s\n", key.c_str());
    }

    printf("\n");

next_header:
    printf("Header at file offset %" PRIu64 "\n", db->header.position);
    printf("   file format version: %" PRIu64 "\n", db->header.disk_version);
    printf("   update_seq: %" PRIu64 "\n", db->header.update_seq);
    printf("   purge_seq: %" PRIu64 "\n", db->header.purge_seq);

    if (db->header.disk_version >= COUCH_DISK_VERSION_13) {
        if (format_timestamp) {
            std::chrono::nanoseconds ns{db->header.timestamp};
            auto seconds = std::chrono::duration_cast<std::chrono::seconds>(ns);
            auto usec = std::chrono::duration_cast<std::chrono::microseconds>(
                    ns - seconds);
            auto dest = cb::time::timestamp(seconds.count(), usec.count());
            printf("   timestamp: %s\n", dest.c_str());
        } else {
            printf("   timestamp: %" PRIu64 "\n", db->header.timestamp);
        }
    }

    print_db_info(db.get());
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
        if (cb::couchstore::seek(*db, direction) == COUCHSTORE_SUCCESS) {
            printf("\n");
            goto next_header;
        }
    }

    return 0;
}

static void usage(int exitcode) {
    std::cerr << R"(Usage: couch_dbinfo [options] <file> [<file2> <file3>]

Options:

)" << program_options
              << std::endl
              << R"(
Note:
Unless --header-offset is specified the program selects the last
header block found in the file.)"
              << std::endl;
    std::exit(exitcode);
}

int main(int argc, char** argv) {
    int error = 0;
    int iterate_headers = getenv("ITERATE_HEADERS") != nullptr;
    std::optional<cs_off_t> header_offset;
    using cb::couchstore::Direction;
    Direction direction = Direction::Backward;

    program_options.addOption(
            {[&header_offset](auto value) {
                 if (value.rfind("0x") == 0) {
                     header_offset.emplace(cb::from_hex(value));
                 } else {
                     header_offset.emplace(std::stoi(std::string(value)));
                 }
             },
             'o',
             "header-offset",
             cb::getopt::Argument::Required,
             "<offset>",
             "Specify the offset of the header to use (may be combined with "
             "--iterate-header to iterate a subset of the file)."});

    program_options.addOption(
            {[&iterate_headers, &direction](auto value) {
                 iterate_headers = 1;
                 if (value == "forward") {
                     direction = Direction::Forward;
                 } else if (value == "backward") {
                     direction = Direction::Backward;
                 } else if (!value.empty()) {
                     std::cerr << "Invalid direction for --iterate-headers"
                               << std::endl;
                     usage(EXIT_FAILURE);
                 }
             },
             'i',
             "iterate-headers",
             cb::getopt::Argument::Optional,
             "<direction>",
             R"(Dump all headers in the file. Direction may be:
            forward   Going forward in history (oldest first, newest last)
            backward  Going back in history (newest first, oldest last))"});

    program_options.addOption(
            {[](auto) { format_timestamp = true; },
             'l',
             "localtime",
             "Assume that the timestamp in the headers is the number of ns "
             "since epoch and print it as a human readable form (local time)"});

    program_options.addOption(
            {[](auto) { usage(EXIT_SUCCESS); }, "help", "This help text "});

    auto arguments =
            program_options.parse(argc, argv, [] { usage(EXIT_FAILURE); });
    if (arguments.empty()) {
        usage(EXIT_FAILURE);
    }

    for (const auto& arg : arguments) {
        error |= process_file(std::string(arg).c_str(),
                              iterate_headers,
                              header_offset,
                              direction);
    }

    if (error) {
        exit(EXIT_FAILURE);
    }
    exit(EXIT_SUCCESS);
}
