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
#include <libcouchstore/couch_db.h>
#include <platform/string_hex.h>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <iostream>

static void usage() {
    std::cerr << R"(Usage: pitr_compact [options] <input file> <output file>
Options:
    -o / --oldest <timestamp>  The timestamp of the oldest database to preserve
    -i / --increment <seq>     The increment between the timestamps to preserve
)";
    exit(-1);
}

uint64_t strToVal(const std::string& str) {
    if (str.find("0x") == 0) {
        return cb::from_hex(optarg);
    }
    return std::stoull(optarg);
}

int main(int argc, char** argv) {
    using std::chrono::minutes;
    using std::chrono::nanoseconds;

    uint64_t oldest = std::numeric_limits<uint64_t>::max();
    uint64_t increment = nanoseconds(minutes(1)).count();
    std::optional<uint64_t> header_offset;

    struct option long_options[] = {
            {"oldest", required_argument, nullptr, 'o'},
            {"increment", required_argument, nullptr, 'i'},
            {"header-offset", required_argument, nullptr, 'h'},
            {"help", no_argument, nullptr, '?'},
            {nullptr, 0, nullptr, 0}};

    int cmd;
    while ((cmd = getopt_long(argc, argv, "o:i:h:", long_options, nullptr)) !=
           EOF) {
        switch (cmd) {
        case 'o':
            oldest = strToVal(optarg);
            break;
        case 'i':
            increment = strToVal(optarg);
            break;
        case 'h':
            header_offset.emplace(strToVal(optarg));
            break;
        default:
            usage();
        }
    }

    if (optind + 2 > argc) {
        usage();
    }

    auto [status, source] = cb::couchstore::openDatabase(
            argv[optind], COUCHSTORE_OPEN_FLAG_RDONLY, {}, header_offset);
    if (status != COUCHSTORE_SUCCESS) {
        std::cerr << "Failed to open " << argv[optind] << ": "
                  << couchstore_strerror(status) << std::endl;
        exit(EXIT_FAILURE);
    }

    std::cout << "Destination: " << argv[optind + 1] << std::endl;

    ::remove(argv[optind + 1]);
    try {
        status = cb::couchstore::compact(*source,
                                         argv[optind + 1],
                                         COUCHSTORE_OPEN_FLAG_UNBUFFERED,
                                         {},
                                         {},
                                         {},
                                         {},
                                         oldest,
                                         increment,
                                         {},
                                         {},
                                         {},
                                         {});
    } catch (const std::runtime_error& error) {
        std::cerr << "Compaction failed: " << error.what() << std::endl;
        exit(EXIT_FAILURE);
    }

    if (status != COUCHSTORE_SUCCESS) {
        std::cerr << "Failed to compact " << argv[optind] << ": "
                  << couchstore_strerror(status) << std::endl;
        exit(EXIT_FAILURE);
    }

    std::cout << "Compaction successful" << std::endl;

    return 0;
}
