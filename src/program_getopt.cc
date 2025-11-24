/*
 *     Copyright 2024-Present Couchbase, Inc.
 *
 *   Use of this software is governed by the Business Source License included
 *   in the file licenses/BSL-Couchbase.txt.  As of the Change Date specified
 *   in that file, in accordance with the Business Source License, use of this
 *   software will be governed by the Apache License, Version 2.0, included in
 *   the file licenses/APL2.txt.
 */

#include "program_getopt.h"
#include <cbcrypto/dump_keys_runner.h>
#include <fmt/format.h>
#include <platform/getpass.h>

using cb::getopt::Argument;
using cb::getopt::Option;

namespace cb::couchstore {

ProgramGetopt::ProgramGetopt()
    : dumpKeysExecutable(DESTINATION_ROOT "/bin/dump-keys"),
      gosecrets(DESTINATION_ROOT "/var/lib/couchbase/config/gosecrets.cfg") {
    addOption({
            [this](auto value) { dumpKeysExecutable = std::string{value}; },
            "with-dump-keys",
            Argument::Required,
            "filename",
            fmt::format("The \"dump-keys\" binary to use (by default {}",
                        dumpKeysExecutable),
    });
    addOption({[this](auto value) { gosecrets = std::string{value}; },
               "with-gosecrets",
               Argument::Required,
               "filename",
               fmt::format("The location of gosecrets.cfg (by default {})",
                           gosecrets)});
    addOption({[this](auto value) {
                   if (value == "-") {
                       password = getpass();
                   } else {
                       password = std::string{value};
                   }
               },
               "password",
               Argument::Required,
               "password",
               "The password to use for authentication (use '-' to read from "
               "standard input)"});
    addOption({[](auto) {
                   fmt::println(stdout, "Couchbase Server {}", PRODUCT_VERSION);
                   std::exit(EXIT_SUCCESS);
               },
               "version",
               "Print program version and exit"});
}

void ProgramGetopt::addOption(Option option) {
    parser.addOption(std::move(option));
}

std::vector<std::string_view> ProgramGetopt::parse(
        int argc, char* const* argv, std::function<void()> error) const {
    return parser.parse(argc, argv, std::move(error));
}

void ProgramGetopt::usage(std::ostream& out) const {
    parser.usage(out);
}

cb::crypto::SharedKeyDerivationKey ProgramGetopt::lookup(std::string_view id) {
    if (id.empty()) {
        return keyStore.getActiveKey();
    }

    auto ret = keyStore.lookup(id);
    if (ret) {
        return ret;
    }

    auto dumpKeysRunner = cb::crypto::DumpKeysRunner::create(
            password, dumpKeysExecutable, gosecrets);
    auto key = dumpKeysRunner->lookup(id);
    if (key) {
        // add for later requests
        keyStore.add(key);
        // set it as the active key. This is useful if for command line
        // utilities which opens file A for reading and B for writing..
        // then they'll reuse the same key (will of course fail if they
        // open B before A.. that'll cause the file to be unencrypted...)
        keyStore.setActiveKey(key);
    }
    return key;
}

std::ostream& operator<<(std::ostream& os,
                         const ProgramGetopt& programOptions) {
    programOptions.usage(os);
    return os;
}

} // namespace cb::couchstore
