/*
 *     Copyright 2024-Present Couchbase, Inc.
 *
 *   Use of this software is governed by the Business Source License included
 *   in the file licenses/BSL-Couchbase.txt.  As of the Change Date specified
 *   in that file, in accordance with the Business Source License, use of this
 *   software will be governed by the Apache License, Version 2.0, included in
 *   the file licenses/APL2.txt.
 */

#pragma once

#include <cbcrypto/common.h>
#include <cbcrypto/key_store.h>
#include <platform/command_line_options_parser.h>

namespace cb::couchstore {

class ProgramGetopt {
public:
    ProgramGetopt();

    /**
     * Add a command line option to the list of command line options
     * to accept
     */
    void addOption(getopt::Option option);

    /**
     * Parse the command line options and call the callbacks for all
     * options found.
     *
     * @param argc argument count
     * @param argv argument vector
     * @param error an error callback for unknown options
     */
    [[nodiscard]] std::vector<std::string_view> parse(
            int argc, char* const* argv, std::function<void()> error) const;

    /// Print the common command line options to the output stream
    void usage(std::ostream& out) const;

    /// Get a lookup function which cache the result of key lookup
    [[nodiscard]] std::function<
            crypto::SharedKeyDerivationKey(std::string_view)>
    getKeyLookupFunction() {
        return [this](std::string_view id) { return lookup(id); };
    }

protected:
    /// Look up the provided key id (and cache it for later use)
    [[nodiscard]] crypto::SharedKeyDerivationKey lookup(std::string_view id);

    getopt::CommandLineOptionsParser parser;
    std::string dumpKeysExecutable;
    std::string password;
    std::string gosecrets;
    crypto::KeyStore keyStore;
};

std::ostream& operator<<(std::ostream& os, const ProgramGetopt& programOptions);

} // namespace cb::couchstore
