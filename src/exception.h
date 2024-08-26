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

#include <libcouchstore/couch_db.h>

#include <stdexcept>

namespace cb::couchstore {

class Exception : public std::runtime_error {
public:
    Exception(couchstore_error_t errcode, const char* what)
        : std::runtime_error(what), errcode(errcode) {
    }

    Exception(couchstore_error_t errcode, const std::string& what)
        : std::runtime_error(what), errcode(errcode) {
    }

    const couchstore_error_t errcode;
};

} // namespace cb::couchstore
