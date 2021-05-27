/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2021-Present Couchbase, Inc.
 *
 *   Use of this software is governed by the Business Source License included
 *   in the file licenses/BSL-Couchbase.txt.  As of the Change Date specified
 *   in that file, in accordance with the Business Source License, use of this
 *   software will be governed by the Apache License, Version 2.0, included in
 *   the file licenses/APL2.txt.
 */

#include "encoding.h"

#include "../bitfield.h"

#include <cstring>

void enc_uint16(uint16_t u, char** buf) {
    raw_16 k = encode_raw16(u);
    std::memcpy(*buf, &k, 2);
    *buf += 2;
}
