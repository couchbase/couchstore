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

#include "internal.h"

/**
 * Convert file offset to encryption nonce
 *
 * As data chunks are always appended to the end of the file, we use the
 * offset in the file as a unique value for the nonce. A chunk that appears
 * at the beginning of a block may be read from the block boundary or one
 * byte ahead, as the first byte of a block is the block type which will be
 * skipped over. To ensure that the same nonce is used for encryption and
 * decryption, we need to adjust the nonce such that it is the same in
 * those two cases. If the offset is at the block boundary, we increment
 * the nonce by one.
 */
static inline uint64_t offset2nonce(cs_off_t offset) {
    const auto nonce = gsl::narrow<uint64_t>(offset);
    return (nonce % COUCH_BLOCK_SIZE) ? nonce : nonce + 1;
}
