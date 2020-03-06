/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2015 Couchbase, Inc
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

/*
 * Checksum abstraction functions.
 *
 * Couchstore evolved to support a software CRC and platform's CRC32-C.
 * This module provides an API for checking and creating checksums
 * utilising the correct method based upon the callers crc_mode.
 */

#pragma once

#include <cstddef>
#include <cstdint>

typedef enum {
    CRC_UNKNOWN,
    CRC32,
    CRC32C
} crc_mode_e;

/*
 * Get a checksum of buf for buf_len bytes.
 *
 * mode = UNKNOWN is an invalid input (triggers assert).
 */
uint32_t get_checksum(const uint8_t* buf,
                      size_t buf_len,
                      crc_mode_e mode);

/*
 * Perform an integrity check of buf for buf_len bytes.
 *
 * A checksum of buf is created and compared against checksum argument.
 *
 * mode = UNKNOWN is an acceptable input. All modes are tried before failing.
 *
 * Returns 1 for success, 0 for failure.
 */
int perform_integrity_check(const uint8_t* buf,
                            size_t buf_len,
                            uint32_t checksum,
                            crc_mode_e mode);

/*
    client_hash_crc32 returns a hash which is the same as a couchbase client
    would e.g. when determining the vbucket from a key, this function would
    match the client's mapping.

    This hashes the key into 'hash', then does ((~hash) >> 16) & 0x7fff;
*/
uint32_t client_hash_crc32(const uint8_t* key, size_t key_length);
