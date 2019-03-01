/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2019 Couchbase, Inc.
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

#include "config.h"
#include "internal.h"
#include "bitfield.h"

#include <platform/platform_socket.h>

/* Functions for decoding raw_xx types to native integers: */

#define DECODE_RAW(DST_TYPE, FLIP_FN)                                   \
    DST_TYPE value = 0;                                                 \
    memcpy((char*)&value + sizeof(value) - sizeof(raw), &(raw), sizeof(raw)); \
    return FLIP_FN(value)

#define DECODE_RAW_POINTER(DST_TYPE, FLIP_FN)                                   \
    DST_TYPE value = 0;                                                         \
    memcpy((char*)&value + sizeof(value) - sizeof(*rawp), rawp, sizeof(*rawp)); \
    return FLIP_FN(value)

LIBCOUCHSTORE_API
uint8_t couchstore_decode_raw08(raw_08 raw)
{
    return raw.raw_bytes[0];
}

LIBCOUCHSTORE_API
uint16_t couchstore_decode_raw16(raw_16 raw)
{
    DECODE_RAW(uint16_t, ntohs);
}

LIBCOUCHSTORE_API
uint32_t couchstore_decode_raw24p(const raw_24 *rawp)
{
    DECODE_RAW_POINTER(uint32_t, ntohl);
}

LIBCOUCHSTORE_API
uint32_t couchstore_decode_raw32(raw_32 raw)
{
    DECODE_RAW(uint32_t, ntohl);
}

LIBCOUCHSTORE_API
uint64_t couchstore_decode_raw40p(const raw_40 *rawp)
{
    DECODE_RAW_POINTER(uint64_t, ntohll);
}

LIBCOUCHSTORE_API
uint64_t couchstore_decode_raw48p(const raw_48 *rawp)
{
    DECODE_RAW_POINTER(uint64_t, ntohll);
}

LIBCOUCHSTORE_API
uint64_t couchstore_decode_raw64(raw_64 raw)
{
    DECODE_RAW(uint64_t, ntohll);
}


/* Functions for encoding native integers to raw_xx types: */

#define ENCODE_RAW(FLIP_FN, RAW_TYPE)                                   \
    RAW_TYPE raw;                                                       \
    value = FLIP_FN(value);                                             \
    memcpy(&raw, (char*)&value + sizeof(value) - sizeof(raw), sizeof(raw)); \
    return raw

#define ENCODE_RAW_POINTER(FLIP_FN, RAW_TYPE)                                   \
    value = FLIP_FN(value);                                             \
    memcpy(raw, (char*)&value + sizeof(value) - sizeof(*raw), sizeof(*raw)); \

LIBCOUCHSTORE_API
raw_08 couchstore_encode_raw08(uint8_t value)
{
    ENCODE_RAW((uint8_t), raw_08);
}

LIBCOUCHSTORE_API
raw_16 couchstore_encode_raw16(uint16_t value)
{
    ENCODE_RAW(htons, raw_16);
}

LIBCOUCHSTORE_API
void couchstore_encode_raw24(uint32_t value, raw_24 *raw)
{
    ENCODE_RAW_POINTER(htonl, raw_24);
}

LIBCOUCHSTORE_API
raw_32 couchstore_encode_raw32(uint32_t value)
{
    ENCODE_RAW(htonl, raw_32);
}

LIBCOUCHSTORE_API
void couchstore_encode_raw40(uint64_t value, raw_40 *raw)
{
    ENCODE_RAW_POINTER(htonll, raw_40);
}

LIBCOUCHSTORE_API
void couchstore_encode_raw48(uint64_t value, raw_48 *raw)
{
    ENCODE_RAW_POINTER(htonll, raw_48);
}

LIBCOUCHSTORE_API
raw_64 couchstore_encode_raw64(uint64_t value)
{
    ENCODE_RAW(htonll, raw_64);
}
