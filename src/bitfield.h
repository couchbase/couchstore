#pragma once

#include "couchstore_config.h"
#include "internal.h"
#include <string>

/*
 * Variable-width types. Since these are made out of chars they will be
 * byte-aligned, so structs consisting only of these will be packed.
 */

struct raw_08 {
    uint8_t raw_bytes[1];
};

struct raw_16 {
    uint8_t raw_bytes[2];
};

struct raw_24 {
    uint8_t raw_bytes[3];
};

struct raw_32 {
    uint8_t raw_bytes[4];
};

struct raw_40 {
    uint8_t raw_bytes[5];
};

struct raw_48 {
    uint8_t raw_bytes[6];
};

struct raw_64 {
    uint8_t raw_bytes[8];
};

/* Functions for decoding raw_xx types to native integers: */
#define encode_raw08(a) couchstore_encode_raw08(a)
#define encode_raw16(a) couchstore_encode_raw16(a)
#define encode_raw24(a, b) couchstore_encode_raw24(a, b)
#define encode_raw32(a) couchstore_encode_raw32(a)
#define encode_raw40(a, b) couchstore_encode_raw40(a, b)
#define encode_raw48(a, b) couchstore_encode_raw48(a, b)
#define encode_raw64(a) couchstore_encode_raw64(a)

#define decode_raw08(a) couchstore_decode_raw08(a)
#define decode_raw16(a) couchstore_decode_raw16(a)
#define decode_raw24(a) couchstore_decode_raw24p(&(a))
#define decode_raw32(a) couchstore_decode_raw32(a)
#define decode_raw40(a) couchstore_decode_raw40p(&(a))
#define decode_raw48(a) couchstore_decode_raw48p(&(a))
#define decode_raw64(a) couchstore_decode_raw64(a)

LIBCOUCHSTORE_API
uint8_t couchstore_decode_raw08(raw_08 raw);
LIBCOUCHSTORE_API
uint16_t couchstore_decode_raw16(raw_16 raw);
LIBCOUCHSTORE_API
uint32_t couchstore_decode_raw24p(const raw_24* raw);
LIBCOUCHSTORE_API
uint32_t couchstore_decode_raw32(raw_32 raw);
LIBCOUCHSTORE_API
uint64_t couchstore_decode_raw40p(const raw_40* raw);
LIBCOUCHSTORE_API
uint64_t couchstore_decode_raw48p(const raw_48* raw);
LIBCOUCHSTORE_API
uint64_t couchstore_decode_raw64(raw_64 raw);

/* Functions for encoding native integers to raw_xx types: */

LIBCOUCHSTORE_API
raw_08 couchstore_encode_raw08(uint8_t value);
LIBCOUCHSTORE_API
raw_16 couchstore_encode_raw16(uint16_t value);
LIBCOUCHSTORE_API
void couchstore_encode_raw24(uint32_t value, raw_24* raw);
LIBCOUCHSTORE_API
raw_32 couchstore_encode_raw32(uint32_t value);
LIBCOUCHSTORE_API
void couchstore_encode_raw40(uint64_t value, raw_40* raw);
LIBCOUCHSTORE_API
void couchstore_encode_raw48(uint64_t value, raw_48* raw);
LIBCOUCHSTORE_API
raw_64 couchstore_encode_raw64(uint64_t value);
