/*
**
**  node_types.h
**  couchstore
**
**  Created by Jens Alfke on 4/25/12.
**  Modified by Filipe Manana on 6/19/13 to fix some GCC warnings regarding
**  violation of strict aliasing rules.
**
**  Copyright (c) 2012 Couchbase, Inc. All rights reserved.
**
*/

#ifndef COUCHSTORE_NODE_TYPES_H
#define COUCHSTORE_NODE_TYPES_H

#include "bitfield.h"
#include "internal.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    raw_08 version;
    raw_48 update_seq;
    raw_48 purge_seq;
    raw_48 purge_ptr;
    raw_16 seqrootsize;
    raw_16 idrootsize;
    raw_16 localrootsize;
    /* Three variable-size raw_btree_root structures follow */
} raw_file_header_v12;
#ifdef __cplusplus
static_assert(sizeof(raw_file_header_v12) == 25, "Unexpected file header side");
#endif

typedef struct {
    raw_08 version;
    raw_48 update_seq;
    raw_48 purge_seq;
    raw_48 purge_ptr;
    raw_16 seqrootsize;
    raw_16 idrootsize;
    raw_16 localrootsize;
    raw_64 timestamp;
    /* Three variable-size raw_btree_root structures follow */
} raw_file_header_v13;
#ifdef __cplusplus
static_assert(sizeof(raw_file_header_v13) == 33, "Unexpected file header side");
#endif

typedef struct {
    raw_48 pointer;
    raw_48 subtreesize;
    /* Variable-size reduce value follows */
} raw_btree_root;

/** Packed key-and-value length type. Key length is 12 bits, value length is 28. */
typedef struct {
    uint8_t raw_kv[5];
} raw_kv_length;

typedef struct {
    raw_48 pointer;
    raw_48 subtreesize;
    raw_16 reduce_value_size;
    /* Variable-size reduce value follows */
} raw_node_pointer;

typedef struct {
    raw_48 sequence;
} raw_by_seq_key;

typedef struct {
    raw_48 db_seq;
    /* physical on-disk size of the value (including headers). */
    raw_32 physical_size;
    raw_48 bp;                 /* high bit is 'deleted' flag */
    raw_48 rev_seq;
    raw_08 content_meta;
    /* Variable-size rev_meta data follows */
} raw_id_index_value;

typedef struct {
    /* value length - physical on-disk size of the value (including headers). */
    raw_kv_length sizes;
    raw_48 bp;                 /* high bit is 'deleted' flag */
    raw_48 rev_seq;
    raw_08 content_meta;
    /* Variable-size id follows */
    /* Variable-size rev_meta data follows */
} raw_seq_index_value;

/* Mask for the 'deleted' bit in .bp fields */
#ifndef UINT64_C
#define UINT64_C(x) (x ## ULL)
#endif
#define BP_DELETED_FLAG UINT64_C(0x800000000000)


node_pointer *read_root(void *buf, int size);

size_t encode_root(void *buf, node_pointer *node);


/**
 * Reads a 12-bit key length and 28-bit value length, packed into 5 bytes big-endian.
 */
void decode_kv_length(const raw_kv_length *kv, uint32_t *klen, uint32_t *vlen);

/**
 * Returns an encoded 5-byte key/value length pair.
 */
raw_kv_length encode_kv_length(size_t klen, size_t vlen);

/**
 * Parses an in-memory buffer containing a 5-byte key/value length followed by key and value data,
 * and fills in sized_bufs to point to the key and data.
 * @return Number of bytes consumed from the buffer
 */
size_t read_kv(const void *buf, sized_buf *key, sized_buf *value);

void* write_kv(void *buf, sized_buf key, sized_buf value);


/**
 * Reads a 48-bit sequence number out of a sized_buf.
 */
uint64_t decode_sequence_key(const sized_buf *buf);

#ifdef __cplusplus
}
#endif

#endif
