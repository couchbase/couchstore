/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
//
//  node_types.c
//  couchstore
//
//  Created by Jens Alfke on 4/25/12.
//  Copyright (c) 2012 Couchbase, Inc. All rights reserved.
//

#include "node_types.h"

#include <platform/cb_malloc.h>
#include <cstring>

size_t read_kv(const void *buf, sized_buf *key, sized_buf *value)
{
    const raw_kv_length* kvlen = static_cast<const raw_kv_length*>(buf);
    uint32_t klen, vlen;
    decode_kv_length(kvlen, &klen, &vlen);
    key->size = klen;
    key->buf = (char*)(kvlen + 1);
    value->size = vlen;
    value->buf = key->buf + klen;
    return sizeof(raw_kv_length) + klen + vlen;
}

void* write_kv(void *buf, sized_buf key, sized_buf value)
{
    uint8_t *dst = static_cast<uint8_t*>(buf);
    *(raw_kv_length*)dst = encode_kv_length((uint32_t)key.size, (uint32_t)value.size);
    dst += sizeof(raw_kv_length);
    memcpy(dst, key.buf, key.size);
    dst += key.size;
    memcpy(dst, value.buf, value.size);
    dst += value.size;
    return dst;
}

node_pointer *read_root(void *buf, int size)
{
    if (size == 0) {
        return nullptr;
    }

    raw_btree_root *raw = (raw_btree_root*)buf;
    node_pointer *ptr;
    uint64_t position = decode_raw48(raw->pointer);
    uint64_t subtreesize = decode_raw48(raw->subtreesize);
    int redsize = size - sizeof(*raw);

    ptr = (node_pointer *) cb_malloc(sizeof(node_pointer) + redsize);
    if (redsize > 0) {
        buf = (char *) memcpy(ptr + 1, raw + 1, redsize);
    } else {
        buf = nullptr;
    }
    ptr->key.buf = nullptr;
    ptr->key.size = 0;
    ptr->pointer = position;
    ptr->subtreesize = subtreesize;
    ptr->reduce_value.buf = static_cast<char*>(buf);
    ptr->reduce_value.size = redsize;
    return ptr;
}

size_t encode_root(void *buf, node_pointer *node)
{
    if (!node) {
        return 0;
    }
    if (buf) {
        raw_btree_root *root = static_cast<raw_btree_root*>(buf);
        encode_raw48(node->pointer, &root->pointer);
        encode_raw48(node->subtreesize, &root->subtreesize);
        if (node->reduce_value.size > 0) {
            memcpy(root + 1, node->reduce_value.buf, node->reduce_value.size);
        }
    }
    return sizeof(raw_btree_root) + node->reduce_value.size;
}

void decode_kv_length(const raw_kv_length *kv, uint32_t *klen, uint32_t *vlen)
{
    /* 12, 28 bit */
    *klen = (uint16_t) ((kv->raw_kv[0] << 4) | ((kv->raw_kv[1] & 0xf0) >> 4));
    memcpy(vlen, &kv->raw_kv[1], 4);
    *vlen = ntohl(*vlen) & 0x0FFFFFFF;
}

raw_kv_length encode_kv_length(size_t klen, size_t vlen)
{
    raw_kv_length kv;
    uint32_t len = htonl((uint32_t)vlen);
    memcpy(&kv.raw_kv[1], &len, 4);
    kv.raw_kv[0] = (uint8_t)(klen >> 4);    /* upper 8 bits of klen */
    kv.raw_kv[1] |= (klen & 0xF) << 4;     /* lower 4 bits of klen in upper half of byte */
    return kv;
}

uint64_t decode_sequence_key(const sized_buf *buf)
{
    const raw_by_seq_key *key = (const raw_by_seq_key*)buf->buf;
    return decode_raw48(key->sequence);
}
