/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

#include "reductions.h"

#include "../bitfield.h"
#include "../couch_btree.h"

#include <platform/cb_malloc.h>
#include <stdlib.h>
#include <string.h>
#include <platform/cbassert.h>

#define BITMASK_BYTE_SIZE      (1024 / CHAR_BIT)

#define dec_uint16(b) (decode_raw16(*((raw_16 *) b)))
#define dec_uint48(b) (decode_raw48(*((raw_48 *) b)))
#define dec_uint40(b) (decode_raw40(*((raw_40 *) b)))

static void enc_uint16(uint16_t u, char **buf);

static void enc_raw40(uint64_t u, char **buf);

uint64_t decode_view_btree_reduction_partitions_bitmap(
        const char* bytes, size_t len, bitmap_t& partitions_bitmap) {
    cb_assert(len >= 5);
    uint64_t kv_count = dec_uint40(bytes);
    bytes += 5;
    len -= 5;

    cb_assert(len >= BITMASK_BYTE_SIZE);
    memcpy(&partitions_bitmap, bytes, BITMASK_BYTE_SIZE);
    return kv_count;
}

couchstore_error_t decode_view_btree_reduction(const char* bytes,
                                               size_t len,
                                               view_btree_reduction_t& r) {
    uint8_t  i, j;
    uint16_t sz;
    const char *bs;
    size_t length;

    // Get the count and bitmap and advance bytes
    r.kv_count = decode_view_btree_reduction_partitions_bitmap(
            bytes, len, r.partitions_bitmap);
    bytes += (5 + BITMASK_BYTE_SIZE);
    len -= (5 + BITMASK_BYTE_SIZE);

    bs = bytes;
    length = len;

    r.num_values = 0;
    size_t buffer_size = 0;
    while (len > 0) {

        cb_assert(len >= 2);
        sz = dec_uint16(bs);
        bs += 2;
        len -= 2;

        cb_assert(len >= sz);
        bs += sz;
        len -= sz;
        r.num_values++;
        buffer_size += sz;
    }

    if (len > 0) {
        return COUCHSTORE_ERROR_CORRUPT;
    }

    if (r.num_values > 0) {
        try {
            r.buffer.resize((r.num_values * sizeof(sized_buf)) + buffer_size);
        } catch (const std::bad_alloc&) {
            return COUCHSTORE_ERROR_ALLOC_FAIL;
        }
        r.reduce_values = reinterpret_cast<sized_buf*>(r.buffer.data());
    } else {
        return COUCHSTORE_SUCCESS;
    }

    for (j = 0; j < r.num_values; ++j) {
        r.reduce_values[j].buf = NULL;
    }

    i = 0;
    len = length;
    char* currentBuffer = r.buffer.data() + (r.num_values * sizeof(sized_buf));
    while (len > 0) {

        sz = dec_uint16(bytes);
        bytes += 2;
        len -= 2;

        r.reduce_values[i].size = sz;
        r.reduce_values[i].buf = currentBuffer;

        memcpy(r.reduce_values[i].buf, bytes, sz);
        bytes += sz;
        len -= sz;
        i++;
        currentBuffer += sz;
    }

    return COUCHSTORE_SUCCESS;
}

couchstore_error_t encode_view_btree_reduction(const view_btree_reduction_t *reduction,
                                               char *buffer,
                                               size_t *buffer_size)
{
    char *b = NULL;
    size_t sz = 0;
    int i;

    sz += 5;                     /* kv_count */
    sz += BITMASK_BYTE_SIZE; /* partitions bitmap */
    /* reduce values */
    for (i = 0; i < reduction->num_values; ++i) {
        sz += 2;             /* size_t */
        sz += reduction->reduce_values[i].size;
    }

    if (sz > MAX_REDUCTION_SIZE) {
        return COUCHSTORE_ERROR_REDUCTION_TOO_LARGE;
    }

    b = buffer;

    enc_raw40(reduction->kv_count, &b);

    memcpy(b, &reduction->partitions_bitmap, BITMASK_BYTE_SIZE);
    b += BITMASK_BYTE_SIZE;

    for (i = 0; i < reduction->num_values; ++i) {
        enc_uint16(reduction->reduce_values[i].size, &b);

        memcpy(b, reduction->reduce_values[i].buf, reduction->reduce_values[i].size);
        b += reduction->reduce_values[i].size;
    }

    *buffer_size = sz;

    return COUCHSTORE_SUCCESS;
}


void free_view_btree_reduction(view_btree_reduction_t *reduction)
{
    int i;

    if (reduction == NULL) {
        return;
    }

    if (reduction->reduce_values != NULL){
        for (i = 0; i < reduction->num_values; ++i) {
            cb_free(reduction->reduce_values[i].buf);
        }
        cb_free(reduction->reduce_values);
    }

    cb_free(reduction);
}


couchstore_error_t decode_view_id_btree_reduction(const char *bytes,
                                                  view_id_btree_reduction_t **reduction)
{
    view_id_btree_reduction_t *r = NULL;

    r = (view_id_btree_reduction_t *) cb_malloc(sizeof(view_id_btree_reduction_t));
    if (r == NULL) {
        goto alloc_error;
    }

    r->kv_count = dec_uint40(bytes);
    bytes += 5;

    memcpy(&r->partitions_bitmap, bytes, BITMASK_BYTE_SIZE);

    *reduction = r;

    return COUCHSTORE_SUCCESS;

 alloc_error:
    free_view_id_btree_reduction(r);
    return COUCHSTORE_ERROR_ALLOC_FAIL;
}


couchstore_error_t encode_view_id_btree_reduction(const view_id_btree_reduction_t *reduction,
                                                  char *buffer,
                                                  size_t *buffer_size)
{
    char *b = NULL;
    size_t sz = 0;

    sz += 5;                     /* kv_count */
    sz += BITMASK_BYTE_SIZE; /* partitions bitmap */

    if (sz > MAX_REDUCTION_SIZE) {
        return COUCHSTORE_ERROR_REDUCTION_TOO_LARGE;
    }

    b = buffer;

    enc_raw40(reduction->kv_count, &b);

    memcpy(b, &reduction->partitions_bitmap, BITMASK_BYTE_SIZE);

    *buffer_size = sz;

    return COUCHSTORE_SUCCESS;
}


void free_view_id_btree_reduction(view_id_btree_reduction_t *reduction)
{
    if (reduction == NULL) {
        return;
    }

    cb_free(reduction);
}

static void enc_uint16(uint16_t u, char **buf)
{
    raw_16 r = encode_raw16(u);
    memcpy(*buf, &r, 2);
    *buf += 2;
}


static void enc_raw40(uint64_t u, char **buf)
{
    raw_40 r;
    encode_raw40(u, &r);
    memcpy(*buf, &r, 5);
    *buf += 5;
}
