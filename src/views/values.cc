/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

#include "values.h"

#include "../bitfield.h"
#include "encoding.h"

#include <platform/cb_malloc.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <platform/cbassert.h>

#define dec_uint16(b) (decode_raw16(*((raw_16*)b)))
#define dec_raw24(b) (decode_raw24(*((raw_24 *) b)))

static void enc_raw24(uint32_t u, char **buf);

couchstore_error_t decode_view_btree_value(const char* bytes,
                                           size_t len,
                                           view_btree_value_t& v) {
    auto info = decode_view_btree_partition_and_num_values(bytes, len);
    v.values = nullptr;
    v.partition = info.partition;
    v.num_values = info.num_values;

    // advance bytes past the partition which is no longer needed.
    bytes += 2;
    len -= 2;

    // One allocation to use for all the data which will be split into two.
    // First area is an array of sized_buf and then each sized_buf points
    // into the second area for its data. Only size if we need more for this
    // decode.
    if (v.values_buf.size() <
        info.total_sizeof_values + (v.num_values * sizeof(sized_buf))) {
        try {
            v.values_buf.resize(info.total_sizeof_values +
                                v.num_values * sizeof(sized_buf));
        } catch (const std::bad_alloc&) {
            return COUCHSTORE_ERROR_ALLOC_FAIL;
        }
    }

    v.values = reinterpret_cast<sized_buf*>(v.values_buf.data());

    int i = 0;
    auto* sized_buf_area =
            v.values_buf.data() + (v.num_values * sizeof(sized_buf));
    while (len > 0) {
        uint32_t sz = dec_raw24(bytes);
        bytes += 3;
        len -= 3;

        v.values[i].size = sz;
        v.values[i].buf = (char*)sized_buf_area;
        sized_buf_area += sz;

        memcpy(v.values[i].buf, bytes, sz);
        bytes += sz;
        len -= sz;
        i++;
    }

    return COUCHSTORE_SUCCESS;
}

uint16_t decode_view_btree_partition(const char* bytes, size_t len) {
    cb_assert(len >= 2);
    return dec_uint16(bytes);
}

partition_and_value_info decode_view_btree_partition_and_num_values(
        const char* bytes, size_t len) {
    uint16_t partition = decode_view_btree_partition(bytes, len);
    bytes += 2;
    len -= 2;

    // No values to decode
    if (len == 0) {
        return {partition, 0};
    }

    uint16_t num_values = 0;
    size_t total_value_size = 0;
    // scan the input bytes and figure out how many values and the accumulative
    // size of them
    while (len > 0) {
        cb_assert(len >= 3);
        auto sz = dec_raw24(bytes);
        bytes += 3;
        len -= 3;

        cb_assert(len >= sz);
        bytes += sz;
        len -= sz;
        num_values++;
        total_value_size += sz;
    }

    return {partition, num_values, total_value_size};
}

couchstore_error_t encode_view_btree_value(const view_btree_value_t *value,
                                           char **buffer,
                                           size_t *buffer_size)
{
    char *buf = nullptr, *b = nullptr;
    uint16_t i;
    size_t sz = 0;

    sz += 2;                 /* partition */
    /* values */
    for (i = 0; i < value->num_values; ++i) {
        sz += 3;             /* json value length */
        sz += value->values[i].size;
    }

    b = buf = (char *) cb_malloc(sz);
    if (buf == nullptr) {
        goto alloc_error;
    }

    enc_uint16(value->partition, &b);

    for (i = 0; i < value->num_values; ++i) {
        enc_raw24(value->values[i].size, &b);

        memcpy(b, value->values[i].buf, value->values[i].size);
        b += value->values[i].size;
    }

    *buffer = buf;
    *buffer_size = sz;

    return COUCHSTORE_SUCCESS;

 alloc_error:
    cb_free(buf);
    *buffer = nullptr;
    *buffer_size = 0;
    return COUCHSTORE_ERROR_ALLOC_FAIL;
}

couchstore_error_t decode_view_id_btree_value(const char *bytes,
                                              size_t len,
                                              view_id_btree_value_t **value)
{
    view_id_btree_value_t* v = nullptr;
    uint16_t i, j, num_keys;
    const char *bs;
    size_t sz, length;

    v = (view_id_btree_value_t *) cb_malloc(sizeof(view_id_btree_value_t));
    if (v == nullptr) {
        goto alloc_error;
    }

    v->view_keys_map = nullptr;

    cb_assert(len >= 2);
    v->partition = dec_uint16(bytes);
    bytes += 2;
    len -= 2;

    // No values to decode
    if (len == 0) {
        *value = v;
        return COUCHSTORE_SUCCESS;
    }

    bs = bytes;
    length = len;

    v->num_view_keys_map = 0;
    while (len > 0) {

        cb_assert(len >= 1);
        bs += 1; /* view_id */
        len -= 1;

        cb_assert(len >= 2);
        num_keys = dec_uint16(bs);
        bs +=2;
        len -= 2;

        for (j = 0; j < num_keys; ++j) {

            cb_assert(len >= 2);
            sz = dec_uint16(bs);
            bs += 2;
            len -= 2;

            cb_assert(len >= sz);
            bs += sz;
            len -= sz;
        }

        v->num_view_keys_map++;
    }

    if (len > 0) {
        free_view_id_btree_value(v);
        return COUCHSTORE_ERROR_CORRUPT;
    }

    v->view_keys_map = (view_keys_mapping_t *) cb_malloc(v->num_view_keys_map *
                                                     sizeof(view_keys_mapping_t));

    if (v->view_keys_map == nullptr) {
        goto alloc_error;
    }

    for (j = 0; j< v->num_view_keys_map; ++j) {
        v->view_keys_map[j].json_keys = nullptr;
    }

    i = 0;
    len = length;
    while (len > 0) {

        v->view_keys_map[i].view_id = bytes[0];
        bytes += 1;
        len -= 1;

        num_keys = dec_uint16(bytes);
        v->view_keys_map[i].num_keys = num_keys;
        bytes += 2;
        len -= 2;

        v->view_keys_map[i].json_keys = (sized_buf *) cb_malloc(num_keys * sizeof(sized_buf));
        if (v->view_keys_map[i].json_keys == nullptr) {
            goto alloc_error;
        }

        for (j = 0; j< num_keys; ++j) {
            v->view_keys_map[i].json_keys[j].buf = nullptr;
        }

        for ( j = 0; j < num_keys; ++j) {

            sz = dec_uint16(bytes);
            bytes += 2;
            len -= 2;

            v->view_keys_map[i].json_keys[j].size = sz;
            v->view_keys_map[i].json_keys[j].buf = (char *) cb_malloc(sz);

            if (v->view_keys_map[i].json_keys[j].buf == nullptr) {
                goto alloc_error;
            }

            memcpy(v->view_keys_map[i].json_keys[j].buf, bytes, sz);
            bytes += sz;
            len -= sz;
        }

        i++;
    }

    *value = v;

    return COUCHSTORE_SUCCESS;

 alloc_error:
    free_view_id_btree_value(v);
    return COUCHSTORE_ERROR_ALLOC_FAIL;
}


couchstore_error_t encode_view_id_btree_value(const view_id_btree_value_t *value,
                                              char **buffer,
                                              size_t *buffer_size)
{
    char *buf = nullptr, *b = nullptr;
    size_t sz = 0;
    uint16_t i, j;

    sz += 2;                 /* partition */

    /* view_keys_mappings */

    for (i = 0; i < value->num_view_keys_map; ++i) {
        sz += 1;            /*view_id */
        sz += 2;
        for (j = 0; j < value->view_keys_map[i].num_keys; ++j) {
            sz += 2;        /* size_t */
            sz += value->view_keys_map[i].json_keys[j].size;
        }
    }

    b = buf = (char *) cb_malloc(sz);
    if (buf == nullptr) {
        goto alloc_error;
    }

    enc_uint16(value->partition, &b);

    for (i = 0; i < value->num_view_keys_map; ++i) {

        b[0] = value->view_keys_map[i].view_id;
        b += 1;

        enc_uint16(value->view_keys_map[i].num_keys, &b);

        for (j = 0; j < value->view_keys_map[i].num_keys; ++j) {

            enc_uint16(value->view_keys_map[i].json_keys[j].size, &b);

            memcpy(b, value->view_keys_map[i].json_keys[j].buf,
                    value->view_keys_map[i].json_keys[j].size);
            b += value->view_keys_map[i].json_keys[j].size;

        }
    }

    *buffer = buf;
    *buffer_size = sz;

    return COUCHSTORE_SUCCESS;

 alloc_error:
    cb_free(buf);
    *buffer = nullptr;
    *buffer_size = 0;
    return COUCHSTORE_ERROR_ALLOC_FAIL;
}


void free_view_id_btree_value(view_id_btree_value_t *value)
{
    int i;
    int j;

    if (value == nullptr) {
        return;
    }

    if (value->view_keys_map != nullptr) {
        for (i = 0; i < value->num_view_keys_map; ++i) {
            if (value->view_keys_map[i].json_keys != nullptr) {
                for (j = 0; j <value->view_keys_map[i].num_keys; ++j) {
                    cb_free(value->view_keys_map[i].json_keys[j].buf);
                }

                cb_free(value->view_keys_map[i].json_keys);
            }
        }

        cb_free(value->view_keys_map);
    }

    cb_free(value);
}

static void enc_raw24(uint32_t u, char **buf)
{
    raw_24 v;
    encode_raw24(u, &v);
    memcpy(*buf, &v, 3);
    *buf += 3;
}
