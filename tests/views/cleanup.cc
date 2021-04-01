/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

/**
 * @copyright 2013 Couchbase, Inc.
 *
 * @author Sarath Lakshman  <sarath@couchbase.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 **/

#include "view_tests.h"
#include "../src/couch_btree.h"

#include <platform/cb_malloc.h>
#include <platform/cbassert.h>

static void test_view_id_btree_cleanup()
{
    sized_buf valbuf;
    view_purger_ctx_t purge_ctx;
    view_id_btree_value_t data1;
    char* data_bin1 = nullptr;
    size_t data_bin1_size = 0;
    view_id_btree_reduction_t reduction1;
    char reduction_bin1[512];
    size_t reduction_bin1_size = 0;
    node_pointer np;

    set_bit(&purge_ctx.cbitmask, 64);

    /* Purge kv tests */
    data1.partition = 64;
    data1.num_view_keys_map = 1;
    data1.view_keys_map = (view_keys_mapping_t *) cb_malloc(sizeof(view_keys_mapping_t));
    cb_assert(data1.view_keys_map != nullptr);
    data1.view_keys_map[0].view_id = 0;
    data1.view_keys_map[0].num_keys = 1;
    data1.view_keys_map[0].json_keys = (sized_buf *) cb_malloc(sizeof(sized_buf));
    data1.view_keys_map[0].json_keys[0].buf = (char*)"100";
    data1.view_keys_map[0].json_keys[0].size = sizeof("100") - 1;
    cb_assert(encode_view_id_btree_value(&data1, &data_bin1, &data_bin1_size) == COUCHSTORE_SUCCESS);
    valbuf.buf = data_bin1;
    valbuf.size = data_bin1_size;

    cb_assert(view_id_btree_purge_kv(nullptr, &valbuf, &purge_ctx) ==
              PURGE_ITEM);
    cb_assert(purge_ctx.count == 1);
    cb_free(data_bin1);
    data1.partition = 32;
    cb_assert(encode_view_id_btree_value(&data1, &data_bin1, &data_bin1_size) == COUCHSTORE_SUCCESS);
    valbuf.buf = data_bin1;
    valbuf.size = data_bin1_size;
    purge_ctx.count = 0;
    cb_assert(view_id_btree_purge_kv(nullptr, &valbuf, &purge_ctx) ==
              PURGE_KEEP);
    cb_assert(purge_ctx.count == 0);
    cb_free(data_bin1);
    cb_free(data1.view_keys_map[0].json_keys);
    cb_free(data1.view_keys_map);

    /* Purge kp tests */
    reduction1.kv_count = 11;

    cb_assert(encode_view_id_btree_reduction(&reduction1, reduction_bin1, &reduction_bin1_size) == COUCHSTORE_SUCCESS);
    np.reduce_value.buf = reduction_bin1;
    np.reduce_value.size = reduction_bin1_size;

    cb_assert(view_id_btree_purge_kp(&np, &purge_ctx) == PURGE_KEEP);
    cb_assert(purge_ctx.count == 0);

    set_bit(&reduction1.partitions_bitmap, 64);
    cb_assert(encode_view_id_btree_reduction(&reduction1, reduction_bin1, &reduction_bin1_size) == COUCHSTORE_SUCCESS);
    np.reduce_value.buf = reduction_bin1;
    np.reduce_value.size = reduction_bin1_size;

    cb_assert(view_id_btree_purge_kp(&np, &purge_ctx) == PURGE_ITEM);
    cb_assert(purge_ctx.count == 11);
    purge_ctx.count = 0;

    set_bit(&reduction1.partitions_bitmap, 100);
    cb_assert(encode_view_id_btree_reduction(&reduction1, reduction_bin1, &reduction_bin1_size) == COUCHSTORE_SUCCESS);
    np.reduce_value.buf = reduction_bin1;
    np.reduce_value.size = reduction_bin1_size;

    cb_assert(view_id_btree_purge_kp(&np, &purge_ctx) == PURGE_PARTIAL);
    cb_assert(purge_ctx.count == 0);
}

static void test_view_btree_cleanup()
{
    sized_buf valbuf;
    view_purger_ctx_t purge_ctx;
    view_btree_value_t value1;
    char* value_bin1 = nullptr;
    size_t value_bin1_size = 0;
    view_btree_reduction_t reduction1;
    char reduction_bin1[512];
    size_t reduction_bin1_size = 0;
    node_pointer np;

    set_bit(&purge_ctx.cbitmask, 64);

    /* Purge KV tests */
    value1.partition = 64;
    value1.num_values = 2;
    value1.values = (sized_buf *) cb_malloc(sizeof(sized_buf) * 2);
    value1.values[0].buf = (char*)"100";
    value1.values[0].size = sizeof("100") - 1;
    value1.values[1].buf = (char*)"1";
    value1.values[1].size = sizeof("1") - 1;
    cb_assert(encode_view_btree_value(&value1, &value_bin1, &value_bin1_size) == COUCHSTORE_SUCCESS);

    valbuf.buf = value_bin1;
    valbuf.size = value_bin1_size;

    cb_assert(view_btree_purge_kv(nullptr, &valbuf, &purge_ctx) == PURGE_ITEM);
    cb_assert(purge_ctx.count == 2);
    purge_ctx.count = 0;
    cb_free(value_bin1);

    value1.partition = 100;
    cb_assert(encode_view_btree_value(&value1, &value_bin1, &value_bin1_size) == COUCHSTORE_SUCCESS);
    valbuf.buf = value_bin1;
    valbuf.size = value_bin1_size;

    cb_assert(view_btree_purge_kv(nullptr, &valbuf, &purge_ctx) == PURGE_KEEP);
    cb_assert(purge_ctx.count == 0);
    cb_free(value_bin1);
    cb_free(value1.values);

    /* Purge KP tests */
    reduction1.kv_count = 11;
    reduction1.num_values = 1;
    reduction1.reduce_values = (sized_buf *) cb_malloc(sizeof(sized_buf));
    reduction1.reduce_values[0].buf = (char*)"value";
    reduction1.reduce_values[0].size = sizeof("value") - 1;

    cb_assert(encode_view_btree_reduction(&reduction1, reduction_bin1, &reduction_bin1_size) == COUCHSTORE_SUCCESS);
    np.reduce_value.buf = reduction_bin1;
    np.reduce_value.size = reduction_bin1_size;

    cb_assert(view_btree_purge_kp(&np, &purge_ctx) == PURGE_KEEP);
    cb_assert(purge_ctx.count == 0);

    set_bit(&reduction1.partitions_bitmap, 64);
    cb_assert(encode_view_btree_reduction(&reduction1, reduction_bin1, &reduction_bin1_size) == COUCHSTORE_SUCCESS);
    np.reduce_value.buf = reduction_bin1;
    np.reduce_value.size = reduction_bin1_size;

    cb_assert(view_btree_purge_kp(&np, &purge_ctx) == PURGE_ITEM);
    cb_assert(purge_ctx.count == 11);
    purge_ctx.count = 0;

    set_bit(&reduction1.partitions_bitmap, 100);
    cb_assert(encode_view_btree_reduction(&reduction1, reduction_bin1, &reduction_bin1_size) == COUCHSTORE_SUCCESS);
    np.reduce_value.buf = reduction_bin1;
    np.reduce_value.size = reduction_bin1_size;

    cb_assert(view_btree_purge_kp(&np, &purge_ctx) == PURGE_PARTIAL);
    cb_assert(purge_ctx.count == 0);
    cb_free(reduction1.reduce_values);
}

void cleanup_tests(void)
{
    fprintf(stderr, "Running view id_btree cleanup tests ... \n");
    test_view_id_btree_cleanup();
    fprintf(stderr, "End of view id_btree cleanup tests ... \n");
    fprintf(stderr, "Running view btree cleanup tests ... \n");
    test_view_btree_cleanup();
    fprintf(stderr, "End of view btree cleanup tests ... \n");
}
