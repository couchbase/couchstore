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

#include "couchstore_config.h"
#include "../../src/couch_btree.h"
#include "../macros.h"
#include "purge_tests.h"
#include <libcouchstore/couch_db.h>
#include <platform/cb_malloc.h>
#include <platform/cbassert.h>
#include <stdlib.h>
#include <string.h>

char testpurgefile[1024] = "purge.couch";
typedef couchstore_error_t (*fetch_callback_fn)(couchfile_lookup_request *,
                                                const sized_buf *,
                                                const sized_buf *);
/* Compare helper function */
static int int_cmp(const sized_buf *a, const sized_buf *b)
{

    if (!a->size || !b->size) {
        return 0;
    }

    return *((int *) a->buf) - *((int *) b->buf);
}

/* Read a field from reduce value */
static int red_intval(const node_pointer *ptr, int i)
{
    sized_buf red;
    red.size = 0;

    if (ptr) {
        red = ptr->reduce_value;
    }

    if (red.size) {
        return *((int *) red.buf + i);
    }

    return 0;
}

/* Reduction functions */
static couchstore_error_t count_reduce(char *dst, size_t *size_r,
                                                const nodelist *leaflist,
                                                int count, void *ctx)
{
    int *dst_count = (int *) dst;
    (void) leaflist;
    (void) size_r;
    (void) ctx;

    *dst_count = count;
    *size_r = sizeof(count);

    return COUCHSTORE_SUCCESS;
}

static couchstore_error_t count_rereduce(char *dst, size_t *size_r,
                                                    const nodelist *ptrlist,
                                                    int count,
                                                    void *ctx)
{
    int total = 0;
    int *dst_count = (int *) dst;
    const nodelist *i = ptrlist;
    (void) size_r;
    (void) ctx;

    while (i != NULL && count > 0) {
        const int *reduce = (const int *) i->pointer->reduce_value.buf;
        total += *reduce;
        i = i->next;
        count--;
    }

    *dst_count = total;
    *size_r = sizeof(total);

    return COUCHSTORE_SUCCESS;
}

static couchstore_error_t evenodd_reduce(char *dst, size_t *size_r,
                                                    const nodelist *leaflist,
                                                    int count,
                                                    void *ctx)
{
    int *evenodd = (int *) dst;
    int E = 0, O = 0;
    int *val;

    (void) size_r;
    (void) ctx;

    while (count--) {
        val = (int *) leaflist->key.buf;
        if (*val & 0x1) {
            O++;
        } else {
            E++;
        }
        leaflist = leaflist->next;
    }


    evenodd[0] = E;
    evenodd[1] = O;
    *size_r = sizeof(int) * 2;

    return COUCHSTORE_SUCCESS;
}

static couchstore_error_t evenodd_rereduce(char *dst, size_t *size_r,
                                                    const nodelist *leaflist,
                                                    int count,
                                                    void *ctx)
{
    int *evenodd = (int *) dst;
    int *node_evenodd;
    int E = 0, O = 0;

    (void) size_r;
    (void) ctx;

    while (count--) {
        node_evenodd = (int *) leaflist->pointer->reduce_value.buf;
        E += node_evenodd[0];
        O += node_evenodd[1];
        leaflist = leaflist->next;
    }

    evenodd[0] = E;
    evenodd[1] = O;
    *size_r = sizeof(int) * 2;

    return COUCHSTORE_SUCCESS;
}

static couchstore_error_t uniq_reduce(char *dst, size_t *size_r,
                                                    const nodelist *leaflist,
                                                    int count,
                                                    void *ctx)
{
    int map[64];
    int *val;
    int total = 0;
    int i, pos;
    memset(map, 0, 64 * sizeof(int));
    val = (int *) dst;
    val[0] = count;

    (void) ctx;

    while (count--) {
        val = (int *) leaflist->data.buf;
        if (!map[*val]) {
            map[*val] = 1;

            total++;
        }
        leaflist = leaflist->next;
    }

    val = (int *) dst;
    val[1] = total;
    pos = 2;
    for (i = 0; i < 64; i++) {
        if (map[i] == 1) {
            val[pos++] = i;
        }
    }

    *size_r = sizeof(int) * (total + 2);

    return COUCHSTORE_SUCCESS;
}

static couchstore_error_t uniq_rereduce(char *dst, size_t *size_r,
                                                    const nodelist *leaflist,
                                                    int count,
                                                    void *ctx)
{
    int map[64];
    int *val;
    int i, pos, unique_count = 0, total_count = 0;
    (void) ctx;

    memset(map, 0, 64 * sizeof(int));

    while (count--) {
        val = (int *) leaflist->pointer->reduce_value.buf;
        total_count += val[0];
        for (i = 2; i < val[1] + 2; i++) {

            if (!map[val[i]]) {
                map[val[i]] = 1;

                unique_count++;
            }
        }

        leaflist = leaflist->next;
    }

    val = (int *) dst;
    val[0] = total_count;
    val[1] = unique_count;

    pos = 2;
    for (i = 0; i < 64; i++) {
        if (map[i] == 1) {
            val[pos++] = i;

        }
    }


    *size_r = sizeof(int) * (unique_count + 2);

    return COUCHSTORE_SUCCESS;
}

/* Purge functions */
static int keepall_purge_kp(const node_pointer *ptr, void *ctx)
{
    (void) ctx;
    return PURGE_KEEP;
}

static int keepall_purge_kv(const sized_buf *key, const sized_buf *val, void *ctx)
{
    (void) key;
    (void) val;
    (void) ctx;

    return PURGE_KEEP;
}

static int all_purge_kp(const node_pointer *ptr, void *ctx)
{
    int *count;
    count = (int *) ctx;
    count[1] += red_intval(ptr, 0);
    return PURGE_ITEM;
}

static int all_purge_kv(const sized_buf *key, const sized_buf *val, void *ctx)
{
    int *count;
    (void) key;
    (void) val;

    count = (int *) ctx;
    count[0]++;
    return PURGE_ITEM;
}

static int evenodd_purge_kp(const node_pointer *ptr, void *ctx)
{
    int even_count, odd_count;
    (void) ctx;

    even_count = red_intval(ptr, 0);
    odd_count = red_intval(ptr, 1);

    if (!even_count) {
        return PURGE_ITEM;
    } else if (!odd_count) {
        return PURGE_KEEP;
    }

    return PURGE_PARTIAL;
}

static int evenodd_purge_kv(const sized_buf *key, const sized_buf *val,
                                                            void *ctx)
{
    int *count = (int *) ctx;
    int *num = (int *) key->buf;
    (void) val;
    (void) ctx;

    if (*num % 2 == 0) {
        return PURGE_KEEP;
    }

    (*count)++;

    return PURGE_ITEM;
}

static int evenodd_stop_purge_kv(const sized_buf *key, const sized_buf *val,
                                                                void *ctx)
{
    int *count = (int *) ctx;
    int *num = (int *) key->buf;
    (void) val;

    if (*count >= 4) {
        return PURGE_STOP;
    }

    if (*num % 2 == 0) {
        return PURGE_KEEP;
    }

    (*count)++;

    return PURGE_ITEM;
}

static int skip_purge_kp(const node_pointer *ptr, void *ctx)
{
    int *count = (int *) ctx;
    int len, range_start, range_end;
    len = red_intval(ptr, 1);
    range_start = red_intval(ptr, 2);
    range_end = red_intval(ptr, len + 1);

    if (!len) {
        return PURGE_KEEP;
    } else if (range_start >= 32 && range_end <= 63) {
        (*count)++;
        return PURGE_ITEM;
    }

    return PURGE_PARTIAL;
}

static int skip_purge_kv(const sized_buf *key, const sized_buf *val, void *ctx)
{
    int *count = (int *) ctx;
    int *num = (int *) val->buf;
    (void) key;

    if (*num < 32) {
        return PURGE_KEEP;
    }

    (*count)++;

    return PURGE_ITEM;
}

/* Btree iterator callbacks */
static couchstore_error_t check_vals_callback(couchfile_lookup_request *rq,
                                                            const sized_buf *k,
                                                            const sized_buf *v)
{

    int *ctx = (int *)rq->callback_ctx;
    int *num = (int *) k->buf;
    cb_assert(*num == ctx[1] && *num <= ctx[0]);
    ctx[1]++;

    return COUCHSTORE_SUCCESS;
}

static couchstore_error_t check_odd_callback(couchfile_lookup_request *rq,
                                                            const sized_buf *k,
                                                            const sized_buf *v)
{
    int *key = (int *) k->buf;
    cb_assert(*key % 2 == 0);

    return COUCHSTORE_SUCCESS;
}

static couchstore_error_t check_odd2_callback(couchfile_lookup_request *rq,
                                                            const sized_buf *k,
                                                            const sized_buf *v)
{
    int *key = (int *) k->buf;
    int *val = (int *) v->buf;
    cb_assert(*key % 2 == 0);

    switch ((*key)) {
    case 2:
    case 14006:
    case 500000:
        cb_assert(*key == *val);
        break;
    case 4:
    case 10:
    case 200000:
        cb_assert(0);
    default:
        cb_assert(*val == (*key % 64));
    }

    return COUCHSTORE_SUCCESS;
}

static couchstore_error_t check_odd_stop_callback(couchfile_lookup_request *rq,
                                                            const sized_buf *k,
                                                            const sized_buf *v)
{
    int *num = (int *) k->buf;
    switch (*num) {
    case 1:
    case 3:
    case 5:
    case 7:
        cb_assert(0);
    }

    return COUCHSTORE_SUCCESS;
}

static couchstore_error_t  check_skiprange_callback(couchfile_lookup_request *rq,
                                                            const sized_buf *k,
                                                            const sized_buf *v)
{
    int *key = (int *) k->buf;
    int *val = (int *) v->buf;
    int *last = (int *) rq->callback_ctx;
    cb_assert(*val >= 0 && *val <= 31);
    cb_assert(*key > *last);
    *last = *key;

    return COUCHSTORE_SUCCESS;
}

/* Helper function to populate a btree  with {1..N} sequence */
static node_pointer *insert_items(tree_file *file, node_pointer *root,
                                  reduce_fn reduce,
                                  reduce_fn rereduce,
                                  int n)
{

    couchstore_error_t errcode;
    int i;
    couchfile_modify_request rq;
    couchfile_modify_action *acts;
    node_pointer *nroot = NULL;
    int *arr1, *arr2;
    sized_buf *keys, *vals;

    arr1 = (int *) cb_calloc(n, sizeof(int));
    arr2 = (int *) cb_calloc(n, sizeof(int));
    keys = (sized_buf *) cb_calloc(n, sizeof(sized_buf));
    vals = (sized_buf *) cb_calloc(n, sizeof(sized_buf));
    acts = (couchfile_modify_action *) cb_calloc(n, sizeof(couchfile_modify_action));

    for (i = 0; i < n; i++) {
        arr1[i] = i + 1;
        arr2[i] = (i + 1) % 64;

        keys[i].size = sizeof(int);
        keys[i].buf = (char *) &arr1[i];

        vals[i].size = sizeof(int);
        vals[i].buf = (char *) &arr2[i];

        acts[i].type = ACTION_INSERT;
        acts[i].value.data = &vals[i];
        acts[i].key = &keys[i];
    }

    rq.cmp.compare = int_cmp;
    rq.file = file;
    rq.actions = acts;
    rq.num_actions = n;
    rq.reduce = reduce;
    rq.rereduce = rereduce;
    rq.compacting = 0;
    rq.kv_chunk_threshold = 6 * 1024;
    rq.kp_chunk_threshold = 6 * 1024;

    nroot = modify_btree(&rq, root, &errcode);
    cb_free(arr1);
    cb_free(arr2);
    cb_free(keys);
    cb_free(vals);
    cb_free(acts);

    cb_assert(errcode == 0);

    return nroot;
}

/* Helper function to create a purge btree modify request */
static couchfile_modify_request purge_request(tree_file *file, reduce_fn reduce,
                                                          reduce_fn rereduce,
                                                          purge_kp_fn purge_kp,
                                                          purge_kv_fn purge_kv,
                                                          void *purge_ctx)
{
    couchfile_modify_request rq{};

    rq.cmp.compare = int_cmp;
    rq.file = file;
    rq.actions = NULL;
    rq.num_actions = 0;
    rq.reduce = reduce;
    rq.rereduce = rereduce;
    rq.compacting = 0;
    rq.kv_chunk_threshold = 6 * 1024;
    rq.kp_chunk_threshold = 6 * 1024;
    rq.purge_kp = purge_kp;
    rq.purge_kv = purge_kv;
    rq.enable_purging = 1;
    rq.guided_purge_ctx = purge_ctx;

    return rq;

}

/* Btree iterator helper function */
static couchstore_error_t iter_btree(tree_file *file, node_pointer *root,
                                                    void *ctx,
                                                    fetch_callback_fn callback)
{
    couchfile_lookup_request rq;
    sized_buf k = {NULL, 0};
    sized_buf *keys = &k;

    rq.cmp.compare = int_cmp;
    rq.file = file;
    rq.num_keys = 1;
    rq.keys = &keys;
    rq.callback_ctx = ctx;
    rq.fetch_callback = callback;
    rq.node_callback = NULL;
    rq.fold = 1;

    return btree_lookup(&rq, root->pointer);
}


/* Unit tests for guided_purge api */

void test_no_purge_items()
{
    couchstore_error_t errcode;
    int N;
    int redval;
    int ctx[2];
    int purge_sum[2] = {0, 0};
    Db *db = NULL;
    node_pointer *root = NULL, *newroot = NULL;
    couchfile_modify_request purge_rq;
    fprintf(stderr, "\nExecuting test_no_purge_items...\n");

    N = 211341;
    ctx[0] = N;
    ctx[1] = 1;
    remove(testpurgefile);
    try_to(couchstore_open_db(testpurgefile, COUCHSTORE_OPEN_FLAG_CREATE, &db));
    root = insert_items(&db->file, NULL, count_reduce, count_rereduce, N);
    cb_assert(root != NULL);

    redval = red_intval(root, 0);
    cb_assert(redval == N);
    fprintf(stderr, "Initial reduce value equals N\n");

    purge_rq = purge_request(&db->file, count_reduce, count_rereduce,
                    keepall_purge_kp, keepall_purge_kv, (void *) purge_sum);
    newroot = guided_purge_btree(&purge_rq, root, &errcode);

    cb_assert(purge_sum[0] == 0 && purge_sum[1] == 0);
    fprintf(stderr, "guided_purge returned correct accumulator {0,0}\n");

    redval = red_intval(newroot, 0);
    cb_assert(redval == N);
    fprintf(stderr, "Reduce value after guided purge equals N\n");

    try_to(iter_btree(&db->file, newroot, &ctx, check_vals_callback));
    fprintf(stderr, "Btree has same values after guided purge\n");

cleanup:
    cb_free(root);
    if (root != newroot) {
        cb_free(newroot);
    }
    couchstore_close_file(db);
    couchstore_free_db(db);
    cb_assert(errcode == 0);
}

void test_all_purge_items()
{
    couchstore_error_t errcode;
    int N;
    int redval;
    int purge_sum[2] = {0, 0};
    Db *db = NULL;
    node_pointer *root = NULL, *newroot = NULL;
    couchfile_modify_request purge_rq;
    fprintf(stderr, "\nExecuting test_all_purge_items...\n");

    N = 211341;
    remove(testpurgefile);
    try_to(couchstore_open_db(testpurgefile, COUCHSTORE_OPEN_FLAG_CREATE, &db));
    root = insert_items(&db->file, NULL, count_reduce, count_rereduce, N);
    cb_assert(root != NULL);

    redval = red_intval(root, 0);
    cb_assert(redval == N);
    fprintf(stderr, "Initial reduce value equals N\n");

    purge_rq = purge_request(&db->file, count_reduce, count_rereduce,
                            all_purge_kp, all_purge_kv, (void *) &purge_sum);
    newroot = guided_purge_btree(&purge_rq, root, &errcode);

    cb_assert(purge_sum[0] == 0 && purge_sum[1] == N);
    fprintf(stderr, "guided_purge returned correct accumulator {0,N}\n");

    redval = red_intval(newroot, 0);
    cb_assert(redval == 0);
    fprintf(stderr, "Reduce value after guided purge equals 0\n");

    cb_assert(newroot == NULL);
    fprintf(stderr, "Btree is empty after guided purge\n");

cleanup:
    cb_free(root);
    cb_free(newroot);
    couchstore_close_file(db);
    couchstore_free_db(db);
    cb_assert(errcode == 0);
}


void test_partial_purge_items()
{
    couchstore_error_t errcode;
    int N;
    int exp_evenodd[2];
    int purge_count = 0;
    Db *db = NULL;
    node_pointer *root = NULL, *newroot = NULL;
    couchfile_modify_request purge_rq;
    fprintf(stderr, "\nExecuting test_partial_purge_items...\n");

    N = 211341;
    exp_evenodd[0] = N / 2;
    exp_evenodd[1] = N / 2 + N % 2;

    remove(testpurgefile);
    try_to(couchstore_open_db(testpurgefile, COUCHSTORE_OPEN_FLAG_CREATE, &db));
    root = insert_items(&db->file, NULL, evenodd_reduce, evenodd_rereduce, N);
    cb_assert(root != NULL);

    cb_assert(exp_evenodd[0] == red_intval(root, 0) && exp_evenodd[1] == red_intval(root, 1));
    fprintf(stderr, "Initial reduce value equals {NumEven, NumOdd}\n");

    purge_rq = purge_request(&db->file, evenodd_reduce, evenodd_rereduce,
                    evenodd_purge_kp, evenodd_purge_kv, (void *) &purge_count);
    newroot = guided_purge_btree(&purge_rq, root, &errcode);

    cb_assert(purge_count == exp_evenodd[1]);
    fprintf(stderr, "guided_purge returned correct accumulator {0,NumOdd}\n");

    cb_assert(red_intval(newroot, 0) == exp_evenodd[0] && red_intval(newroot, 1) == 0);
    fprintf(stderr, "Reduce value after guided purge equals {NumEven, 0}\n");

    try_to(iter_btree(&db->file, newroot, NULL, check_odd_callback));
    fprintf(stderr, "Btree has no odd values after guided purge\n");

cleanup:
    cb_free(root);
    cb_free(newroot);
    couchstore_close_file(db);
    couchstore_free_db(db);
    cb_assert(errcode == 0);
}

void test_partial_purge_items2()
{
    couchstore_error_t errcode;
    int N;
    Db *db = NULL;
    node_pointer *root = NULL, *newroot = NULL;
    int range_start, range_end;
    int count, purge_count = 0, iter_context = -1;
    couchfile_modify_request purge_rq;
    fprintf(stderr, "\nExecuting test_partial_purge_items2...\n");

    N = 320000;
    remove(testpurgefile);
    try_to(couchstore_open_db(testpurgefile, COUCHSTORE_OPEN_FLAG_CREATE, &db));
    root = insert_items(&db->file, NULL, uniq_reduce, uniq_rereduce, N);
    cb_assert(root != NULL);

    count = red_intval(root, 1);
    range_start = red_intval(root, 2);
    range_end = red_intval(root, count + 1);
    cb_assert(range_start == 0 && range_end == 63);

    fprintf(stderr, "Initial reduce value equals seq{0, 63}\n");

    purge_rq = purge_request(&db->file, uniq_reduce, uniq_rereduce,
                        skip_purge_kp, skip_purge_kv, (void *) &purge_count);
    newroot = guided_purge_btree(&purge_rq, root, &errcode);

    cb_assert(purge_count == N / 2);
    fprintf(stderr, "guided_purge returned correct accumulator N/2\n");

    count = red_intval(newroot, 1);
    range_start = red_intval(newroot, 2);
    range_end = red_intval(newroot, count + 1);
    cb_assert(red_intval(newroot, 0) == N / 2 && range_start == 0 && range_end == 31);
    fprintf(stderr, "Reduce value after guided purge equals {0, 31}\n");

    try_to(iter_btree(
            &db->file, newroot, &iter_context, check_skiprange_callback));
    fprintf(stderr, "Btree has only values within the range {0, 31} and keys are sorted\n");

cleanup:
    cb_free(root);
    cb_free(newroot);
    couchstore_close_file(db);
    couchstore_free_db(db);
    cb_assert(errcode == 0);
}

void test_partial_purge_with_stop()
{
    couchstore_error_t errcode;
    int N;
    int exp_evenodd[2];
    int purge_count = 0;
    Db *db = NULL;
    node_pointer *root = NULL, *newroot = NULL;
    couchfile_modify_request purge_rq;
    fprintf(stderr, "\nExecuting test_partial_purge_items...\n");

    N = 211341;
    exp_evenodd[0] = N / 2;
    exp_evenodd[1] = N / 2 + N % 2;

    remove(testpurgefile);
    try_to(couchstore_open_db(testpurgefile, COUCHSTORE_OPEN_FLAG_CREATE, &db));
    root = insert_items(&db->file, NULL, evenodd_reduce, evenodd_rereduce, N);
    cb_assert(root != NULL);

    cb_assert(exp_evenodd[0] == red_intval(root, 0) && exp_evenodd[1] == red_intval(root, 1));
    fprintf(stderr, "Initial reduce value equals {NumEven, NumOdd}\n");

    purge_rq = purge_request(&db->file, evenodd_reduce, evenodd_rereduce,
            evenodd_purge_kp, evenodd_stop_purge_kv, (void *) &purge_count);
    newroot = guided_purge_btree(&purge_rq, root, &errcode);

    cb_assert(purge_count == 4);
    fprintf(stderr, "guided_purge returned correct accumulator - 4\n");

    cb_assert(red_intval(newroot, 0) == exp_evenodd[0]);
    cb_assert(red_intval(newroot, 1) == (exp_evenodd[1] - 4));
    fprintf(stderr, "Reduce value after guided purge equals {NumEven, NumOdd-4}\n");

    try_to(iter_btree(&db->file, newroot, NULL, check_odd_stop_callback));
    fprintf(stderr, "Btree does not contain first 4 odd values after guided purge\n");

cleanup:
    cb_free(root);
    cb_free(newroot);
    couchstore_close_file(db);
    couchstore_free_db(db);
    cb_assert(errcode == 0);
}

void test_add_remove_purge()
{
    couchstore_error_t errcode;
    int N, i;
    int exp_evenodd[2];
    int purge_count = 0;
    Db *db = NULL;
    node_pointer *root = NULL, *newroot = NULL;
    couchfile_modify_request purge_rq;
    int *arr = NULL;
    couchfile_modify_action *acts = NULL;
    sized_buf *keys = NULL;
    fprintf(stderr, "\nExecuting test_add_remove_purge...\n");

    N = 211341;
    exp_evenodd[0] = N / 2;
    exp_evenodd[1] = N / 2 + N % 2;

    remove(testpurgefile);
    try_to(couchstore_open_db(testpurgefile, COUCHSTORE_OPEN_FLAG_CREATE, &db));
    root = insert_items(&db->file, NULL, evenodd_reduce, evenodd_rereduce, N);
    cb_assert(root != NULL);

    cb_assert(exp_evenodd[0] == red_intval(root, 0) && exp_evenodd[1] == red_intval(root, 1));
    fprintf(stderr, "Initial reduce value equals {NumEven, NumOdd}\n");

    purge_rq = purge_request(&db->file, evenodd_reduce, evenodd_rereduce,
                    evenodd_purge_kp, evenodd_purge_kv, (void *) &purge_count);

    /* Add few add and remove actions in the modify request */
    arr = (int *) cb_calloc(6, sizeof(int));
    keys = (sized_buf *) cb_calloc(6, sizeof(sized_buf));
    acts = (couchfile_modify_action *) cb_calloc(6, sizeof(couchfile_modify_action));

    arr[0] = 2;
    arr[1] = 4;
    arr[2] = 10;
    arr[3] = 14006;
    arr[4] = 200000;
    arr[5] = 500000;

    acts[0].type = ACTION_INSERT;
    acts[1].type = ACTION_REMOVE;
    acts[2].type = ACTION_REMOVE;
    acts[3].type = ACTION_INSERT;
    acts[4].type = ACTION_REMOVE;
    acts[5].type = ACTION_INSERT;


    for (i = 0; i < 6; i++) {
        keys[i].size  = sizeof(int);
        keys[i].buf = (char *) &arr[i];
        acts[i].key = &keys[i];
        acts[i].value.data = &keys[i];
    }

    purge_rq.actions = acts;
    purge_rq.num_actions = 6;
    purge_rq.enable_purging = 1;
    newroot = modify_btree(&purge_rq, root, &errcode);


    cb_assert(purge_count == exp_evenodd[1]);
    fprintf(stderr, "Btree add_remove with purge returned correct purge_count - Numodds\n");

    cb_assert(red_intval(newroot, 0) == (exp_evenodd[0] - 2) && red_intval(newroot, 1) == 0);
    fprintf(stderr, "Btree reduce value equals - {NumEven-2, 0}\n");

    try_to(iter_btree(&db->file, newroot, NULL, check_odd2_callback));
    fprintf(stderr, "Btree has no odd values after guided purge\n");
    fprintf(stderr, "Keys 4,10,200000 are not in tree after guided purge\n");

cleanup:
    cb_free(root);
    cb_free(newroot);
    cb_free(keys);
    cb_free(acts);
    cb_free(arr);
    couchstore_close_file(db);
    couchstore_free_db(db);
    cb_assert(errcode == 0);
}

void test_only_single_leafnode()
{
    couchstore_error_t errcode;
    int N;
    int redval;
    int purge_sum[2] = {0,0};
    Db *db = NULL;
    node_pointer *root = NULL, *newroot = NULL;
    couchfile_modify_request purge_rq;

    fprintf(stderr, "\nExecuting test_only_single_leafnode...\n");
    N = 2;
    remove(testpurgefile);
    try_to(couchstore_open_db(testpurgefile, COUCHSTORE_OPEN_FLAG_CREATE, &db));
    root = insert_items(&db->file, NULL, count_reduce, count_rereduce, N);
    cb_assert(root != NULL);

    redval = red_intval(root, 0);
    cb_assert(redval == N);
    fprintf(stderr, "Initial reduce value equals N\n");

    purge_rq = purge_request(&db->file, count_reduce, count_rereduce, keepall_purge_kp, all_purge_kv, (void *) &purge_sum);
    newroot = guided_purge_btree(&purge_rq, root, &errcode);

    cb_assert(purge_sum[0] == N && purge_sum[1] == 0);
    fprintf(stderr, "guided_purge returned correct accumulator {N,0}\n");

    redval = red_intval(newroot, 0);
    cb_assert(redval == 0);
    fprintf(stderr, "Reduce value after guided purge equals 0\n");

    cb_assert(newroot == NULL);
    fprintf(stderr, "Btree is empty after guided purge\n");

cleanup:
    cb_free(root);
    cb_free(newroot);
    couchstore_close_file(db);
    couchstore_free_db(db);
    cb_assert(errcode == 0);
}
