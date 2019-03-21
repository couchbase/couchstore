/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

#include "couchstore_config.h"

#include "../src/couch_btree.h"
#include "view_tests.h"
#include <platform/cbassert.h>

static view_btree_reduction_t *test_view_btree_reduction_decoding(const char *reduction_bin,
                                                                  size_t len)
{
    view_btree_reduction_t *r = NULL;
    uint16_t partition_bitset[] = {
        0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,
        25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,
        47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63
    };
    bitmap_t expected_part_bitmap;
    unsigned i;

    cb_assert(decode_view_btree_reduction(reduction_bin, len, &r) == COUCHSTORE_SUCCESS);

    cb_assert(r != NULL);
    cb_assert(r->kv_count == 1582);

    memset(&expected_part_bitmap, 0, sizeof(expected_part_bitmap));
    for (i = 0; i < (sizeof(partition_bitset) / sizeof(partition_bitset[0])); ++i) {
        set_bit(&expected_part_bitmap, partition_bitset[i]);
    }

    cb_assert(memcmp(&r->partitions_bitmap, &expected_part_bitmap, sizeof(expected_part_bitmap)) == 0);
    cb_assert(r->num_values == 3);
    cb_assert(r->reduce_values[0].size == 4);
    cb_assert(r->reduce_values[1].size == 5);
    cb_assert(r->reduce_values[2].size == 9);

    cb_assert(memcmp(r->reduce_values[0].buf, "1582", 4) == 0);
    cb_assert(memcmp(r->reduce_values[1].buf, "-1582", 5) == 0);
    cb_assert(memcmp(r->reduce_values[2].buf, "110120647", 9) == 0);

    return r;
}

static view_id_btree_reduction_t *test_view_id_btree_reduction_decoding(const char *id_btree_reduction_bin)
{
    view_id_btree_reduction_t *r = NULL;
    uint16_t partition_bitset[] = { 49, 50, 51, 52 };
    bitmap_t expected_part_bitmap;
    unsigned i;

    cb_assert(decode_view_id_btree_reduction(id_btree_reduction_bin, &r) == COUCHSTORE_SUCCESS);
    cb_assert(r != NULL);
    cb_assert(r->kv_count == 3026);
    memset(&expected_part_bitmap, 0, sizeof(expected_part_bitmap));
    for (i = 0; i < (sizeof(partition_bitset) / sizeof(partition_bitset[0])); ++i) {
        set_bit(&expected_part_bitmap, partition_bitset[i]);
    }
    cb_assert(memcmp(&r->partitions_bitmap, &expected_part_bitmap, sizeof(expected_part_bitmap)) == 0);

    return r;
}

static void test_view_btree_reduction_encoding(const view_btree_reduction_t *r,
                                               char *buffer,
                                               size_t *size)
{
    couchstore_error_t res;

    res = encode_view_btree_reduction(r, buffer, size);
    cb_assert(res == COUCHSTORE_SUCCESS);
}


static void test_view_id_btree_reduction_encoding(const view_id_btree_reduction_t *r,
                                                  char *buffer,
                                                  size_t *size)
{
    couchstore_error_t res;

    res = encode_view_id_btree_reduction(r, buffer, size);
    cb_assert(res == COUCHSTORE_SUCCESS);
}

void test_reductions()
{
    unsigned char reduction_bin[] = {
        0,0,0,6,46,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,255,255,255,255,255,255,255,255,0,4,
        49,53,56,50,0,5,45,49,53,56,50,0,9,49,49,48,49,50,48,54,52,55
    };
    unsigned char id_btree_reduction_bin[] = {
        0,0,0,11,210,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,30,0,0,0,0,0,0
    };
    char r_bin2[MAX_REDUCTION_SIZE];
    size_t r_bin2_size = 0;
    char id_btree_r_bin2[MAX_REDUCTION_SIZE];
    size_t id_btree_r_bin2_size = 0;
    char r_bin3[MAX_REDUCTION_SIZE];
    size_t r_bin3_size = 0;
    char id_btree_r_bin3[MAX_REDUCTION_SIZE];
    size_t id_btree_r_bin3_size = 0;
    view_btree_reduction_t *r;
    view_id_btree_reduction_t *id_btree_r;
    view_btree_reduction_t *r2;
    view_id_btree_reduction_t *id_btree_r2;

    fprintf(stderr, "Decoding a view btree reduction ...\n");
    r = test_view_btree_reduction_decoding((char*)reduction_bin,
                                           sizeof(reduction_bin));

    fprintf(stderr, "Decoding a view id btree reduction ...\n");
    id_btree_r = test_view_id_btree_reduction_decoding((char*)id_btree_reduction_bin);

    fprintf(stderr, "Encoding the previously decoded view btree reduction ...\n");
    test_view_btree_reduction_encoding(r, r_bin2, &r_bin2_size);

    cb_assert(r_bin2_size == sizeof(reduction_bin));
    cb_assert(memcmp(r_bin2, reduction_bin, r_bin2_size) == 0);

    fprintf(stderr, "Encoding the previously decoded view id btree reduction ...\n");
    test_view_id_btree_reduction_encoding(id_btree_r, id_btree_r_bin2, &id_btree_r_bin2_size);

    cb_assert(id_btree_r_bin2_size == sizeof(id_btree_reduction_bin));
    cb_assert(memcmp(id_btree_r_bin2, id_btree_reduction_bin, id_btree_r_bin2_size) == 0);

    fprintf(stderr, "Decoding the previously encoded view btree reduction ...\n");
    r2 = test_view_btree_reduction_decoding(r_bin2, r_bin2_size);

    fprintf(stderr, "Decoding the previously encoded view id btree reduction ...\n");
    id_btree_r2 = test_view_id_btree_reduction_decoding(id_btree_r_bin2);

    fprintf(stderr, "Encoding the previously decoded view btree reduciton ...\n");
    test_view_btree_reduction_encoding(r2, r_bin3, &r_bin3_size);

    cb_assert(r_bin3_size == sizeof(reduction_bin));
    cb_assert(memcmp(r_bin3, reduction_bin, r_bin3_size) == 0);

    fprintf(stderr, "Encoding the previously decoded view id btree reduciton ...\n");
    test_view_id_btree_reduction_encoding(id_btree_r2, id_btree_r_bin3, &id_btree_r_bin3_size);

    cb_assert(id_btree_r_bin3_size == sizeof(id_btree_reduction_bin));
    cb_assert(memcmp(id_btree_r_bin3, id_btree_reduction_bin, id_btree_r_bin3_size) == 0);

    free_view_btree_reduction(r);
    free_view_btree_reduction(r2);

    free_view_id_btree_reduction(id_btree_r);
    free_view_id_btree_reduction(id_btree_r2);
}
