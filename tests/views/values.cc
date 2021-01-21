/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

#include "view_tests.h"

#include <platform/cb_malloc.h>
#include <platform/cbassert.h>

static view_btree_value_t test_view_btree_value_decoding(const char* value_bin,
                                                         size_t len) {
    view_btree_value_t v{};

    cb_assert(decode_view_btree_value(value_bin, len, v) == COUCHSTORE_SUCCESS);
    cb_assert(v.partition == 10);
    cb_assert(v.num_values == 2);
    cb_assert(v.values_buf.data() != nullptr);

    cb_assert(v.values[0].size == 4);
    cb_assert(memcmp(v.values[0].buf, "6155", v.values[0].size) == 0);
    cb_assert(v.values[1].size == 4);
    cb_assert(memcmp(v.values[1].buf, "6154", v.values[0].size) == 0);

    return v;
}

static view_id_btree_value_t *test_view_id_btree_value_decoding(const char *id_btree_value_bin,
                                                                size_t len)
{
    view_id_btree_value_t* v = nullptr;

    cb_assert(decode_view_id_btree_value(id_btree_value_bin, len, &v) == COUCHSTORE_SUCCESS);
    cb_assert(v != nullptr);

    cb_assert(v->partition == 67);
    cb_assert(v->num_view_keys_map == 2);

    cb_assert(v->view_keys_map[0].view_id == 0);
    cb_assert(v->view_keys_map[0].num_keys == 2);
    cb_assert(v->view_keys_map[0].json_keys[0].size == 14);
    cb_assert(memcmp(v->view_keys_map[0].json_keys[0].buf,
                  "[123,\"foobar\"]",
                  v->view_keys_map[0].json_keys[0].size) == 0);
    cb_assert(v->view_keys_map[0].json_keys[1].size == 4);
    cb_assert(memcmp(v->view_keys_map[0].json_keys[1].buf,
                  "-321",
                  v->view_keys_map[0].json_keys[1].size) == 0);

    cb_assert(v->view_keys_map[1].view_id == 1);
    cb_assert(v->view_keys_map[1].num_keys == 1);
    cb_assert(v->view_keys_map[1].json_keys[0].size == 7);
    cb_assert(memcmp(v->view_keys_map[1].json_keys[0].buf,
                  "[5,6,7]",
                  v->view_keys_map[1].json_keys[0].size) == 0);

    return v;
}

static void test_view_btree_value_encoding(const view_btree_value_t *v,
                                           char **buffer,
                                           size_t *size)
{
    couchstore_error_t res;

    res = encode_view_btree_value(v, buffer, size);
    cb_assert(res == COUCHSTORE_SUCCESS);
}


static void test_view_id_btree_value_encoding(const view_id_btree_value_t *v,
                                              char **buffer,
                                              size_t *size)
{
    couchstore_error_t res;

    res = encode_view_id_btree_value(v, buffer, size);
    cb_assert(res == COUCHSTORE_SUCCESS);
}

void test_values()
{
    char value_bin[] = {
        0,10,0,0,4,54,49,53,53,0,0,4,54,49,53,52
    };
    char id_btree_value_bin[] = {
        0,67,0,0,2,0,14,91,49,50,51,44,34,102,111,111,98,97,114,
        34,93,0,4,45,51,50,49,1,0,1,0,7,91,53,44,54,44,55,93
    };
    view_id_btree_value_t *id_btree_v;
    view_id_btree_value_t *id_btree_v2;
    char* v_bin2 = nullptr;
    size_t v_bin2_size = 0;
    char* id_btree_v_bin2 = nullptr;
    size_t id_btree_v_bin2_size = 0;
    char* v_bin3 = nullptr;
    size_t v_bin3_size = 0;
    char* id_btree_v_bin3 = nullptr;
    size_t id_btree_v_bin3_size = 0;

    fprintf(stderr, "Decoding a view btree value ...\n");
    auto v = test_view_btree_value_decoding(value_bin, sizeof(value_bin));

    fprintf(stderr, "Decoding a view id btree value ...\n");
    id_btree_v = test_view_id_btree_value_decoding(id_btree_value_bin,
                                                   sizeof(id_btree_value_bin));

    fprintf(stderr, "Encoding the previously decoded view btree value ...\n");
    test_view_btree_value_encoding(&v, &v_bin2, &v_bin2_size);

    cb_assert(v_bin2_size == sizeof(value_bin));
    cb_assert(memcmp(v_bin2, value_bin, v_bin2_size) == 0);

    fprintf(stderr, "Encoding the previously decoded view id btree value ...\n");
    test_view_id_btree_value_encoding(id_btree_v, &id_btree_v_bin2, &id_btree_v_bin2_size);

    cb_assert(id_btree_v_bin2_size == sizeof(id_btree_value_bin));
    cb_assert(memcmp(id_btree_v_bin2, id_btree_value_bin, id_btree_v_bin2_size) == 0);

    fprintf(stderr, "Decoding the previously encoded view btree value ...\n");
    auto v2 = test_view_btree_value_decoding(v_bin2, v_bin2_size);

    fprintf(stderr, "Decoding the previously encoded view id btree value ...\n");
    id_btree_v2 = test_view_id_btree_value_decoding(id_btree_v_bin2,
                                                    id_btree_v_bin2_size);

    fprintf(stderr, "Encoding the previously decoded view btree value ...\n");
    test_view_btree_value_encoding(&v2, &v_bin3, &v_bin3_size);

    cb_assert(v_bin3_size == sizeof(value_bin));
    cb_assert(memcmp(v_bin3, value_bin, v_bin3_size) == 0);

    fprintf(stderr, "Encoding the previously decoded view id btree value ...\n");
    test_view_id_btree_value_encoding(id_btree_v2, &id_btree_v_bin3, &id_btree_v_bin3_size);

    cb_assert(id_btree_v_bin3_size == sizeof(id_btree_value_bin));
    cb_assert(memcmp(id_btree_v_bin3, id_btree_value_bin, id_btree_v_bin3_size) == 0);

    cb_free(v_bin2);
    cb_free(v_bin3);

    free_view_id_btree_value(id_btree_v);
    free_view_id_btree_value(id_btree_v2);
    cb_free(id_btree_v_bin2);
    cb_free(id_btree_v_bin3);
}
