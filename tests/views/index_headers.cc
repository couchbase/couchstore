/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

/**
 * @copyright 2013 Couchbase, Inc.
 *
 * @author Filipe Manana  <filipe@couchbase.com>
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

#include <platform/cb_malloc.h>
#include <platform/cbassert.h>

static index_header_t *test_index_header_decoding_v1(const char *header_bin,
                                                     size_t header_bin_size)
{
    uint16_t active[] = { 3,7,19,23,27,31,35,39,43,47,51,55,59,63 };
    uint16_t passive[] = {
        0,1,2,4,5,6,8,9,10,12,13,14,16,17,18,20,21,22,24,25,
        26,28,29,30,32,33,34,36,37,38,40,41,42,44,45,46,48,49,
        50,52,53,54,56,57,60,62
    };
    uint16_t cleanup[] = { 11,15,58,61 };
    uint16_t unindexable[] = { 0,63 };
    uint16_t replicas_on_transfer[] = { 5, 10, 60, 62 };
    uint16_t pending_active[] = { 11,15 };
    uint16_t pending_passive[] = { 58,61 };
    uint16_t pending_unindexable[] = { 15,58 };
    index_header_t* header = nullptr;
    bitmap_t expected_active, expected_passive, expected_cleanup;
    unsigned i;
    int ii;
    uint16_t jj;
    int num_unindexable;
    int num_reps;
    int num_pending_active;
    int num_pending_passive;
    int num_pending_unindexable;

    cb_assert(decode_index_header(header_bin, header_bin_size, &header) == COUCHSTORE_SUCCESS);
    cb_assert(header != nullptr);

    cb_assert(header->version == 1);
    cb_assert(memcmp(header->signature, header_bin, 16) == 0);
    cb_assert(header->num_partitions == 64);
    cb_assert(header->num_views == 2);

    for (i = 0; i < (sizeof(active) / sizeof(active[0])); ++i) {
        set_bit(&expected_active, active[i]);
    }
    cb_assert(memcmp(&header->active_bitmask, &expected_active, sizeof(expected_active)) == 0);

    for (i = 0; i < (sizeof(passive) / sizeof(passive[0])); ++i) {
        set_bit(&expected_passive, passive[i]);
    }
    cb_assert(memcmp(&header->passive_bitmask, &expected_passive, sizeof(expected_passive)) == 0);

    for (i = 0; i < (sizeof(cleanup) / sizeof(cleanup[0])); ++i) {
        set_bit(&expected_cleanup, cleanup[i]);
    }
    cb_assert(memcmp(&header->cleanup_bitmask, &expected_cleanup, sizeof(expected_cleanup)) == 0);

    cb_assert(sorted_list_size(header->seqs) == 58);
    for (jj = 0; jj < 64; ++jj) {
        part_seq_t rs, *pseq;

        switch (jj) {
            /* unindexable */
        case 0:
        case 63:
            /* cleanup */
        case 11:
        case 15:
        case 58:
        case 61:
            continue;
        default:
            break;
        }

        rs.part_id = jj;

        pseq = (part_seq_t *) sorted_list_get(header->seqs, &rs);
        cb_assert(pseq != nullptr);
        cb_assert(pseq->part_id == jj);
        cb_assert(pseq->seq == 1221);
    }

    num_unindexable = sizeof(unindexable) / sizeof(unindexable[0]);
    cb_assert(sorted_list_size(header->unindexable_seqs) == num_unindexable);
    for (ii = 0; ii < num_unindexable; ++ii) {
        part_seq_t rs, *pseq;
        rs.part_id = unindexable[ii];

        pseq = (part_seq_t *) sorted_list_get(header->unindexable_seqs, &rs);
        cb_assert(pseq != nullptr);
        cb_assert(pseq->part_id == unindexable[ii]);
        cb_assert(pseq->seq == 1221);
    }

    cb_assert(header->id_btree_state->pointer == 1617507);
    cb_assert(header->id_btree_state->subtreesize == 1286028);
    cb_assert(header->id_btree_state->reduce_value.size == 133);
    /* TODO: once view reduction decoding is done, test the exact reduction value. */

    cb_assert(header->view_states[0]->pointer == 2901853);
    cb_assert(header->view_states[0]->subtreesize == 1284202);
    cb_assert(header->view_states[0]->reduce_value.size == 140);
    /* TODO: once view reduction decoding is done, test the exact reduction value. */

    cb_assert(header->view_states[1]->pointer == 4180175);
    cb_assert(header->view_states[1]->subtreesize == 1278451);
    cb_assert(header->view_states[1]->reduce_value.size == 140);
    /* TODO: once view reduction decoding is done, test the exact reduction value. */

    cb_assert(header->has_replica == 1);
    cb_assert(header->replicas_on_transfer != nullptr);

    num_reps = (sizeof(replicas_on_transfer) / sizeof(replicas_on_transfer[0]));

    cb_assert(sorted_list_size(header->replicas_on_transfer) == num_reps);
    for (ii = 0; ii < num_reps; ++ii) {
        uint16_t *part_id = (uint16_t*)
                            sorted_list_get(header->replicas_on_transfer,
                                            &replicas_on_transfer[ii]);
        cb_assert(part_id != nullptr);
        cb_assert(*part_id == replicas_on_transfer[ii]);
    }

    num_pending_active = sizeof(pending_active) / sizeof(pending_active[0]);
    cb_assert(sorted_list_size(header->pending_transition.active) == num_pending_active);
    for (ii = 0; ii < num_pending_active; ++ii) {
        uint16_t *part_id = (uint16_t*)
                            sorted_list_get(header->pending_transition.active,
                                            &pending_active[ii]);
        cb_assert(part_id != nullptr);
        cb_assert(*part_id == pending_active[ii]);
    }

    num_pending_passive = sizeof(pending_passive) / sizeof(pending_passive[0]);
    cb_assert(sorted_list_size(header->pending_transition.passive) == num_pending_passive);
    for (ii = 0; ii < num_pending_passive; ++ii) {
        uint16_t *part_id = (uint16_t*)
                            sorted_list_get(header->pending_transition.passive,
                                            &pending_passive[ii]);
        cb_assert(part_id != nullptr);
        cb_assert(*part_id == pending_passive[ii]);
    }

    num_pending_unindexable = sizeof(pending_unindexable) / sizeof(pending_unindexable[0]);
    cb_assert(sorted_list_size(header->pending_transition.unindexable) == num_pending_unindexable);
    for (ii = 0; ii < num_pending_unindexable; ++ii) {
        uint16_t *part_id = (uint16_t*)
                            sorted_list_get(header->pending_transition.unindexable,
                                            &pending_unindexable[ii]);
        cb_assert(part_id != nullptr);
        cb_assert(*part_id == pending_unindexable[ii]);
    }

    return header;
}

static index_header_t *test_index_header_decoding_v2(const char *header_bin,
                                                     size_t header_bin_size)
{
    uint16_t active[] = { 3, 4, 21, 24 };
    uint16_t passive[] = { 1, 5, 14, 28, 31};
    uint16_t cleanup[] = { 2, 13 };
    uint16_t unindexable[] = { 3, 31 };
    uint16_t replicas_on_transfer[] = { 5 };
    uint16_t pending_active[] = { 14, 28 };
    uint16_t pending_passive[] = { 1 };
    uint16_t pending_unindexable[] = { 1, 28 };
    index_header_t* header = nullptr;
    bitmap_t expected_active, expected_passive, expected_cleanup;
    unsigned i;
    int ii;
    uint16_t jj;
    int num_unindexable;
    int num_reps;
    int num_pending_active;
    int num_pending_passive;
    int num_pending_unindexable;

    cb_assert(decode_index_header(header_bin, header_bin_size, &header) == COUCHSTORE_SUCCESS);
    cb_assert(header != nullptr);

    cb_assert(header->version == 2);
    cb_assert(memcmp(header->signature, header_bin, 16) == 0);
    cb_assert(header->num_partitions == 32);
    cb_assert(header->num_views == 2);

    for (i = 0; i < (sizeof(active) / sizeof(active[0])); ++i) {
        set_bit(&expected_active, active[i]);
    }
    cb_assert(memcmp(&header->active_bitmask, &expected_active, sizeof(expected_active)) == 0);

    for (i = 0; i < (sizeof(passive) / sizeof(passive[0])); ++i) {
        set_bit(&expected_passive, passive[i]);
    }
    cb_assert(memcmp(&header->passive_bitmask, &expected_passive, sizeof(expected_passive)) == 0);

    for (i = 0; i < (sizeof(cleanup) / sizeof(cleanup[0])); ++i) {
        set_bit(&expected_cleanup, cleanup[i]);
    }
    cb_assert(memcmp(&header->cleanup_bitmask, &expected_cleanup, sizeof(expected_cleanup)) == 0);

    cb_assert(sorted_list_size(header->seqs) == 32);
    for (jj = 0; jj < 32; ++jj) {
        part_seq_t rs, *pseq;
        rs.part_id = jj;
        pseq = (part_seq_t *) sorted_list_get(header->seqs, &rs);
        cb_assert(pseq != nullptr);
        cb_assert(pseq->part_id == jj);
        cb_assert(pseq->seq == (uint64_t)jj * jj);
    }

    num_unindexable = sizeof(unindexable) / sizeof(unindexable[0]);
    cb_assert(sorted_list_size(header->unindexable_seqs) == num_unindexable);
    for (ii = 0; ii < num_unindexable; ++ii) {
        part_seq_t rs, *pseq;
        rs.part_id = unindexable[ii];

        pseq = (part_seq_t *) sorted_list_get(header->unindexable_seqs, &rs);
        cb_assert(pseq != nullptr);
        cb_assert(pseq->part_id == unindexable[ii]);
        cb_assert(pseq->seq == (uint64_t)unindexable[ii] * unindexable[ii]);
    }
    cb_assert(header->id_btree_state->pointer == 123);
    cb_assert(header->id_btree_state->subtreesize == 567);
    cb_assert(header->id_btree_state->reduce_value.size == 6);
    cb_assert(memcmp(
        header->id_btree_state->reduce_value.buf, "redval",
        header->id_btree_state->reduce_value.size) == 0);

    cb_assert(header->view_states[0]->pointer == 2345);
    cb_assert(header->view_states[0]->subtreesize == 789);
    cb_assert(header->view_states[0]->reduce_value.size == 7);
    cb_assert(memcmp(
        header->view_states[0]->reduce_value.buf, "redval2",
        header->view_states[0]->reduce_value.size) == 0);

    cb_assert(header->view_states[1]->pointer == 3456);
    cb_assert(header->view_states[1]->subtreesize == 8901);
    cb_assert(header->view_states[1]->reduce_value.size == 7);
    cb_assert(memcmp(
        header->view_states[1]->reduce_value.buf, "redval3",
        header->view_states[1]->reduce_value.size) == 0);

    cb_assert(header->has_replica == 0);
    cb_assert(header->replicas_on_transfer != nullptr);

    num_reps = (sizeof(replicas_on_transfer) / sizeof(replicas_on_transfer[0]));

    cb_assert(sorted_list_size(header->replicas_on_transfer) == num_reps);
    for (ii = 0; ii < num_reps; ++ii) {
        uint16_t *part_id = (uint16_t*)
                            sorted_list_get(header->replicas_on_transfer,
                                            &replicas_on_transfer[ii]);
        cb_assert(part_id != nullptr);
        cb_assert(*part_id == replicas_on_transfer[ii]);
    }

    num_pending_active = sizeof(pending_active) / sizeof(pending_active[0]);
    cb_assert(sorted_list_size(header->pending_transition.active) == num_pending_active);
    for (ii = 0; ii < num_pending_active; ++ii) {
        uint16_t *part_id = (uint16_t*)
                            sorted_list_get(header->pending_transition.active,
                                            &pending_active[ii]);
        cb_assert(part_id != nullptr);
        cb_assert(*part_id == pending_active[ii]);
    }

    num_pending_passive = sizeof(pending_passive) / sizeof(pending_passive[0]);
    cb_assert(sorted_list_size(header->pending_transition.passive) == num_pending_passive);
    for (ii = 0; ii < num_pending_passive; ++ii) {
        uint16_t *part_id = (uint16_t*)
                            sorted_list_get(header->pending_transition.passive,
                                            &pending_passive[ii]);
        cb_assert(part_id != nullptr);
        cb_assert(*part_id == pending_passive[ii]);
    }

    num_pending_unindexable = sizeof(pending_unindexable) / sizeof(pending_unindexable[0]);
    cb_assert(sorted_list_size(header->pending_transition.unindexable) == num_pending_unindexable);
    for (ii = 0; ii < num_pending_unindexable; ++ii) {
        uint16_t *part_id = (uint16_t*)
                            sorted_list_get(header->pending_transition.unindexable,
                                            &pending_unindexable[ii]);
        cb_assert(part_id != nullptr);
        cb_assert(*part_id == pending_unindexable[ii]);
    }

    cb_assert(sorted_list_size(header->part_versions) == 32);
    for (jj = 0; jj < 32; ++jj) {
        part_version_t rs, *pver;
        rs.part_id = jj;
        pver = (part_version_t *) sorted_list_get(header->part_versions, &rs);
        cb_assert(pver != nullptr);
        cb_assert(pver->part_id == jj);
        cb_assert(pver->num_failover_log == 2);
        cb_assert(memcmp(pver->failover_log[0].uuid, "auuid123", 8) == 0);
        cb_assert(pver->failover_log[0].seq == jj);
        cb_assert(memcmp(pver->failover_log[1].uuid, "another1", 8) == 0);
        cb_assert(pver->failover_log[1].seq == (uint64_t)jj * jj);
    }

    return header;
}

static void test_index_header_encoding(const index_header_t *header,
                                       char **buffer,
                                       size_t *size)
{
    couchstore_error_t res;

    res = encode_index_header(header, buffer, size);
    cb_assert(res == COUCHSTORE_SUCCESS);
}

void test_index_headers_v1(void)
{
    index_header_t*header;
    index_header_t *header2;
    char* header_bin2 = nullptr;
    size_t header_bin2_size = 0;
    char* header_bin3 = nullptr;
    size_t header_bin3_size = 0;

    unsigned char header_bin[] = {
        5,226,251,160,170,107,207,39,248,218,139,62,137,58,95,46,204,10,12,1,0,64,0,
        254,1,0,218,1,0,0,136,5,1,4,0,136,254,127,0,218,127,0,8,0,83,119,9,1,254,128,
        0,222,128,0,0,36,5,121,20,136,0,0,58,0,1,1,11,12,4,197,0,2,13,8,0,3,13,8,0,4,
        13,8,0,5,13,8,0,6,13,8,0,7,13,8,0,8,13,8,0,9,13,8,0,10,13,8,0,12,13,8,0,13,
        13,8,0,14,13,8,0,16,13,8,0,17,13,8,0,18,13,8,0,19,13,8,0,20,13,8,0,21,13,8,0,
        22,13,8,0,23,13,8,0,24,13,8,0,25,13,8,0,26,13,8,0,27,13,8,0,28,13,8,0,29,13,
        8,0,30,13,8,0,31,13,8,0,32,13,8,0,33,13,8,0,34,13,8,0,35,13,8,37,19,12,4,197,
        0,37,13,16,0,38,13,8,0,39,13,8,0,40,13,8,0,41,13,8,0,42,13,8,0,43,13,8,0,44,
        13,8,0,45,13,8,0,46,13,8,0,47,13,8,0,48,13,8,0,49,13,8,0,50,13,8,0,51,13,8,0,
        52,13,8,0,53,13,8,0,54,13,8,0,55,13,8,0,56,13,8,0,57,13,8,0,59,13,8,0,60,13,
        8,0,62,13,8,64,145,0,0,0,24,174,99,0,0,0,19,159,140,0,0,1,49,254,101,3,226,
        101,3,0,255,13,1,32,2,0,152,0,0,0,44,71,93,1,148,8,152,106,0,254,148,0,254,
        148,0,1,148,24,0,5,55,56,49,52,52,5,154,8,63,200,207,1,154,4,129,243,254,154,
        0,254,154,0,46,154,0,112,1,0,4,0,5,0,10,0,60,0,62,0,2,0,11,0,15,0,2,0,58,0,
        61,0,2,0,15,0,58,105,173,44,0,0,4,197,0,63,0,0,0,0,4,197
    };

    fprintf(stderr, "Decoding an index header v1...\n");
    header = test_index_header_decoding_v1((const char*)header_bin, sizeof(header_bin));

    fprintf(stderr, "Encoding the previously decoded header...\n");
    test_index_header_encoding(header, &header_bin2, &header_bin2_size);

    cb_assert(header_bin2_size == sizeof(header_bin));
    cb_assert(memcmp(header_bin2, header_bin, header_bin2_size) == 0);

    fprintf(stderr, "Decoding the previously encoded header...\n");
    header2 = test_index_header_decoding_v1(header_bin2, header_bin2_size);

    fprintf(stderr, "Encoding the previously decoded header...\n");
    test_index_header_encoding(header2, &header_bin3, &header_bin3_size);

    cb_assert(header_bin3_size == sizeof(header_bin));
    cb_assert(memcmp(header_bin3, header_bin, header_bin3_size) == 0);

    free_index_header(header);
    free_index_header(header2);
    cb_free(header_bin2);
    cb_free(header_bin3);
}


void test_index_headers_v2(void)
{
    index_header_t*header;
    index_header_t *header2;
    char* header_bin2 = nullptr;
    size_t header_bin2_size = 0;
    char* header_bin3 = nullptr;
    size_t header_bin3_size = 0;

    unsigned char header_bin[] = {
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,237,14,12,2,0,32,0,254,1,0,234,1,0,12,1,32,0,
        24,254,127,0,234,127,0,16,0,144,0,64,34,254,128,0,238,128,0,12,0,0,32,4,61,
        130,0,1,5,140,8,1,0,2,5,8,8,4,0,3,5,8,8,9,0,4,5,8,8,16,0,5,5,8,8,25,0,6,5,8,
        8,36,0,7,5,8,8,49,0,8,5,8,8,64,0,9,5,8,8,81,0,10,5,8,8,100,0,11,5,8,8,121,0,
        12,5,8,8,144,0,13,5,8,8,169,0,14,5,8,8,196,0,15,5,8,8,225,0,16,1,8,12,1,0,0,
        17,5,8,8,33,0,18,5,8,8,68,0,19,5,8,8,105,0,20,5,8,8,144,0,21,5,8,8,185,0,22,
        5,8,8,228,0,23,1,8,4,2,17,41,196,12,2,64,0,25,5,16,8,113,0,26,5,8,8,164,0,27,
        5,8,8,217,0,28,1,8,12,3,16,0,29,5,8,8,73,0,30,5,8,8,132,0,31,5,8,0,193,9,112,
        4,0,123,1,14,32,2,55,114,101,100,118,97,108,2,9,125,4,9,41,1,21,4,3,21,9,21,
        0,50,9,21,4,13,128,1,21,4,34,197,9,21,52,51,0,0,1,0,5,0,2,0,14,0,28,0,1,37,
        62,16,1,0,28,0,2,53,62,17,102,65,234,32,2,97,117,117,105,100,49,50,51,1,66,1,
        1,28,97,110,111,116,104,101,114,49,1,12,5,1,0,1,66,36,0,0,1,58,36,0,33,160,
        62,72,0,0,2,58,36,0,33,188,62,36,0,0,3,58,36,0,33,216,62,36,0,0,4,58,36,0,33,
        244,62,36,0,0,5,58,36,0,8,25,0,6,66,36,0,0,6,58,36,0,65,44,62,72,0,0,7,58,36,
        0,65,72,62,36,0,0,8,58,36,0,8,64,0,9,66,36,0,0,9,58,36,0,65,128,62,72,0,0,10,
        58,36,0,65,156,62,36,0,0,11,58,36,0,65,184,62,36,0,0,12,58,36,0,65,212,62,36,
        0,0,13,58,36,0,65,240,62,36,0,0,14,58,36,0,97,12,62,36,0,0,15,58,36,0,97,40,
        62,36,0,0,16,54,36,0,101,68,62,36,0,0,17,58,36,0,97,96,62,36,0,0,18,58,36,0,
        97,124,62,36,0,0,19,58,36,0,97,152,62,36,0,0,20,58,36,0,97,180,62,36,0,0,21,
        58,36,0,97,208,62,36,0,0,22,58,36,0,97,236,62,36,0,0,23,54,36,0,133,8,62,36,
        0,0,24,58,36,0,129,36,62,36,0,0,25,58,36,0,129,64,62,36,0,0,26,58,36,0,129,
        92,62,36,0,0,27,58,36,0,129,120,62,36,0,0,28,54,36,0,133,148,62,36,0,0,29,58,
        36,0,129,176,62,36,0,0,30,58,36,0,129,204,62,36,0,0,31,58,36,0,0,193
    };

    fprintf(stderr, "Decoding an index header v2...\n");
    header = test_index_header_decoding_v2(
        (const char*)header_bin, sizeof(header_bin));

    fprintf(stderr, "Encoding the previously decoded header...\n");
    test_index_header_encoding(header, &header_bin2, &header_bin2_size);

    cb_assert(header_bin2_size == sizeof(header_bin));
    cb_assert(memcmp(header_bin2, header_bin, header_bin2_size) == 0);

    fprintf(stderr, "Decoding the previously encoded header...\n");
    header2 = test_index_header_decoding_v2(header_bin2, header_bin2_size);

    fprintf(stderr, "Encoding the previously decoded header...\n");
    test_index_header_encoding(header2, &header_bin3, &header_bin3_size);

    cb_assert(header_bin3_size == sizeof(header_bin));
    cb_assert(memcmp(header_bin3, header_bin, header_bin3_size) == 0);

    free_index_header(header);
    free_index_header(header2);
    cb_free(header_bin2);
    cb_free(header_bin3);
}
