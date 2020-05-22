/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#ifndef _REDUCTIONS_H
#define _REDUCTIONS_H

#include "couchstore_config.h"
#include <stdint.h>
#include <libcouchstore/visibility.h>
#include <libcouchstore/couch_db.h>
#include <libcouchstore/couch_common.h>
#include "bitmap.h"

#ifdef __cplusplus
extern "C" {
#endif


typedef struct {
    uint64_t kv_count{0};
    bitmap_t                partitions_bitmap;
    /* number of elements in reduce_values */
    uint8_t num_values{0};
    sized_buf* reduce_values{nullptr};
    std::vector<char> buffer;
} view_btree_reduction_t;

typedef struct {
    uint64_t                kv_count;
    bitmap_t                partitions_bitmap;
} view_id_btree_reduction_t;

// return kv_count and copy bitmap to partitions_bitmap
uint64_t decode_view_btree_reduction_partitions_bitmap(
        const char* bytes, size_t len, bitmap_t& partitions_bitmap);

couchstore_error_t decode_view_btree_reduction(
        const char* bytes, size_t len, view_btree_reduction_t& reduction);

couchstore_error_t encode_view_btree_reduction(const view_btree_reduction_t *reduction,
                                               char *buffer,
                                               size_t *buffer_size);

void free_view_btree_reduction(view_btree_reduction_t *reduction);

couchstore_error_t decode_view_id_btree_reduction(const char *bytes,
                                                  view_id_btree_reduction_t **reduction);

couchstore_error_t encode_view_id_btree_reduction(const view_id_btree_reduction_t *reduction,
                                                  char *buffer,
                                                  size_t *buffer_size);

void free_view_id_btree_reduction(view_id_btree_reduction_t *reduction);

#ifdef __cplusplus
}
#endif

#endif
