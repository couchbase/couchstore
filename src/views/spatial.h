/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

/**
 * @copyright 2013 Couchbase, Inc.
 *
 * @author Volker Mische <volker@couchbase.com>
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

#ifndef _VIEW_SPATIAL_UTILS_H
#define _VIEW_SPATIAL_UTILS_H

#include "couchstore_config.h"
#include <libcouchstore/couch_db.h>
#include "../file_merger.h"
#include "../couch_btree.h"
#include "bitmap.h"

#ifdef __cplusplus
extern "C" {
#endif
    #define ZCODE_PRECISION 32
    #define ZCODE_MAX_VALUE UINT32_MAX

    typedef struct {
        double *mbb;
        /* the total number of values (two times the dimension) */
        uint16_t num;
    } sized_mbb_t;

    /* It is used to scale up MBBs to the relative size of an enclosing one */
    typedef struct {
        /* The offset the value needs to be shifted in order to be in the
         * origin of the enclosing MBB */
        double *offsets;
        /* The scale factors for every dimension */
        double *scales;
        /* the total number of values, one per dimension */
        uint8_t dim;
    } scale_factor_t;

    /* The context to build the initial index */
    typedef struct {
        arena                   *transient_arena;
        couchfile_modify_result *modify_result;
        /* Scale MBBs up for a better results when using the space filling
         * curve */
        scale_factor_t          *scale_factor;
    } view_spatial_builder_ctx_t;

    /* compare keys of a spatial index */
    int spatial_key_cmp(const sized_buf *key1, const sized_buf *key2,
                        const void *user_ctx);

    /* Compare keys of a spatial index for the file merger */
    int spatial_merger_key_cmp(const sized_buf *key1, const sized_buf *key2,
                               const void *user_ctx);

    /* Return the scale factor for every dimension that would be needed to
     * scale this MBB to the maximum value `max` (when shifted to the
     * origin)
     * Memory is dynamically allocted within the function, make sure to call
     * free_spatial_scale_factor() afterwards */
    scale_factor_t *spatial_scale_factor(const double *mbb, uint16_t dim,
                                         uint32_t max);

    /* Free the memory that spatial_scale_factor() allocated */
    void free_spatial_scale_factor(scale_factor_t *sf);

    /* Calculate the center of an multi-dimensional bounding box (MBB) */
    double *spatial_center(const sized_mbb_t *mbb);

    /* Scales all dimensions of a (multi-dimensional) point
     * with the given factor and offset */
    uint32_t *spatial_scale_point(const double *point,
                                  const scale_factor_t *sf);

    /* Set a bit on a buffer with a certain size */
    void set_bit_sized(unsigned char *bitmap, uint16_t size, uint16_t bit);

    /* Interleave numbers bitwise. The return value is a unsigned char array
     * with length 4 bytes * number of numbers.
     * The maximum number of numbers is (2^14)-1 (16383). */
    unsigned char *interleave_uint32s(uint32_t *numbers, uint16_t num);

    /* A reduce is used to calculate the enclosing MBB of a parent node (it's
     * its key) */
    couchstore_error_t view_spatial_reduce(char *dst,
                                           size_t *size_r,
                                           const nodelist *leaflist,
                                           int count,
                                           void *ctx);

    /* Puts an item into the results set. If there are enough items they are
     * are flused to disk */
    couchstore_error_t spatial_push_item(sized_buf *k, sized_buf *v,
                                         couchfile_modify_result *dst);

    /* Build an r-tree bottom-up from the already stored leaf nodes */
    node_pointer* complete_new_spatial(couchfile_modify_result* mr,
                                       couchstore_error_t *errcode);

    /* Filter function for the compactor */
    int view_spatial_filter(const sized_buf *k, const sized_buf *v,
                            const bitmap_t *bm);
#ifdef __cplusplus
}
#endif

#endif
