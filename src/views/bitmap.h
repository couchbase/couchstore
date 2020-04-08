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

#ifndef _BITMAP_H
#define _BITMAP_H

#include <climits>
#include <cstdint>

#ifdef __cplusplus
extern "C" {
#endif

struct bitmap_t {
    /* Big endian format.
     * chunk[0] msb contains msb of the 1024 bits bitmap.
     */
    unsigned char chunks[1024 / (sizeof(unsigned char) * CHAR_BIT)];
};

int  is_bit_set(const bitmap_t *bm, uint16_t bit);
void set_bit(bitmap_t *bm, uint16_t bit);
void unset_bit(bitmap_t *bm, uint16_t bit);
void union_bitmaps(bitmap_t *dst_bm, const bitmap_t *src_bm);
void intersect_bitmaps(bitmap_t *dst_bm, const bitmap_t *src_bm);
int is_equal_bitmap(const bitmap_t *bm1, const bitmap_t *bm2);


#ifdef __cplusplus
}
#endif

#endif
