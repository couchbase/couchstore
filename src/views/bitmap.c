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

#include "couchstore_config.h"
#include "bitmap.h"
#include <string.h>

#define CHUNK_BITS            (sizeof(unsigned char) * CHAR_BIT)
#define TOTAL_CHUNKS(map)     sizeof(((map).chunks))
#define CHUNK_INDEX(map, bit) (TOTAL_CHUNKS(map) - 1 - ((bit) / CHUNK_BITS))
#define MAP_CHUNK(map, bit)   ((map).chunks)[CHUNK_INDEX(map, bit)]
#define CHUNK_OFFSET(bit)     ((bit) % CHUNK_BITS)


int is_bit_set(const bitmap_t *bm, uint16_t bit)
{
    return (MAP_CHUNK(*bm, bit) & (1 << CHUNK_OFFSET(bit))) != 0;
}


void set_bit(bitmap_t *bm, uint16_t bit)
{
    (MAP_CHUNK(*bm, bit)) |= (1 << CHUNK_OFFSET(bit));
}


void unset_bit(bitmap_t *bm, uint16_t bit)
{
    ((MAP_CHUNK(*bm, bit)) &= ~(1 << CHUNK_OFFSET(bit)));
}

void union_bitmaps(bitmap_t *dst_bm, const bitmap_t *src_bm)
{
    unsigned int i;
    for (i = 0; i < 1024 / CHUNK_BITS; ++i) {
        dst_bm->chunks[i] |= src_bm->chunks[i];
    }
}

void intersect_bitmaps(bitmap_t *dst_bm, const bitmap_t *src_bm)
{
    unsigned int i;
    for (i = 0; i < 1024 / CHUNK_BITS; ++i) {
        dst_bm->chunks[i] &= src_bm->chunks[i];
    }
}

int is_equal_bitmap(const bitmap_t *bm1, const bitmap_t *bm2)
{
    return !memcmp(bm1, bm2, sizeof(bitmap_t));
}
