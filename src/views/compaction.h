/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

/**
 * @copyright 2014 Couchbase, Inc.
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

#pragma once

#include "../couch_btree.h"
#include "../internal.h"
#include "bitmap.h"
#include <libcouchstore/couch_common.h>
#include <libcouchstore/couch_db.h>
#include <libcouchstore/visibility.h>

/* Filter function to selectively ignore values during compaction */
typedef int (*compact_filter_fn)(const sized_buf* k,
                                 const sized_buf* v,
                                 const bitmap_t* bm);

/* Function spec for updating compactor progress */
typedef void (*stats_update_fn)(uint64_t freq, uint64_t inserted);

struct compactor_stats_t {
    uint64_t freq;
    uint64_t inserted;
    stats_update_fn update_fun;
};

/* Compaction context definition */
struct view_compact_ctx_t {
    couchfile_modify_result* mr;
    arena* transient_arena;
    const bitmap_t* filterbm;
    compact_filter_fn filter_fun;
    compactor_stats_t* stats;
};

int view_id_btree_filter(const sized_buf* k,
                         const sized_buf* v,
                         const bitmap_t* bm);

int view_btree_filter(const sized_buf* k,
                      const sized_buf* v,
                      const bitmap_t* bm);
