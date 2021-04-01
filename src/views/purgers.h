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

#pragma once

#include "../couch_btree.h"
#include "../internal.h"
#include "bitmap.h"
#include "mapreduce/mapreduce.h"
#include <libcouchstore/couch_common.h>
#include <libcouchstore/couch_db.h>
#include <libcouchstore/visibility.h>
#include <cstdint>

struct view_purger_ctx_t {
    bitmap_t cbitmask;
    uint64_t count{0};
};

int view_id_btree_purge_kv(const sized_buf* key,
                           const sized_buf* val,
                           void* ctx);
int view_id_btree_purge_kp(const node_pointer* ptr, void* ctx);
int view_btree_purge_kv(const sized_buf* key, const sized_buf* val, void* ctx);
int view_btree_purge_kp(const node_pointer* ptr, void* ctx);
