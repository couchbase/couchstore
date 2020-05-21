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
#include "couchstore_config.h"
#include "bitmap.h"
#include "values.h"
#include "compaction.h"
#include "../couch_btree.h"

int view_id_btree_filter(const sized_buf *k, const sized_buf *v,
                                             const bitmap_t *bm)
{
    return is_bit_set(bm, decode_view_btree_partition(v->buf, v->size));
}

int view_btree_filter(const sized_buf *k, const sized_buf *v,
                                          const bitmap_t *bm)
{
    return is_bit_set(bm, decode_view_btree_partition(v->buf, v->size));
}
