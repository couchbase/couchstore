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
    int ret = 0;
    couchstore_error_t errcode = COUCHSTORE_SUCCESS;
    view_id_btree_value_t *val = NULL;
    (void) k;

    errcode = decode_view_id_btree_value(v->buf, v->size, &val);
    if (errcode != COUCHSTORE_SUCCESS) {
        ret = (int) errcode;
        goto cleanup;
    }

    ret = is_bit_set(bm, val->partition);

cleanup:
    free_view_id_btree_value(val);
    return ret;
}

int view_btree_filter(const sized_buf *k, const sized_buf *v,
                                          const bitmap_t *bm)
{
    int ret = 0;
    couchstore_error_t errcode = COUCHSTORE_SUCCESS;
    view_btree_value_t *val = NULL;
    (void) k;

    errcode = decode_view_btree_value(v->buf, v->size, &val);
    if (errcode != COUCHSTORE_SUCCESS) {
        ret = (int) errcode;
        goto cleanup;
    }

    ret = is_bit_set(bm, val->partition);

cleanup:
    free_view_btree_value(val);
    return ret;
}
