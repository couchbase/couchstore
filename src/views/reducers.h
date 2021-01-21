/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

/**
 * @copyright 2013 Couchbase, Inc.
 *
 * @author Filipe Manana  <filipe@couchbase.com>
 * @author Fulu Li        <fulu@couchbase.com>
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
#include "mapreduce/mapreduce.h"
#include <libcouchstore/couch_common.h>
#include <libcouchstore/couch_db.h>
#include <libcouchstore/visibility.h>
#include <cstdint>

struct view_reducer_ctx_t {
    /* If not NULL, an error happened and it contains a human
       readable error message. */
    const char* error;
    void* priv;
};

struct stats_t {
    uint64_t count;
    double sum, min, max, sumsqr;
};

view_reducer_ctx_t* make_view_reducer_ctx(const char* functions[],
                                          unsigned num_functions,
                                          char** error_msg);

void free_view_reducer_ctx(view_reducer_ctx_t* ctx);

couchstore_error_t view_id_btree_reduce(char* dst,
                                        size_t* size_r,
                                        const nodelist* leaflist,
                                        int count,
                                        void* ctx);

couchstore_error_t view_id_btree_rereduce(char* dst,
                                          size_t* size_r,
                                          const nodelist* itmlist,
                                          int count,
                                          void* ctx);

couchstore_error_t view_btree_reduce(char* dst,
                                     size_t* size_r,
                                     const nodelist* leaflist,
                                     int count,
                                     void* ctx);

couchstore_error_t view_btree_rereduce(char* dst,
                                       size_t* size_r,
                                       const nodelist* nodelist,
                                       int count,
                                       void* ctx);
