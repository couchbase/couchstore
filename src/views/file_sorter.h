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

#ifndef _VIEW_FILE_SORTER_H
#define _VIEW_FILE_SORTER_H

#include "couchstore_config.h"
#include <libcouchstore/visibility.h>
#include "../file_sorter.h"
#include "util.h"

#ifdef __cplusplus
extern "C" {
#endif


    /*
     * Sort a file containing records of btree operations for a view btree.
     */
    LIBCOUCHSTORE_API
    file_sorter_error_t sort_view_kvs_ops_file(const char *file_path,
                                               const char *tmp_dir);

    /*
     * Sort a file containing view records for a view btree.
     */
    LIBCOUCHSTORE_API
    file_sorter_error_t sort_view_kvs_file(const char *file_path,
                                           const char *tmp_dir,
                                           file_merger_feed_record_t callback,
                                           void *user_ctx);

    /*
     * Sort a file containing records of btree operations for a view id
     * btree (back index).
     */
    LIBCOUCHSTORE_API
    file_sorter_error_t sort_view_ids_ops_file(const char *file_path,
                                               const char *tmp_dir);

    /*
     * Sort a file containing records for a view id btree (back index).
     */
    LIBCOUCHSTORE_API
    file_sorter_error_t sort_view_ids_file(const char *file_path,
                                           const char *tmp_dir,
                                           file_merger_feed_record_t callback,
                                           void *user_ctx);

    /*
     * Sort a file containing records for a spatial index.
     */
    LIBCOUCHSTORE_API
    file_sorter_error_t sort_spatial_kvs_file(const char *file_path,
                                              const char *tmp_dir,
                                              file_merger_feed_record_t callback,
                                              void *user_ctx);

    /*
     * Sort a file containing records of spatial index operations for a
     * spatial view.
     */
    LIBCOUCHSTORE_API
    file_sorter_error_t sort_spatial_kvs_ops_file(const char *file_path,
                                                  const char *tmp_dir,
                                                  view_file_merge_ctx_t *ctx);

    /* Record file sorter */
    typedef file_sorter_error_t (*sort_record_fn)(const char *file_path,
                                                  const char *tmp_dir,
                                                  file_merger_feed_record_t callback,
                                                  void *user_ctx);

#ifdef __cplusplus
}
#endif

#endif
