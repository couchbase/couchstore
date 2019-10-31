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

#include "file_sorter.h"
#include "util.h"
#include "spatial.h"

#define SORT_MAX_BUFFER_SIZE       (64 * 1024 * 1024)
#define SORT_MAX_NUM_TMP_FILES     16


static file_sorter_error_t do_sort_file(const char *file_path,
                                        const char *tmp_dir,
                                        file_merger_feed_record_t callback,
                                        int skip_writeback,
                                        view_file_merge_ctx_t *ctx);

file_sorter_error_t sort_view_kvs_ops_file(const char *file_path,
                                           const char *tmp_dir)
{
    view_file_merge_ctx_t ctx;

    ctx.key_cmp_fun = view_key_cmp;
    ctx.type = INCREMENTAL_UPDATE_VIEW_RECORD;

    return do_sort_file(file_path, tmp_dir, NULL, 0, &ctx);
}

file_sorter_error_t sort_view_kvs_file(const char *file_path,
                                       const char *tmp_dir,
                                       file_merger_feed_record_t callback,
                                       void *user_ctx)
{
    view_file_merge_ctx_t ctx;

    ctx.key_cmp_fun = view_key_cmp;
    ctx.type = INITIAL_BUILD_VIEW_RECORD;
    ctx.user_ctx = user_ctx;

    return do_sort_file(file_path, tmp_dir, callback, 1, &ctx);
}

file_sorter_error_t sort_view_ids_ops_file(const char *file_path,
                                           const char *tmp_dir)
{
    view_file_merge_ctx_t ctx;

    ctx.key_cmp_fun = view_id_cmp;
    ctx.type = INCREMENTAL_UPDATE_VIEW_RECORD;

    return do_sort_file(file_path, tmp_dir, NULL, 0, &ctx);
}

file_sorter_error_t sort_view_ids_file(const char *file_path,
                                       const char *tmp_dir,
                                       file_merger_feed_record_t callback,
                                       void *user_ctx)
{
    view_file_merge_ctx_t ctx;

    ctx.key_cmp_fun = view_id_cmp;
    ctx.type = INITIAL_BUILD_VIEW_RECORD;
    ctx.user_ctx = user_ctx;

    return do_sort_file(file_path, tmp_dir, callback, 1, &ctx);
}

file_sorter_error_t sort_spatial_kvs_file(const char *file_path,
                                          const char *tmp_dir,
                                          file_merger_feed_record_t callback,
                                          void *user_ctx)
{
    file_sorter_error_t ret;
    view_file_merge_ctx_t ctx;

    ctx.key_cmp_fun = spatial_key_cmp;
    ctx.type = INITIAL_BUILD_SPATIAL_RECORD;
    ctx.user_ctx = user_ctx;

    ret = do_sort_file(file_path, tmp_dir, callback, 1, &ctx);

    return ret;
}

file_sorter_error_t sort_spatial_kvs_ops_file(const char *file_path,
                                              const char *tmp_dir,
                                              view_file_merge_ctx_t *ctx)
{
    return do_sort_file(file_path, tmp_dir, NULL, 0, ctx);
}


static file_sorter_error_t do_sort_file(const char *file_path,
                                        const char *tmp_dir,
                                        file_merger_feed_record_t callback,
                                        int skip_writeback,
                                        view_file_merge_ctx_t *ctx)
{
    return sort_file(file_path,
                     tmp_dir,
                     SORT_MAX_NUM_TMP_FILES,
                     SORT_MAX_BUFFER_SIZE,
                     read_view_record,
                     write_view_record,
                     callback,
                     compare_view_records,
                     free_view_record,
                     skip_writeback,
                     ctx);
}
