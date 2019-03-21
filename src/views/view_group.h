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

#ifndef COUCHSTORE_VIEW_GROUP_H
#define COUCHSTORE_VIEW_GROUP_H

#include "couchstore_config.h"
#include <stdio.h>
#include <libcouchstore/couch_db.h>
#include "index_header.h"
#include "compaction.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The maximum header size is based on the
 * couch_set_view_util:group_to_header_bin/1 function in couchdb */
#define MAX_VIEW_HEADER_SIZE (20 * 1024 * 1024)

    typedef enum {
        VIEW_INDEX_TYPE_MAPREDUCE,
        VIEW_INDEX_TYPE_SPATIAL
    }  view_index_type_t;

    typedef struct {
        const char *view_name;
        const char *error_msg;
        const char *idx_type;
    } view_error_t;

    typedef struct {
        int           view_id;
        int           num_reducers;
        const char  **names;
        const char  **reducers;
    } view_btree_info_t;

    typedef struct {
        /* Number of dimensions the multidimensional bounding box (MBB) has */
        uint16_t  dimension;
        /* The MBB that enclosed the whole spatial view*/
        double   *mbb;
    } view_spatial_info_t;

    typedef union {
        view_btree_info_t   *btree;
        view_spatial_info_t *spatial;
    } view_infos_t;

    typedef struct {
        const char        *filepath;
        uint64_t           header_pos;
        int                num_btrees;
        view_index_type_t  type;
        view_infos_t       view_infos;
        tree_file          file;
    } view_group_info_t;

    typedef struct {
       uint64_t ids_inserted;
       uint64_t ids_removed;
       uint64_t kvs_inserted;
       uint64_t kvs_removed;
       uint64_t purged;
    } view_group_update_stats_t;

    typedef struct {
        arena *transient_arena;
        couchfile_modify_result *modify_result;
    } view_btree_builder_ctx_t;

    /* Read a view group definition from an input stream, and write any
       errors to the optional error stream. */
    LIBCOUCHSTORE_API
    view_group_info_t *couchstore_read_view_group_info(FILE *in_stream,
                                                       FILE *error_stream);

    LIBCOUCHSTORE_API
    void couchstore_free_view_group_info(view_group_info_t *info);

    LIBCOUCHSTORE_API
    couchstore_error_t couchstore_build_view_group(view_group_info_t *info,
                                                   const char *id_records_file,
                                                   const char *kv_records_files[],
                                                   const char *dst_file,
                                                   const char *tmpdir,
                                                   uint64_t *header_pos,
                                                   view_error_t *error_info);

    couchstore_error_t read_view_group_header(view_group_info_t *info,
                                              index_header_t **header);

    couchstore_error_t write_view_group_header(tree_file *file,
                                               uint64_t *pos,
                                               const index_header_t *header);

    couchstore_error_t open_view_group_file(const char *path,
                                            couchstore_open_flags open_flags,
                                            tree_file *file);

    LIBCOUCHSTORE_API
    couchstore_error_t couchstore_cleanup_view_group(view_group_info_t *info,
                                                     uint64_t *header_pos,
                                                     uint64_t *purge_count,
                                                     view_error_t *error_info);

    LIBCOUCHSTORE_API
    couchstore_error_t couchstore_update_view_group(
                                               view_group_info_t *info,
                                               const char *id_records_file,
                                               const char *kv_records_files[],
                                               size_t batch_size,
                                               const sized_buf *header_buf,
                                               int is_sorted,
                                               const char *tmp_dir,
                                               view_group_update_stats_t *stats,
                                               sized_buf *header_outbuf,
                                               view_error_t *error_info);

    LIBCOUCHSTORE_API
    couchstore_error_t couchstore_compact_view_group(
                                                 view_group_info_t *info,
                                                 const char *target_file,
                                                 const sized_buf *header_buf,
                                                 compactor_stats_t *stats,
                                                 sized_buf *header_outbuf,
                                                 view_error_t *error_info);

#ifdef __cplusplus
}
#endif

#endif
