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

#ifndef _VIEW_UTILS_H
#define _VIEW_UTILS_H

#include "couchstore_config.h"
#include <stdio.h>
#include <libcouchstore/couch_db.h>
#include "../file_merger.h"
#include "view_group.h"

#ifdef __cplusplus
extern "C" {
#endif

#pragma pack(push, 1)
    typedef struct {
        uint8_t   op;
        uint16_t  ksize;
        uint32_t  vsize;
    } view_file_merge_record_t;
#pragma pack(pop)

#define VIEW_RECORD_KEY(rec) (((char *) rec) + sizeof(view_file_merge_record_t))
#define VIEW_RECORD_VAL(rec) (VIEW_RECORD_KEY(rec) + rec->ksize)

    enum view_record_type {
        INITIAL_BUILD_VIEW_RECORD,
        INCREMENTAL_UPDATE_VIEW_RECORD,
        INITIAL_BUILD_SPATIAL_RECORD,
        INCREMENTAL_UPDATE_SPATIAL_RECORD
    };

    typedef struct {
        FILE *src_f;
        FILE *dst_f;
        enum view_record_type type;
        int (*key_cmp_fun)(const sized_buf *key1, const sized_buf *key2,
                           const void *user_ctx);
        const void *user_ctx;
    } view_file_merge_ctx_t;

    /* compare keys of a view btree */
    int view_key_cmp(const sized_buf *key1, const sized_buf *key2,
                     const void *user_ctx);

    /* compare keys of the id btree of an index */
    int view_id_cmp(const sized_buf *key1, const sized_buf *key2,
                    const void *user_ctx);

    /* read view index record from a file, obbeys the read record function
       prototype defined in src/file_merger.h */
    int read_view_record(FILE *in, void **buf, void *ctx);

    /* write view index record from a file, obbeys the write record function
       prototype defined in src/file_merger.h */
    file_merger_error_t write_view_record(FILE *out, void *buf, void *ctx);

    /* compare 2 view index records, obbeys the record compare function
       prototype defined in src/file_merger.h */
    int compare_view_records(const void *r1, const void *r2, void *ctx);

    /* Pick the winner from the duplicate entries */
    size_t dedup_view_records_merger(file_merger_record_t **records, size_t len, void *ctx);

    /* frees a view record, obbeys the record free function prototype
       defined in src/file_merger.h */
    void free_view_record(void *record, void *ctx);

    LIBCOUCHSTORE_API
    char *couchstore_read_line(FILE *in, char *buf, int size);

    LIBCOUCHSTORE_API
    uint64_t couchstore_read_int(FILE *in, char *buf, size_t size,
                                                      couchstore_error_t *ret);

    /* Generate appropriate view error messages */
    void set_error_info(const view_btree_info_t *info,
                        const char *red_error,
                        couchstore_error_t ret,
                        view_error_t *error_info);

#ifdef __cplusplus
}
#endif

#endif
