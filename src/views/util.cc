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

#include <platform/cb_malloc.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"
#include "../util.h"
#include "../bitfield.h"
#include "collate_json.h"


static bool is_incremental_update_record(view_file_merge_ctx_t *ctx) {
    return ctx->type == INCREMENTAL_UPDATE_VIEW_RECORD ||
            ctx->type == INCREMENTAL_UPDATE_SPATIAL_RECORD;
}


int view_key_cmp(const sized_buf *key1, const sized_buf *key2,
                 const void *user_ctx)
{
    uint16_t json_key1_len = decode_raw16(*((raw_16 *) key1->buf));
    uint16_t json_key2_len = decode_raw16(*((raw_16 *) key2->buf));
    sized_buf json_key1;
    sized_buf json_key2;
    sized_buf doc_id1;
    sized_buf doc_id2;
    int res;

    (void)user_ctx;

    json_key1.buf = key1->buf + sizeof(uint16_t);
    json_key1.size = json_key1_len;
    json_key2.buf = key2->buf + sizeof(uint16_t);
    json_key2.size = json_key2_len;

    res = CollateJSON(&json_key1, &json_key2, kCollateJSON_Unicode);

    if (res == 0) {
        doc_id1.buf = key1->buf + sizeof(uint16_t) + json_key1.size;
        doc_id1.size = key1->size - sizeof(uint16_t) - json_key1.size;
        doc_id2.buf = key2->buf + sizeof(uint16_t) + json_key2.size;
        doc_id2.size = key2->size - sizeof(uint16_t) - json_key2.size;

        res = ebin_cmp(&doc_id1, &doc_id2);
    }

    return res;
}


int view_id_cmp(const sized_buf *key1, const sized_buf *key2,
                const void *user_ctx)
{
    (void)user_ctx;
    return ebin_cmp(key1, key2);
}


int read_view_record(FILE *in, void **buf, void *ctx)
{
    uint32_t len, vlen;
    uint16_t klen;
    uint8_t op = 0;
    view_file_merge_record_t *rec;
    view_file_merge_ctx_t *merge_ctx = (view_file_merge_ctx_t *) ctx;

    /* On disk format is a bit weird, but it's compatible with what
       Erlang's file_sorter module requires. */

    if (fread(&len, sizeof(len), 1, in) != 1) {
        if (feof(in)) {
            return 0;
        } else {
            return FILE_MERGER_ERROR_FILE_READ;
        }
    }
    if (is_incremental_update_record(merge_ctx)) {
        if (fread(&op, sizeof(rec->op), 1, in) != 1) {
            return FILE_MERGER_ERROR_FILE_READ;
        }
    }
    if (fread(&klen, sizeof(klen), 1, in) != 1) {
        return FILE_MERGER_ERROR_FILE_READ;
    }

    klen = ntohs(klen);
    vlen = len - sizeof(klen) - klen;
    if (is_incremental_update_record(merge_ctx)) {
        vlen -= sizeof(op);
    }

    rec = (view_file_merge_record_t *) cb_malloc(sizeof(*rec) + klen + vlen);
    if (rec == NULL) {
        return FILE_MERGER_ERROR_ALLOC;
    }

    rec->op = op;
    rec->ksize = klen;
    rec->vsize = vlen;

    if (fread(VIEW_RECORD_KEY(rec), klen + vlen, 1, in) != 1) {
        cb_free(rec);
        return FILE_MERGER_ERROR_FILE_READ;
    }

    *buf = (void *) rec;

    return klen + vlen;
}


file_merger_error_t write_view_record(FILE *out, void *buf, void *ctx)
{
    view_file_merge_record_t *rec = (view_file_merge_record_t *) buf;
    uint16_t klen = htons((uint16_t) rec->ksize);
    uint32_t len;
    view_file_merge_ctx_t *merge_ctx = (view_file_merge_ctx_t *) ctx;

    len = (uint32_t)  sizeof(klen) + rec->ksize + rec->vsize;
    if (is_incremental_update_record(merge_ctx)) {
        len += (uint32_t) sizeof(rec->op);
    }

    if (fwrite(&len, sizeof(len), 1, out) != 1) {
        return FILE_MERGER_ERROR_FILE_WRITE;
    }
    if (is_incremental_update_record(merge_ctx)) {
        if (fwrite(&rec->op, sizeof(rec->op), 1, out) != 1) {
            return FILE_MERGER_ERROR_FILE_WRITE;
        }
    }
    if (fwrite(&klen, sizeof(klen), 1, out) != 1) {
        return FILE_MERGER_ERROR_FILE_WRITE;
    }
    if (fwrite(VIEW_RECORD_KEY(rec), rec->ksize + rec->vsize, 1, out) != 1) {
        return FILE_MERGER_ERROR_FILE_WRITE;
    }

    return FILE_MERGER_SUCCESS;
}


int compare_view_records(const void *r1, const void *r2, void *ctx)
{
    view_file_merge_ctx_t *merge_ctx = (view_file_merge_ctx_t *) ctx;
    view_file_merge_record_t *rec1 = (view_file_merge_record_t *) r1;
    view_file_merge_record_t *rec2 = (view_file_merge_record_t *) r2;
    sized_buf k1, k2;

    k1.size = rec1->ksize;
    k1.buf = VIEW_RECORD_KEY(rec1);

    k2.size = rec2->ksize;
    k2.buf = VIEW_RECORD_KEY(rec2);

    return merge_ctx->key_cmp_fun(&k1, &k2, merge_ctx->user_ctx);
}


size_t dedup_view_records_merger(file_merger_record_t **records, size_t len, void *ctx)
{
    size_t i;
    size_t max = 0;
    (void) ctx;

    for (i = 1; i < len; i++) {
        if (records[max]->filenum < records[i]->filenum) {
            max = i;
        }
    }

    return max;
}


void free_view_record(void *record, void *ctx)
{
    (void) ctx;
    cb_free(record);
}

char *couchstore_read_line(FILE *in, char *buf, int size)
{
    size_t len;

    if (fgets(buf, size, in) != buf) {
        return NULL;
    }

    len = strlen(buf);
    if ((len >= 1) && (buf[len - 1] == '\n')) {
        buf[len - 1] = '\0';
    }

    return buf;
}

uint64_t couchstore_read_int(FILE *in, char *buf, size_t size,
                                                  couchstore_error_t *ret)
{
    uint64_t val;
    *ret = COUCHSTORE_SUCCESS;

    if (couchstore_read_line(in, buf, size) != buf) {
        *ret = COUCHSTORE_ERROR_READ;
        return 0;
    }

    if (sscanf(buf, "%" SCNu64, &val) != 1) {
        *ret = COUCHSTORE_ERROR_READ;
        return 0;
    }

    return val;
}


void set_error_info(const view_btree_info_t *info,
                    const char *red_error,
                    couchstore_error_t ret,
                    view_error_t *error_info)
{
    if (ret == COUCHSTORE_SUCCESS) {
        return;
    }

    if (red_error) {
        error_info->error_msg = (const char *) cb_strdup(red_error);
        error_info->idx_type = "MAPREDUCE";
    } else {
        /* TODO: add more human friendly messages for other error types */
        const int buffersize = 128;
        char* buf = (char*)cb_malloc(buffersize);

        if (buf != NULL) {
            size_t len = 0;

            switch (ret) {
            case COUCHSTORE_ERROR_REDUCTION_TOO_LARGE:
                len = snprintf(buf, buffersize,
                               "(view %d) reduction too large, ret = %d",
                               info->view_id,
                               ret);
                error_info->idx_type = "MAPREDUCE";
                break;

            default:
                len = snprintf(buf, buffersize, "(view %d) failed, ret = %d",
                               info->view_id, ret);
            }

            if (len > 0 && len < buffersize) {
                error_info->error_msg = buf;
            } else {
                cb_free(buf);
                error_info->error_msg = cb_strdup("Failed to build error message");
            }
        }
    }

    if (info->num_reducers) {
        error_info->view_name = (const char *) cb_strdup(info->names[0]);
    }
}
