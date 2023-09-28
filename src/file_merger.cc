/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

/**
 * @copyright 2013 Couchbase, Inc.
 *
 * @author Filipe Manana  <filipe@couchbase.com>
 * @author Aliaksey Kandratsenka <alk@tut.by> (small optimization)
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

#include "file_merger.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <platform/cb_malloc.h>
#include <platform/cbassert.h>


typedef struct {
    void      *data;
    unsigned  file;
} record_t;

#define FREE_RECORD(ctx, rec)                                \
    do {                                                     \
        (*(ctx)->free_record)((rec)->data, (ctx)->user_ctx); \
        cb_free((rec));                                      \
    } while (0)

struct file_merger_ctx_t;

typedef struct {
    struct file_merger_ctx_t  *ctx;
    record_t                  **data;
    unsigned                  count;
} sorted_vector_t;

typedef struct file_merger_ctx_t {
    unsigned                            num_files;
    FILE                                **files;
    FILE                                *dest_file;
    file_merger_read_record_t           read_record;
    file_merger_write_record_t          write_record;
    file_merger_record_free_t           free_record;
    file_merger_compare_records_t       compare_records;
    file_merger_deduplicate_records_t   dedup_records;
    file_merger_feed_record_t           feed_record;
    void                                *user_ctx;
    sorted_vector_t                     sorted_vector;
} file_merger_ctx_t;


static int  init_sorted_vector(sorted_vector_t *sorted_vector, unsigned max_elements, file_merger_ctx_t *ctx);
static void sorted_vector_destroy(sorted_vector_t *sorted_vector);
static void sorted_vector_pop(sorted_vector_t *sorted_vector,
                              record_t ***records,
                              size_t *n);
static int  sorted_vector_add(sorted_vector_t *sorted_vector, record_t *record);

static file_merger_error_t do_merge_files(file_merger_ctx_t *ctx);
static void free_all_records(file_merger_ctx_t *ctx, record_t **records,
                             int offset, int num);


file_merger_error_t merge_files(const char *source_files[],
                                unsigned num_files,
                                const char *dest_file,
                                file_merger_read_record_t read_record,
                                file_merger_write_record_t write_record,
                                file_merger_feed_record_t feed_record,
                                file_merger_compare_records_t compare_records,
                                file_merger_deduplicate_records_t dedup_records,
                                file_merger_record_free_t free_record,
                                int skip_writeback,
                                void *user_ctx)
{
    file_merger_ctx_t ctx;
    file_merger_error_t ret;
    unsigned i, j;

    if (num_files == 0) {
        return FILE_MERGER_ERROR_BAD_ARG;
    }

    ctx.num_files = num_files;
    ctx.read_record = read_record;
    ctx.write_record = write_record;
    ctx.free_record = free_record;
    ctx.compare_records = compare_records;
    ctx.user_ctx = user_ctx;
    ctx.feed_record = feed_record;
    ctx.dedup_records = dedup_records;

    if (feed_record && skip_writeback) {
        ctx.dest_file = nullptr;
    } else {
        ctx.dest_file = fopen(dest_file, "ab");
    }

    if (!init_sorted_vector(&ctx.sorted_vector, num_files, &ctx)) {
        return FILE_MERGER_ERROR_ALLOC;
    }

    if (feed_record == nullptr && ctx.dest_file == nullptr) {
        sorted_vector_destroy(&ctx.sorted_vector);
        return FILE_MERGER_ERROR_OPEN_FILE;
    }

    ctx.files = (FILE **) cb_malloc(sizeof(FILE *) * num_files);

    if (ctx.files == nullptr) {
        sorted_vector_destroy(&ctx.sorted_vector);
        fclose(ctx.dest_file);
        return FILE_MERGER_ERROR_ALLOC;
    }

    for (i = 0; i < num_files; ++i) {
        ctx.files[i] = fopen(source_files[i], "rb");

        if (ctx.files[i] == nullptr) {
            fprintf(stderr, "Error while opening file %s errcode %s\n",
                    source_files[i], strerror(errno));
            for (j = 0; j < i; ++j) {
                fclose(ctx.files[j]);
            }
            cb_free(ctx.files);
            fclose(ctx.dest_file);
            sorted_vector_destroy(&ctx.sorted_vector);

            return FILE_MERGER_ERROR_OPEN_FILE;
        }
    }

    ret = do_merge_files(&ctx);

    for (i = 0; i < ctx.num_files; ++i) {
        if (ctx.files[i] != nullptr) {
            fclose(ctx.files[i]);
        }
    }
    cb_free(ctx.files);
    sorted_vector_destroy(&ctx.sorted_vector);
    if (ctx.dest_file) {
        fclose(ctx.dest_file);
    }

    return ret;
}


static file_merger_error_t do_merge_files(file_merger_ctx_t *ctx)
{
    for (size_t i = 0; i < ctx->num_files; ++i) {
        FILE *f = ctx->files[i];
        int record_len;
        void *record_data;
        record_t *record;

        record_len = (*ctx->read_record)(f, &record_data, ctx->user_ctx);

        if (record_len == 0) {
            fclose(f);
            ctx->files[i] = nullptr;
        } else if (record_len < 0) {
            return (file_merger_error_t) record_len;
        } else {
            int rv;
            record = (record_t *) cb_malloc(sizeof(*record));
            if (record == nullptr) {
                return FILE_MERGER_ERROR_ALLOC;
            }
            record->data = record_data;
            record->file = i;
            rv = sorted_vector_add(&ctx->sorted_vector, record);
            if (!rv) {
                FREE_RECORD(ctx, record);
                return FILE_MERGER_SORT_ERROR;
            }
        }
    }

    while (ctx->sorted_vector.count != 0) {
        record_t **records;
        size_t n;
        void *record_data;
        int record_len;
        file_merger_error_t ret;

        /* The head of the list is the required item which needs to be written
         * to the output destination records file.
         * For each duplicated item that is eliminated (elements of linked
         * list), we need to read one record from the same file as the
         * duplicated record came from and add them to the sort vector.
         */
        sorted_vector_pop(&ctx->sorted_vector, &records, &n);
        cb_assert(records != nullptr);
        cb_assert(n != 0);

        if (ctx->feed_record) {
            ret = (*ctx->feed_record)(records[0]->data, ctx->user_ctx);
            if (ret != FILE_MERGER_SUCCESS) {
                free_all_records(ctx, records, 0, n);
                return ret;
            }
        } else {
            cb_assert(ctx->dest_file != nullptr);
        }

        if (ctx->dest_file) {
            ret = (*ctx->write_record)(ctx->dest_file, records[0]->data, ctx->user_ctx);
            if (ret != FILE_MERGER_SUCCESS) {
                free_all_records(ctx, records, 0, n);
                return ret;
            }
        }

        for (size_t i = 0; i < n; i++) {
            record_len = (*ctx->read_record)(ctx->files[records[i]->file],
                                             &record_data,
                                             ctx->user_ctx);
            if (record_len == 0) {
                fclose(ctx->files[records[i]->file]);
                ctx->files[records[i]->file] = nullptr;
                FREE_RECORD(ctx, records[i]);

            } else if (record_len < 0) {
                free_all_records(ctx, records, i, n);
                return (file_merger_error_t) record_len;
            } else {
                int rv;
                (*ctx->free_record)(records[i]->data, ctx->user_ctx);
                records[i]->data = record_data;
                rv = sorted_vector_add(&ctx->sorted_vector, records[i]);
                if (!rv) {
                    free_all_records(ctx, records, i, n);
                    return FILE_MERGER_SORT_ERROR;
                }
            }
        }

        cb_free(records);
    }

    return FILE_MERGER_SUCCESS;
}


static void free_all_records(file_merger_ctx_t *ctx, record_t **records,
                             int offset, int num) {
    for (; offset < num; offset++) {
        FREE_RECORD(ctx, records[offset]);
    }
    cb_free(records);
}


static int init_sorted_vector(sorted_vector_t *sorted_vector,
                              unsigned max_elements,
                              file_merger_ctx_t *ctx)
{
    sorted_vector->data = (record_t **) cb_malloc(sizeof(record_t *) * max_elements);
    if (sorted_vector->data == nullptr) {
        return 0;
    }

    sorted_vector->count = 0;
    sorted_vector->ctx = ctx;

    return 1;
}


static void sorted_vector_destroy(sorted_vector_t *sorted_vector)
{
    unsigned i;

    for (i = 0; i < sorted_vector->count; ++i) {
        FREE_RECORD(sorted_vector->ctx, sorted_vector->data[i]);
    }

    cb_free(sorted_vector->data);
}


#define SORTED_VECTOR_CMP(h, a, b)  \
    (*(h)->ctx->compare_records)((a)->data, (b)->data, (h)->ctx->user_ctx)

static void sorted_vector_pop(sorted_vector_t *sorted_vector,
                              record_t ***records,
                              size_t *n)
{
    record_t *head;
    file_merger_record_t **duplicates;
    size_t i, j;

    if (sorted_vector->count == 0) {
        *records = nullptr;
        *n = 0;
        return;
    }

    /* For deduplication, return the list of records whose keys are equal.
     * Hence they can be eliminated from the sort vector and least element can
     * be picked for writing out to the output file.
     * */
    head = sorted_vector->data[0];

    for (i = 1; sorted_vector->ctx->dedup_records != nullptr &&
                i < sorted_vector->count;
         i++) {
        if (SORTED_VECTOR_CMP(sorted_vector, head, sorted_vector->data[i]) != 0) {
            break;
        }
    }

    *records = (record_t **) cb_malloc(sizeof(record_t *) * i);
    memcpy(*records, sorted_vector->data, sizeof(record_t *) * i);
    *n = i;


    if (i > 1) {
        record_t *tmp;
        duplicates = (file_merger_record_t **) *records;
        j = sorted_vector->ctx->dedup_records(duplicates, i, sorted_vector->ctx->user_ctx);
        tmp = (*records)[0];
        (*records)[0] = (*records)[j];
        (*records)[j] = tmp;
    }

    sorted_vector->count -= i;
    memmove(sorted_vector->data + 0, sorted_vector->data + i,
            sizeof(sorted_vector->data[0]) * (sorted_vector->count));
}


static int sorted_vector_add(sorted_vector_t *sorted_vector, record_t *record)
{
    unsigned l, r;

    if (sorted_vector->count == sorted_vector->ctx->num_files) {
        /* sorted_vector full */
        return 0;
    }

    l = 0;
    r = sorted_vector->count;
    while (r - l > 1) {
        unsigned pos = (l + r) / 2;

        if (SORTED_VECTOR_CMP(sorted_vector, record, sorted_vector->data[pos]) < 0) {
            r = pos;
        } else {
            l = pos;
        }
    }

    if (l == 0 && r != 0) {
        if (SORTED_VECTOR_CMP(sorted_vector, record, sorted_vector->data[0]) < 0) {
            r = 0;
        }
    }

    if (r < sorted_vector->count) {
        memmove(sorted_vector->data + r + 1,
                sorted_vector->data + r,
                sizeof(sorted_vector->data[0]) * (sorted_vector->count - r));
    }

    sorted_vector->count += 1;

    sorted_vector->data[r] = record;

    return 1;
}
