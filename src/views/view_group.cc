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

#include "couchstore_config.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "view_group.h"
#include "reducers.h"
#include "reductions.h"
#include "values.h"
#include "purgers.h"
#include "util.h"
#include "file_sorter.h"
#include "spatial.h"
#include "../arena.h"
#include "../couch_btree.h"
#include "../internal.h"
#include "../util.h"
#include <platform/cb_malloc.h>
#include <platform/cbassert.h>

#define VIEW_KV_CHUNK_THRESHOLD (7 * 1024)
#define VIEW_KP_CHUNK_THRESHOLD (6 * 1024)
#define MAX_ACTIONS_SIZE        (2 * 1024 * 1024)

static couchstore_error_t read_btree_info(view_group_info_t *info,
                                          FILE *in_stream,
                                          FILE *error_stream);

static couchstore_error_t read_spatial_info(view_group_info_t *info,
                                            FILE *in_stream,
                                            FILE *error_stream);

static couchstore_error_t build_btree(const char *source_file,
                                      tree_file *dest_file,
                                      compare_info *cmp,
                                      reduce_fn reduce_fun,
                                      reduce_fn rereduce_fun,
                                      const char *tmpdir,
                                      sort_record_fn sort_fun,
                                      void *reduce_ctx,
                                      node_pointer **out_root);

static couchstore_error_t build_id_btree(const char *source_file,
                                         tree_file *dest_file,
                                         const char *tmpdir,
                                         node_pointer **out_root);

static couchstore_error_t build_view_btree(const char *source_file,
                                           const view_btree_info_t *info,
                                           tree_file *dest_file,
                                           const char *tmpdir,
                                           node_pointer **out_root,
                                           view_error_t *error_info);

static void close_view_group_file(view_group_info_t *info);

static int read_record(FILE *f, arena *a, sized_buf *k, sized_buf *v,
                                                        uint8_t *op);

extern "C" {
    int view_btree_cmp(const sized_buf *key1, const sized_buf *key2);
}
static couchstore_error_t update_btree(const char *source_file,
                                       tree_file *dest_file,
                                       const node_pointer *root,
                                       size_t batch_size,
                                       compare_info *cmp,
                                       reduce_fn reduce_fun,
                                       reduce_fn rereduce_fun,
                                       purge_kv_fn purge_kv,
                                       purge_kp_fn purge_kp,
                                       view_reducer_ctx_t *red_ctx,
                                       view_purger_ctx_t *purge_ctx,
                                       uint64_t *inserted,
                                       uint64_t *removed,
                                       node_pointer **out_root);

static couchstore_error_t update_id_btree(const char *source_file,
                                         tree_file *dest_file,
                                         const node_pointer *root,
                                         size_t batch_size,
                                         view_purger_ctx_t *purge_ctx,
                                         uint64_t *inserted,
                                         uint64_t *removed,
                                         node_pointer **out_root);

static couchstore_error_t update_view_btree(const char *source_file,
                                            const view_btree_info_t *info,
                                            tree_file *dest_file,
                                            const node_pointer *root,
                                            size_t batch_size,
                                            view_purger_ctx_t *purge_ctx,
                                            uint64_t *inserted,
                                            uint64_t *removed,
                                            node_pointer **out_root,
                                            view_error_t *error_info);

static couchstore_error_t compact_view_fetchcb(couchfile_lookup_request *rq,
                                        const sized_buf *k,
                                        const sized_buf *v);

static couchstore_error_t compact_btree(tree_file *source,
                                 tree_file *target,
                                 const node_pointer *root,
                                 compare_info *cmp,
                                 reduce_fn reduce_fun,
                                 reduce_fn rereduce_fun,
                                 compact_filter_fn filter_fun,
                                 view_reducer_ctx_t *red_ctx,
                                 const bitmap_t *filterbm,
                                 compactor_stats_t *stats,
                                 node_pointer **out_root);

static couchstore_error_t compact_id_btree(tree_file *source,
                                    tree_file *target,
                                    const node_pointer *root,
                                    const bitmap_t *filterbm,
                                    compactor_stats_t *stats,
                                    node_pointer **out_root);

static couchstore_error_t compact_view_btree(tree_file *source,
                                      tree_file *target,
                                      const view_btree_info_t *info,
                                      const node_pointer *root,
                                      const bitmap_t *filterbm,
                                      compactor_stats_t *stats,
                                      node_pointer **out_root,
                                      view_error_t *error_info);

/* Some preparations before building the actual spatial index */
static couchstore_error_t build_view_spatial(const char *source_file,
                                             const view_spatial_info_t *info,
                                             tree_file *dest_file,
                                             const char *tmpdir,
                                             node_pointer **out_root,
                                             view_error_t *error_info);

/* Build the actual spatial index */
static couchstore_error_t build_spatial(const char *source_file,
                                        tree_file *dest_file,
                                        compare_info *cmp,
                                        reduce_fn reduce_fun,
                                        reduce_fn rereduce_fun,
                                        const uint16_t dimension,
                                        const double *mbb,
                                        const char *tmpdir,
                                        sort_record_fn sort_fun,
                                        node_pointer **out_root);

/* Callback for every item that got fetched from the original view */
static couchstore_error_t compact_spatial_fetchcb(couchfile_lookup_request *rq,
                                                  const sized_buf *k,
                                                  const sized_buf *v);

/* Some preparations before compacting the actual spatial index */
static couchstore_error_t compact_view_spatial(tree_file *source,
                                               tree_file *target,
                                               const view_spatial_info_t *info,
                                               const node_pointer *root,
                                               const bitmap_t *filterbm,
                                               compactor_stats_t *stats,
                                               node_pointer **out_root,
                                               view_error_t *error_info);

/* Compact the actual spatial index */
static couchstore_error_t compact_spatial(tree_file *source,
                                          tree_file *target,
                                          const node_pointer *root,
                                          compare_info *cmp,
                                          reduce_fn reduce_fun,
                                          reduce_fn rereduce_fun,
                                          compact_filter_fn filter_fun,
                                          const bitmap_t *filterbm,
                                          compactor_stats_t *stats,
                                          node_pointer **out_root);

view_group_info_t *couchstore_read_view_group_info(FILE *in_stream,
                                                   FILE *error_stream)
{
    view_group_info_t *info;
    char buf[4096];
    char *dup;
    couchstore_error_t ret;
    uint64_t type;

    info = (view_group_info_t *) cb_calloc(1, sizeof(*info));
    if (info == NULL) {
        fprintf(error_stream, "Memory allocation failure\n");
        goto out_error;
    }

    type = couchstore_read_int(in_stream, buf, sizeof(buf), &ret);
    if (ret != COUCHSTORE_SUCCESS) {
        fprintf(stderr, "Error reading view file type\n");
        goto out_error;
    }
    switch (type) {
    case VIEW_INDEX_TYPE_MAPREDUCE:
        info->type = VIEW_INDEX_TYPE_MAPREDUCE;
        break;
    case VIEW_INDEX_TYPE_SPATIAL:
        info->type = VIEW_INDEX_TYPE_SPATIAL;
        break;
    default:
        fprintf(stderr, "Invalid view file type: %" PRIu64 "\n", type);
        goto out_error;
    }

    if (couchstore_read_line(in_stream, buf, sizeof(buf)) != buf) {
        fprintf(stderr, "Error reading source index file path\n");
        goto out_error;
    }
    dup = cb_strdup(buf);
    if (dup == NULL) {
        fprintf(error_stream, "Memory allocation failure\n");
        goto out_error;
    }
    info->filepath = (const char *) dup;

    info->header_pos = couchstore_read_int(in_stream, buf,
                                                      sizeof(buf),
                                                      &ret);
    if (ret != COUCHSTORE_SUCCESS) {
        fprintf(error_stream, "Error reading header position\n");
        goto out_error;
    }

    info->num_btrees = couchstore_read_int(in_stream, buf,
                                                      sizeof(buf),
                                                      &ret);
    if (ret != COUCHSTORE_SUCCESS) {
        fprintf(error_stream, "Error reading number of btrees\n");
        goto out_error;
    }

    switch (info->type) {
    case VIEW_INDEX_TYPE_MAPREDUCE:
        ret = read_btree_info(info, in_stream, error_stream);
        break;
    case VIEW_INDEX_TYPE_SPATIAL:
        ret = read_spatial_info(info, in_stream, error_stream);
        break;
    }
    if (ret != COUCHSTORE_SUCCESS) {
        goto out_error;
    }

    return info;

out_error:
    couchstore_free_view_group_info(info);

    return NULL;
}


/* Read in the information about the mapreduce view indexes */
static couchstore_error_t read_btree_info(view_group_info_t *info,
                                          FILE *in_stream,
                                          FILE *error_stream)
{
    char buf[4096];
    char *dup;
    int i, j;
    int reduce_len;
    couchstore_error_t ret;

    info->view_infos.btree = (view_btree_info_t *)
        cb_calloc(info->num_btrees, sizeof(view_btree_info_t));
    if (info->view_infos.btree == NULL) {
        fprintf(error_stream, "Memory allocation failure on btree infos\n");
        info->num_btrees = 0;
        return COUCHSTORE_ERROR_ALLOC_FAIL;
    }

    for (i = 0; i < info->num_btrees; ++i) {
        view_btree_info_t *bti = &info->view_infos.btree[i];

        bti->view_id = i;
        bti->num_reducers = couchstore_read_int(in_stream,
                                                buf,
                                                sizeof(buf),
                                                &ret);

        if (ret != COUCHSTORE_SUCCESS) {
            fprintf(error_stream,
                    "Error reading number of reducers for btree %d\n", i);
            return COUCHSTORE_ERROR_INVALID_ARGUMENTS;
        }

        bti->names = (const char **) cb_calloc(bti->num_reducers, sizeof(char *));
        if (bti->names == NULL) {
            fprintf(error_stream,
                    "Memory allocation failure on btree %d reducer names\n",
                    i);
            bti->num_reducers = 0;
            return COUCHSTORE_ERROR_ALLOC_FAIL;
        }

        bti->reducers = (const char **) cb_calloc(bti->num_reducers, sizeof(char *));
        if (bti->reducers == NULL) {
            fprintf(error_stream,
                    "Memory allocation failure on btree %d reducers\n", i);
            bti->num_reducers = 0;
            cb_free(bti->names);
            return COUCHSTORE_ERROR_ALLOC_FAIL;
        }

        for (j = 0; j < bti->num_reducers; ++j) {
            if (couchstore_read_line(in_stream, buf, sizeof(buf)) != buf) {
                fprintf(error_stream,
                        "Error reading btree %d view %d name\n", i, j);
                return COUCHSTORE_ERROR_INVALID_ARGUMENTS;
            }
            dup = cb_strdup(buf);
            if (dup == NULL) {
                fprintf(error_stream,
                        "Memory allocation failure on btree %d "
                        "view %d name\n", i, j);
                return COUCHSTORE_ERROR_ALLOC_FAIL;
            }
            bti->names[j] = (const char *) dup;

            reduce_len = couchstore_read_int(in_stream,
                                             buf,
                                             sizeof(buf),
                                             &ret);
            if (ret != COUCHSTORE_SUCCESS) {
                fprintf(error_stream,
                        "Error reading btree %d view %d "
                        "reduce function size\n", i, j);
                return COUCHSTORE_ERROR_INVALID_ARGUMENTS;
            }

            dup = (char *) cb_malloc(reduce_len + 1);
            if (dup == NULL) {
                fprintf(error_stream,
                        "Memory allocation failure on btree %d "
                        "view %d reducer\n", i, j);
                return COUCHSTORE_ERROR_ALLOC_FAIL;
            }

            if (fread(dup, reduce_len, 1, in_stream) != 1) {
                fprintf(error_stream,
                        "Error reading btree %d view %d reducer\n", i, j);
                cb_free(dup);
                return COUCHSTORE_ERROR_INVALID_ARGUMENTS;
            }
            dup[reduce_len] = '\0';
            bti->reducers[j] = (const char *) dup;
        }
    }
    return COUCHSTORE_SUCCESS;
}


/* Read in the information about the spatial view indexes */
static couchstore_error_t read_spatial_info(view_group_info_t *info,
                                            FILE *in_stream,
                                            FILE *error_stream)
{
    char buf[24];
    int i;
    couchstore_error_t ret;

    info->view_infos.spatial = (view_spatial_info_t *)
        cb_calloc(info->num_btrees, sizeof(view_spatial_info_t));
    if (info->view_infos.spatial == NULL) {
        fprintf(error_stream, "Memory allocation failure on spatial infos\n");
        info->num_btrees = 0;
        return COUCHSTORE_ERROR_ALLOC_FAIL;
    }

    for (i = 0; i < info->num_btrees; ++i) {
        view_spatial_info_t *si = &info->view_infos.spatial[i];

        si->dimension = couchstore_read_int(in_stream, buf, sizeof(buf), &ret);

        if (ret != COUCHSTORE_SUCCESS) {
            fprintf(error_stream,
                    "Error reading the dimension of spatial view %d\n", i);
            return COUCHSTORE_ERROR_INVALID_ARGUMENTS;
        }

        /* If the dimension is 0, no index exists or hasn't been built yet */
        if (si->dimension == 0) {
            continue;
        }

        si->mbb = (double *) cb_calloc(si->dimension * 2, sizeof(double));
        if (si->mbb == NULL) {
            fprintf(error_stream,
                    "Memory allocation failure on spatial view %d\n", i);
            si->dimension = 0;
            return COUCHSTORE_ERROR_ALLOC_FAIL;
        }

        if (fread(si->mbb, sizeof(double), si->dimension * 2, in_stream) <
                si->dimension * 2) {
            fprintf(error_stream, "Error reading mbb of view %d\n", i);
            return COUCHSTORE_ERROR_INVALID_ARGUMENTS;
        }
    }
    return COUCHSTORE_SUCCESS;
}

void couchstore_free_view_group_info(view_group_info_t *info)
{
    int i, j;

    if (info == NULL)
        return;

    close_view_group_file(info);

    switch (info->type) {
    case VIEW_INDEX_TYPE_MAPREDUCE:
        for (i = 0; i < info->num_btrees; ++i) {
            view_btree_info_t vi = info->view_infos.btree[i];

            for (j = 0; j < vi.num_reducers; ++j) {
                cb_free((void *) vi.names[j]);
                cb_free((void *) vi.reducers[j]);
            }
            cb_free(vi.names);
            cb_free(vi.reducers);
        }
        cb_free(info->view_infos.btree);
        break;
    case VIEW_INDEX_TYPE_SPATIAL:
        for (i = 0; i < info->num_btrees; ++i) {
            cb_free((void *) info->view_infos.spatial[i].mbb);
        }
        cb_free(info->view_infos.spatial);
        break;
    }
    cb_free((void *) info->filepath);
    cb_free(info);
}


static void close_view_group_file(view_group_info_t *info)
{
    if (info->file.ops != NULL) {
        info->file.ops->close(&info->file.lastError, info->file.handle);
        info->file.ops->destructor(info->file.handle);
        info->file.ops = NULL;
        info->file.handle = NULL;
    }
    cb_free((void *) info->file.path);
    info->file.path = NULL;
}


couchstore_error_t open_view_group_file(const char *path,
                                               couchstore_open_flags open_flags,
                                               tree_file *file)
{
    couchstore_error_t ret;
    FileOpsInterface* file_ops = couchstore_get_default_file_ops();
    int flags = 0;

    if ((open_flags & COUCHSTORE_OPEN_FLAG_RDONLY) &&
        (open_flags & COUCHSTORE_OPEN_FLAG_CREATE)) {
        return COUCHSTORE_ERROR_INVALID_ARGUMENTS;
    }

    if (open_flags & COUCHSTORE_OPEN_FLAG_RDONLY) {
        flags |= O_RDONLY;
    } else {
        flags |= O_RDWR;
    }

    if (open_flags & COUCHSTORE_OPEN_FLAG_CREATE) {
        flags |= O_CREAT;
    }

    ret = tree_file_open(file, path, flags, CRC32, file_ops,
                         tree_file_options() /* Enable buffered IO by default. */);

    return ret;
}

couchstore_error_t couchstore_build_view_group(view_group_info_t *info,
                                               const char *id_records_file,
                                               const char *kv_records_files[],
                                               const char *dst_file,
                                               const char *tmpdir,
                                               uint64_t *header_pos,
                                               view_error_t *error_info)
{
    couchstore_error_t ret;
    tree_file index_file;
    index_header_t *header = NULL;
    node_pointer *id_root = NULL;
    node_pointer **view_roots = NULL;
    int i;

    error_info->view_name = NULL;
    error_info->error_msg = NULL;
    index_file.handle = NULL;
    index_file.ops = NULL;
    index_file.path = NULL;

    view_roots = (node_pointer **) cb_calloc(
        info->num_btrees, sizeof(node_pointer *));
    if (view_roots == NULL) {
        return COUCHSTORE_ERROR_ALLOC_FAIL;
    }

    ret = open_view_group_file(info->filepath,
                               COUCHSTORE_OPEN_FLAG_RDONLY,
                               &info->file);
    if (ret != COUCHSTORE_SUCCESS) {
        goto out;
    }

    ret = read_view_group_header(info, &header);
    if (ret != COUCHSTORE_SUCCESS) {
        goto out;
    }
    cb_assert(info->num_btrees == header->num_views);

    ret = open_view_group_file(dst_file,
                               COUCHSTORE_OPEN_FLAG_CREATE,
                               &index_file);
    if (ret != COUCHSTORE_SUCCESS) {
        goto out;
    }

    ret = build_id_btree(id_records_file, &index_file, tmpdir, &id_root);
    if (ret != COUCHSTORE_SUCCESS) {
        goto out;
    }

    cb_free(header->id_btree_state);
    header->id_btree_state = id_root;
    id_root = NULL;

    for (i = 0; i < info->num_btrees; ++i) {
        switch(info->type) {
        case VIEW_INDEX_TYPE_MAPREDUCE:
            ret = build_view_btree(kv_records_files[i],
                                   &info->view_infos.btree[i],
                                   &index_file,
                                   tmpdir,
                                   &view_roots[i],
                                   error_info);
            break;
        case VIEW_INDEX_TYPE_SPATIAL:
            ret = build_view_spatial(kv_records_files[i],
                                     &info->view_infos.spatial[i],
                                     &index_file,
                                     tmpdir,
                                     &view_roots[i],
                                     error_info);
            break;
        }
        if (ret != COUCHSTORE_SUCCESS) {
            goto out;
        }

        cb_free(header->view_states[i]);
        header->view_states[i] = view_roots[i];
        view_roots[i] = NULL;
    }

    ret = write_view_group_header(&index_file, header_pos, header);
    if (ret != COUCHSTORE_SUCCESS) {
        goto out;
    }

    ret = COUCHSTORE_SUCCESS;

out:
    free_index_header(header);
    close_view_group_file(info);
    tree_file_close(&index_file);
    cb_free(id_root);
    if (view_roots != NULL) {
        for (i = 0; i < info->num_btrees; ++i) {
            cb_free(view_roots[i]);
        }
        cb_free(view_roots);
    }

    return ret;
}


/*
 * Similar to util.c:read_view_record(), but it uses arena allocator, which is
 * required for the existing semantics/api of btree bottom-up build in
 * src/btree_modify.cc.
 */
static int read_record(FILE *f, arena *a, sized_buf *k, sized_buf *v,
                                                        uint8_t *op)
{
    uint16_t klen;
    uint8_t oplen = 0;
    uint32_t vlen, len;

    if (fread(&len, sizeof(len), 1, f) != 1) {
        if (feof(f)) {
            return 0;
        } else {
            return COUCHSTORE_ERROR_READ;
        }
    }

    /* For incremental update, read optype */
    if (op != NULL) {
        if (fread(op, sizeof(uint8_t), 1, f) != 1) {
            return COUCHSTORE_ERROR_READ;
        }

        oplen = 1;
    }

    if (fread(&klen, sizeof(klen), 1, f) != 1) {
        return COUCHSTORE_ERROR_READ;
    }

    klen = ntohs(klen);
    vlen = len - sizeof(klen) - klen - oplen;

    k->size = klen;
    k->buf = (char *) arena_alloc(a, k->size);
    if (k->buf == NULL) {
        return COUCHSTORE_ERROR_ALLOC_FAIL;
    }

    v->size = vlen;
    /* Handle zero len vals */
    if (v->size) {
        v->buf = (char *) arena_alloc(a, v->size);
        if (v->buf == NULL) {
            return COUCHSTORE_ERROR_ALLOC_FAIL;
        }
    } else {
        v->buf = NULL;
    }

    if (fread(k->buf, k->size, 1, f) != 1) {
        return FILE_MERGER_ERROR_FILE_READ;
    }

    if (v->size && fread(v->buf, v->size, 1, f) != 1) {
        return FILE_MERGER_ERROR_FILE_READ;
    }

    return len;
}


static int id_btree_cmp(const sized_buf *key1, const sized_buf *key2)
{
    return view_id_cmp(key1, key2, NULL);
}


int view_btree_cmp(const sized_buf *key1, const sized_buf *key2)
{
    return view_key_cmp(key1, key2, NULL);
}


/*
 * For initial btree build, feed the btree builder as soon as
 * sorted records are available.
 */
static file_merger_error_t build_btree_record_callback(void *buf, void *ctx)
{
    int ret;
    sized_buf *k, *v;
    view_file_merge_record_t *rec = (view_file_merge_record_t *) buf;
    view_file_merge_ctx_t *merge_ctx = (view_file_merge_ctx_t *) ctx;
    view_btree_builder_ctx_t *build_ctx =
                    (view_btree_builder_ctx_t *) merge_ctx->user_ctx;
    sized_buf src_k, src_v;

    src_k.size = rec->ksize;
    src_k.buf = VIEW_RECORD_KEY(rec);
    src_v.size = rec->vsize;
    src_v.buf = VIEW_RECORD_VAL(rec);

    k = arena_copy_buf(build_ctx->transient_arena, &src_k);
    v = arena_copy_buf(build_ctx->transient_arena, &src_v);
    ret = mr_push_item(k, v, build_ctx->modify_result);

    if (ret != COUCHSTORE_SUCCESS) {
        return static_cast<file_merger_error_t>(ret);
    }

    if (build_ctx->modify_result->count == 0) {
        arena_free_all(build_ctx->transient_arena);
    }

    return static_cast<file_merger_error_t>(ret);
}


static couchstore_error_t build_btree(const char *source_file,
                                      tree_file *dest_file,
                                      compare_info *cmp,
                                      reduce_fn reduce_fun,
                                      reduce_fn rereduce_fun,
                                      const char *tmpdir,
                                      sort_record_fn sort_fun,
                                      void *reduce_ctx,
                                      node_pointer **out_root)
{
    couchstore_error_t ret = COUCHSTORE_SUCCESS;
    arena *transient_arena = new_arena(0);
    arena *persistent_arena = new_arena(0);
    couchfile_modify_result *mr;
    view_btree_builder_ctx_t build_ctx;

    if (transient_arena == NULL || persistent_arena == NULL) {
        ret = COUCHSTORE_ERROR_ALLOC_FAIL;
        goto out;
    }

    mr = new_btree_modres(persistent_arena,
                          transient_arena,
                          dest_file,
                          cmp,
                          reduce_fun,
                          rereduce_fun,
                          reduce_ctx,
                          VIEW_KV_CHUNK_THRESHOLD + (VIEW_KV_CHUNK_THRESHOLD / 3),
                          VIEW_KP_CHUNK_THRESHOLD + (VIEW_KP_CHUNK_THRESHOLD / 3));
    if (mr == NULL) {
        ret = COUCHSTORE_ERROR_ALLOC_FAIL;
        goto out;
    }

    build_ctx.transient_arena = transient_arena;
    build_ctx.modify_result = mr;

    ret = (couchstore_error_t) sort_fun(source_file,
                                        tmpdir,
                                        build_btree_record_callback, &build_ctx);
    if (ret != COUCHSTORE_SUCCESS) {
        goto out;
    }

    *out_root = complete_new_btree(mr, &ret);
    if (ret != COUCHSTORE_SUCCESS) {
        goto out;
    }

    /* Don't care about success/failure. Erlang side will eventually delete it. */
    remove(source_file);

out:
    if (transient_arena != NULL) {
        delete_arena(transient_arena);
    }
    if (persistent_arena != NULL) {
        delete_arena(persistent_arena);
    }

    return ret;
}


static couchstore_error_t build_id_btree(const char *source_file,
                                         tree_file *dest_file,
                                         const char *tmpdir,
                                         node_pointer **out_root)
{
    couchstore_error_t ret;
    compare_info cmp;

    cmp.compare = id_btree_cmp;

    ret = build_btree(source_file,
                      dest_file,
                      &cmp,
                      view_id_btree_reduce,
                      view_id_btree_rereduce,
                      tmpdir,
                      sort_view_ids_file,
                      NULL,
                      out_root);

    return ret;
}


static couchstore_error_t build_view_btree(const char *source_file,
                                           const view_btree_info_t *info,
                                           tree_file *dest_file,
                                           const char *tmpdir,
                                           node_pointer **out_root,
                                           view_error_t *error_info)
{
    couchstore_error_t ret = COUCHSTORE_SUCCESS;
    compare_info cmp;
    view_reducer_ctx_t *red_ctx = NULL;
    char *error_msg = NULL;

    cmp.compare = view_btree_cmp;
    red_ctx = make_view_reducer_ctx(info->reducers,
                                    info->num_reducers,
                                    &error_msg);
    if (red_ctx == NULL) {
        set_error_info(info, (const char *) error_msg, ret, error_info);
        cb_free(error_msg);
        return COUCHSTORE_ERROR_REDUCER_FAILURE;
    }

    ret = build_btree(source_file,
                      dest_file,
                      &cmp,
                      view_btree_reduce,
                      view_btree_rereduce,
                      tmpdir,
                      sort_view_kvs_file,
                      red_ctx,
                      out_root);

    if (ret != COUCHSTORE_SUCCESS) {
        set_error_info(info, red_ctx->error, ret, error_info);
    }

    free_view_reducer_ctx(red_ctx);

    return ret;
}


couchstore_error_t read_view_group_header(view_group_info_t *info,
                                          index_header_t **header)
{
    couchstore_error_t ret;
    cs_off_t pos = info->header_pos;
    tree_file *file = &info->file;
    char *header_buf = NULL;
    int header_len;
    char buf;

    if (file->handle == NULL) {
        return COUCHSTORE_ERROR_FILE_CLOSED;
    }

    if (info->file.ops->pread(NULL, file->handle, &buf, 1, pos) != 1) {
        return COUCHSTORE_ERROR_READ;
    }
    if (buf == 0) {
        return COUCHSTORE_ERROR_NO_HEADER;
    } else if (buf != 1) {
        return COUCHSTORE_ERROR_CORRUPT;
    }

    header_len = pread_header(file, pos, &header_buf, MAX_VIEW_HEADER_SIZE);
    if (header_len < 0) {
        return (couchstore_error_t) header_len;
    }

    ret = decode_index_header(header_buf, (size_t) header_len, header);
    cb_free(header_buf);

    return ret;
}

couchstore_error_t write_view_group_header(tree_file *file,
                                           uint64_t *pos,
                                           const index_header_t *header)
{
    couchstore_error_t ret;
    sized_buf buf = { NULL, 0 };
    cs_off_t p;

    if (file->handle == NULL) {
        return COUCHSTORE_ERROR_FILE_CLOSED;
    }

    ret = encode_index_header(header, &buf.buf, &buf.size);
    if (ret != COUCHSTORE_SUCCESS) {
        return ret;
    }

    ret = write_header(file, &buf, &p);
    if (ret != COUCHSTORE_SUCCESS) {
        goto out;
    }

    cb_assert(p >= 0);
    *pos = (uint64_t) p;

out:
    cb_free(buf.buf);

    return ret;
}


static couchstore_error_t view_id_bitmask(const node_pointer *root, bitmap_t *bm)
{
    view_id_btree_reduction_t *r = NULL;
    couchstore_error_t errcode;
    if (root == NULL) {
        return COUCHSTORE_SUCCESS;
    }

    errcode = decode_view_id_btree_reduction(root->reduce_value.buf, &r);
    if (errcode != COUCHSTORE_SUCCESS) {
        goto cleanup;
    }

    union_bitmaps(bm, &r->partitions_bitmap);

cleanup:
    free_view_id_btree_reduction(r);
    return errcode;
}


static couchstore_error_t view_bitmask(const node_pointer *root, bitmap_t *bm)
{
    view_btree_reduction_t *r = NULL;
    couchstore_error_t errcode;
    if (root == NULL) {
        return COUCHSTORE_SUCCESS;
    }

    errcode = decode_view_btree_reduction(root->reduce_value.buf,
                                          root->reduce_value.size, &r);
    if (errcode != COUCHSTORE_SUCCESS) {
        goto cleanup;
    }

    union_bitmaps(bm, &r->partitions_bitmap);

cleanup:
    free_view_btree_reduction(r);
    return errcode;
}


static couchstore_error_t cleanup_btree(tree_file *file,
                                        node_pointer *root,
                                        compare_info *cmp,
                                        reduce_fn reduce,
                                        reduce_fn rereduce,
                                        purge_kv_fn purge_kv,
                                        purge_kp_fn purge_kp,
                                        view_purger_ctx_t *purge_ctx,
                                        view_reducer_ctx_t *red_ctx,
                                        node_pointer **out_root)
{
    couchstore_error_t errcode;
    couchfile_modify_request rq;

    rq.cmp = *cmp;
    rq.file = file;
    rq.actions = NULL;
    rq.num_actions = 0;
    rq.reduce = reduce;
    rq.rereduce = rereduce;
    rq.compacting = 0;
    rq.kv_chunk_threshold = VIEW_KV_CHUNK_THRESHOLD;
    rq.kp_chunk_threshold = VIEW_KP_CHUNK_THRESHOLD;
    rq.purge_kp = purge_kp;
    rq.purge_kv = purge_kv;
    rq.enable_purging = 1;
    rq.guided_purge_ctx = purge_ctx;
    rq.user_reduce_ctx = red_ctx;

    *out_root = guided_purge_btree(&rq, root, &errcode);

    return errcode;
}

static couchstore_error_t cleanup_id_btree(tree_file *file,
                                           node_pointer *root,
                                           node_pointer **out_root,
                                           view_purger_ctx_t *purge_ctx,
                                           view_error_t *error_info)
{
    couchstore_error_t ret;
    compare_info cmp;

    cmp.compare = id_btree_cmp;

    ret = cleanup_btree(file,
                        root,
                        &cmp,
                        view_id_btree_reduce,
                        view_id_btree_rereduce,
                        view_id_btree_purge_kv,
                        view_id_btree_purge_kp,
                        purge_ctx,
                        NULL,
                        out_root);

    return ret;
}


static couchstore_error_t cleanup_view_btree(tree_file *file,
                                             node_pointer *root,
                                             const view_btree_info_t *info,
                                             node_pointer **out_root,
                                             view_purger_ctx_t *purge_ctx,
                                             view_error_t *error_info)
{
    couchstore_error_t ret = COUCHSTORE_SUCCESS;
    compare_info cmp;
    view_reducer_ctx_t *red_ctx = NULL;
    char *error_msg = NULL;

    cmp.compare = view_btree_cmp;
    red_ctx = make_view_reducer_ctx(info->reducers,
                                    info->num_reducers,
                                    &error_msg);
    if (red_ctx == NULL) {
        set_error_info(info, (const char *) error_msg, ret, error_info);
        cb_free(error_msg);
        return COUCHSTORE_ERROR_REDUCER_FAILURE;
    }

    ret = cleanup_btree(file,
                        root,
                        &cmp,
                        view_btree_reduce,
                        view_btree_rereduce,
                        view_btree_purge_kv,
                        view_btree_purge_kp,
                        purge_ctx,
                        red_ctx,
                        out_root);

    if (ret != COUCHSTORE_SUCCESS) {
        const char *error_msg = NULL;
        if (red_ctx->error != NULL) {
            error_msg = red_ctx->error;
        }
        set_error_info(info, (const char *) error_msg, ret, error_info);
    }

    free_view_reducer_ctx(red_ctx);

    return ret;
}

couchstore_error_t couchstore_cleanup_view_group(view_group_info_t *info,
                                                 uint64_t *header_pos,
                                                 uint64_t *purge_count,
                                                 view_error_t *error_info)
{
    couchstore_error_t ret;
    tree_file index_file;
    index_header_t *header = NULL;
    node_pointer *id_root = NULL;
    node_pointer **view_roots = NULL;
    view_purger_ctx_t purge_ctx;
    bitmap_t bm_cleanup;
    int i;

    memset(&bm_cleanup, 0, sizeof(bm_cleanup));
    error_info->view_name = NULL;
    error_info->error_msg = NULL;
    index_file.handle = NULL;
    index_file.ops = NULL;
    index_file.path = NULL;

    view_roots = (node_pointer **) cb_calloc(
        info->num_btrees, sizeof(node_pointer *));
    if (view_roots == NULL) {
        return COUCHSTORE_ERROR_ALLOC_FAIL;
    }

    /* Read info from current index viewgroup file */
    ret = open_view_group_file(info->filepath,
                               COUCHSTORE_OPEN_FLAG_RDONLY,
                               &info->file);
    if (ret != COUCHSTORE_SUCCESS) {
        goto cleanup;
    }

    ret = read_view_group_header(info, &header);
    if (ret != COUCHSTORE_SUCCESS) {
        goto cleanup;
    }
    cb_assert(info->num_btrees == header->num_views);

    /* Setup purger context */
    purge_ctx.count = 0;
    purge_ctx.cbitmask = header->cleanup_bitmask;

    ret = open_view_group_file(info->filepath,
                               0,
                               &index_file);
    if (ret != COUCHSTORE_SUCCESS) {
        goto cleanup;
    }

    index_file.pos = index_file.ops->goto_eof(&index_file.lastError,
                                                         index_file.handle);

    /* Cleanup id_bree */
    ret = cleanup_id_btree(&index_file, header->id_btree_state, &id_root,
                                                                &purge_ctx,
                                                                error_info);
    if (ret != COUCHSTORE_SUCCESS) {
        goto cleanup;
    }

    if (header->id_btree_state != id_root) {
        cb_free(header->id_btree_state);
    }

    header->id_btree_state = id_root;
    view_id_bitmask(id_root, &bm_cleanup);
    id_root = NULL;

    /* Cleanup all view btrees */
    for (i = 0; i < info->num_btrees; ++i) {
        ret = cleanup_view_btree(&index_file,
                                 (node_pointer *) header->view_states[i],
                                 &info->view_infos.btree[i],
                                 &view_roots[i],
                                 &purge_ctx,
                                 error_info);

        if (ret != COUCHSTORE_SUCCESS) {
            goto cleanup;
        }

        if (header->view_states[i] != view_roots[i]) {
            cb_free(header->view_states[i]);
        }

        header->view_states[i] = view_roots[i];
        view_bitmask(view_roots[i], &bm_cleanup);
        view_roots[i] = NULL;
    }

    /* Set resulting cleanup bitmask */
    /* TODO: This code can be removed, if we do not plan for cleanup STOP command */
    intersect_bitmaps(&bm_cleanup, &purge_ctx.cbitmask);
    header->cleanup_bitmask = bm_cleanup;

    /* Update header with new btree infos */
    ret = write_view_group_header(&index_file, header_pos, header);
    if (ret != COUCHSTORE_SUCCESS) {
        goto cleanup;
    }

    *purge_count = purge_ctx.count;
    ret = COUCHSTORE_SUCCESS;

cleanup:
    free_index_header(header);
    close_view_group_file(info);
    tree_file_close(&index_file);
    cb_free(id_root);
    if (view_roots != NULL) {
        for (i = 0; i < info->num_btrees; ++i) {
            cb_free(view_roots[i]);
        }
        cb_free(view_roots);
    }

    return ret;
}

static couchstore_error_t update_btree(const char *source_file,
                                       tree_file *dest_file,
                                       const node_pointer *root,
                                       size_t batch_size,
                                       compare_info *cmp,
                                       reduce_fn reduce_fun,
                                       reduce_fn rereduce_fun,
                                       purge_kv_fn purge_kv,
                                       purge_kp_fn purge_kp,
                                       view_reducer_ctx_t *red_ctx,
                                       view_purger_ctx_t *purge_ctx,
                                       uint64_t *inserted,
                                       uint64_t *removed,
                                       node_pointer **out_root)
{
    couchstore_error_t ret = COUCHSTORE_SUCCESS;
    couchfile_modify_request rq;
    node_pointer *newroot = (node_pointer *) root;
    arena *transient_arena = new_arena(0);
    FILE *f = NULL;
    couchfile_modify_action *actions = NULL;
    sized_buf *keybufs = NULL, *valbufs = NULL;
    size_t bufsize = 0;
    int last_record = 0;
    bitmap_t empty_bm;
    int max_actions = MAX_ACTIONS_SIZE /
                (sizeof(couchfile_modify_action) + 2 * sizeof(sized_buf));

    memset(&empty_bm, 0, sizeof(empty_bm));

    if (transient_arena == NULL) {
        ret = COUCHSTORE_ERROR_ALLOC_FAIL;
        goto cleanup;
    }


    actions = (couchfile_modify_action *) cb_calloc(
                                            max_actions,
                                            sizeof(couchfile_modify_action));
    if (actions == NULL) {
        ret = COUCHSTORE_ERROR_ALLOC_FAIL;
        goto cleanup;
    }

    keybufs = (sized_buf *) cb_calloc(max_actions, sizeof(sized_buf));
    if (keybufs == NULL) {
        ret = COUCHSTORE_ERROR_ALLOC_FAIL;
        goto cleanup;
    }

    valbufs = (sized_buf *) cb_calloc(max_actions, sizeof(sized_buf));
    if (valbufs == NULL) {
        ret = COUCHSTORE_ERROR_ALLOC_FAIL;
        goto cleanup;
    }

    rq.cmp = *cmp;
    rq.file = dest_file;
    rq.actions = actions;
    rq.num_actions = 0;
    rq.reduce = reduce_fun;
    rq.rereduce = rereduce_fun;
    rq.compacting = 0;
    rq.kv_chunk_threshold = VIEW_KV_CHUNK_THRESHOLD;
    rq.kp_chunk_threshold = VIEW_KP_CHUNK_THRESHOLD;
    rq.purge_kp = purge_kp;
    rq.purge_kv = purge_kv;
    rq.guided_purge_ctx = purge_ctx;
    rq.enable_purging = 1;
    rq.user_reduce_ctx = red_ctx;

    /* If cleanup bitmask is empty, no need to try purging */
    if (is_equal_bitmap(&empty_bm, &purge_ctx->cbitmask)) {
        rq.enable_purging = 0;
    }

    f = fopen(source_file, "rb");
    if (f == NULL) {
        fprintf(stderr, "Error while opening file: source file %s, errorcode %s\n",
                source_file, strerror(errno));
        ret = COUCHSTORE_ERROR_OPEN_FILE;
        goto cleanup;
    }

    while (!last_record) {
        int read_ret;
        uint8_t op;

        read_ret = read_record(f, transient_arena, &keybufs[rq.num_actions],
                                                   &valbufs[rq.num_actions],
                                                   &op);
        if (read_ret == 0) {
            last_record = 1;
            goto flush;
        } else if (read_ret < 0) {
            ret = (couchstore_error_t) read_ret;
            goto cleanup;
        }

        /* Add action */
        actions[rq.num_actions].type = op;
        actions[rq.num_actions].key = &keybufs[rq.num_actions];
        actions[rq.num_actions].data = &valbufs[rq.num_actions];

        if (inserted && op == ACTION_INSERT) {
            (*inserted)++;
        } else if (removed && op == ACTION_REMOVE) {
            (*removed)++;
        }

        bufsize += keybufs[rq.num_actions].size +
                   valbufs[rq.num_actions].size +
                   sizeof(uint8_t);
        rq.num_actions++;

flush:
        if (rq.num_actions && (last_record || bufsize > batch_size ||
                               rq.num_actions == max_actions)) {
            newroot = modify_btree(&rq, newroot, &ret);
            if (ret != COUCHSTORE_SUCCESS) {
                goto cleanup;
            }

            rq.num_actions = 0;
            bufsize = 0;
            arena_free_all(transient_arena);
        }
    }

    *out_root = newroot;

cleanup:
    cb_free(actions);
    cb_free(keybufs);
    cb_free(valbufs);

    if (f != NULL) {
        fclose(f);
    }

    if (transient_arena != NULL) {
        delete_arena(transient_arena);
    }

    return ret;
}

static couchstore_error_t update_id_btree(const char *source_file,
                                         tree_file *dest_file,
                                         const node_pointer *root,
                                         size_t batch_size,
                                         view_purger_ctx_t *purge_ctx,
                                         uint64_t *inserted,
                                         uint64_t *removed,
                                         node_pointer **out_root)
{
    couchstore_error_t ret;
    compare_info cmp;

    cmp.compare = id_btree_cmp;

    ret = update_btree(source_file,
                      dest_file,
                      root,
                      batch_size,
                      &cmp,
                      view_id_btree_reduce,
                      view_id_btree_rereduce,
                      view_id_btree_purge_kv,
                      view_id_btree_purge_kp,
                      NULL,
                      purge_ctx,
                      inserted,
                      removed,
                      out_root);

    return ret;
}


static couchstore_error_t update_view_btree(const char *source_file,
                                            const view_btree_info_t *info,
                                            tree_file *dest_file,
                                            const node_pointer *root,
                                            size_t batch_size,
                                            view_purger_ctx_t *purge_ctx,
                                            uint64_t *inserted,
                                            uint64_t *removed,
                                            node_pointer **out_root,
                                            view_error_t *error_info)
{
    couchstore_error_t ret = COUCHSTORE_SUCCESS;
    compare_info cmp;
    view_reducer_ctx_t *red_ctx = NULL;
    char *error_msg = NULL;

    cmp.compare = view_btree_cmp;
    red_ctx = make_view_reducer_ctx(info->reducers,
                                    info->num_reducers,
                                    &error_msg);
    if (red_ctx == NULL) {
        set_error_info(info, (const char *) error_msg, ret, error_info);
        cb_free(error_msg);
        return COUCHSTORE_ERROR_REDUCER_FAILURE;
    }

    ret = update_btree(source_file,
                      dest_file,
                      root,
                      batch_size,
                      &cmp,
                      view_btree_reduce,
                      view_btree_rereduce,
                      view_btree_purge_kv,
                      view_btree_purge_kp,
                      red_ctx,
                      purge_ctx,
                      inserted,
                      removed,
                      out_root);

    if (ret != COUCHSTORE_SUCCESS) {
        set_error_info(info, red_ctx->error, ret, error_info);
    }

    free_view_reducer_ctx(red_ctx);

    return ret;
}

couchstore_error_t couchstore_update_view_group(view_group_info_t *info,
                                               const char *id_records_file,
                                               const char *kv_records_files[],
                                               size_t batch_size,
                                               const sized_buf *header_buf,
                                               int is_sorted,
                                               const char *tmp_dir,
                                               view_group_update_stats_t *stats,
                                               sized_buf *header_outbuf,
                                               view_error_t *error_info)
{
    couchstore_error_t ret;
    tree_file index_file = {0, NULL, NULL, NULL, {-1}, CRC32};
    index_header_t *header = NULL;
    node_pointer *id_root = NULL;
    node_pointer **view_roots = NULL;
    view_purger_ctx_t purge_ctx;
    bitmap_t bm_cleanup;
    int i;

    ret = decode_index_header(header_buf->buf, header_buf->size, &header);
    if (ret < 0) {
        goto cleanup;
    }

    memset(&bm_cleanup, 0, sizeof(bm_cleanup));

    error_info->view_name = NULL;
    error_info->error_msg = NULL;

    view_roots = (node_pointer **) cb_calloc(info->num_btrees,
                                          sizeof(node_pointer *));
    if (view_roots == NULL) {
        ret = COUCHSTORE_ERROR_ALLOC_FAIL;
        goto cleanup;
    }

    /* Spatial views use the native updater only for sorting the ID b-tree.
     * Before starting it, the references to the spatial view index files
     * get removed, hence the number of trees in `info` don't match the number
     * in the header */
    if (info->type != VIEW_INDEX_TYPE_SPATIAL) {
        cb_assert(info->num_btrees == header->num_views);
    }

    /* Setup purger context */
    purge_ctx.count = 0;
    purge_ctx.cbitmask = header->cleanup_bitmask;

    ret = open_view_group_file(info->filepath,
                               0,
                               &index_file);
    if (ret != COUCHSTORE_SUCCESS) {
        goto cleanup;
    }

    /* Move pos to end of file */
    index_file.pos = index_file.ops->goto_eof(&index_file.lastError,
                                              index_file.handle);

    if (!is_sorted) {
        ret = (couchstore_error_t) sort_view_ids_ops_file(id_records_file, tmp_dir);
        if (ret != COUCHSTORE_SUCCESS) {
            char error_msg[1024];
            int nw = snprintf(error_msg, sizeof(error_msg),
                              "Error sorting records file: %s",
                              id_records_file);
            if (nw > 0 && size_t(nw) < sizeof(error_msg)) {
                error_info->error_msg = cb_strdup(error_msg);
            } else {
                error_info->error_msg = cb_strdup("Error sorting records file");
            }
            error_info->idx_type = "MAPREDUCE";
            error_info->view_name = (const char *) cb_strdup("id_btree");
            goto cleanup;
        }
    }

    ret = update_id_btree(id_records_file, &index_file,
                                           header->id_btree_state,
                                           batch_size,
                                           &purge_ctx,
                                           &stats->ids_inserted,
                                           &stats->ids_removed,
                                           &id_root);
    if (ret != COUCHSTORE_SUCCESS) {
        goto cleanup;
    }


    if (header->id_btree_state != id_root) {
        cb_free(header->id_btree_state);
    }

    header->id_btree_state = id_root;
    view_id_bitmask(id_root, &bm_cleanup);
    id_root = NULL;

    for (i = 0; i < info->num_btrees; ++i) {
        if (!is_sorted) {
            ret = (couchstore_error_t) sort_view_kvs_ops_file(kv_records_files[i], tmp_dir);
            if (ret != COUCHSTORE_SUCCESS) {
                const char* errmsg = "Error sorting records file";
                char error_msg[1024];
                int nw = snprintf(error_msg, sizeof(error_msg),
                                  "Error sorting records file: %s",
                                  kv_records_files[i]);

                if (nw > 0 && size_t(nw) < sizeof(error_msg)) {
                    errmsg = error_msg;
                }
                set_error_info(&info->view_infos.btree[i], errmsg, ret,
                               error_info);
                goto cleanup;
            }
        }

        ret = update_view_btree(kv_records_files[i],
                                &info->view_infos.btree[i],
                                &index_file,
                                header->view_states[i],
                                batch_size,
                                &purge_ctx,
                                &stats->kvs_inserted,
                                &stats->kvs_removed,
                                &view_roots[i],
                                error_info);

        if (ret != COUCHSTORE_SUCCESS) {
            goto cleanup;
        }

        if (header->view_states[i] != view_roots[i]) {
            cb_free(header->view_states[i]);
        }

        header->view_states[i] = view_roots[i];
        view_bitmask(view_roots[i], &bm_cleanup);
        view_roots[i] = NULL;
    }

    /* Set resulting cleanup bitmask */
    intersect_bitmaps(&bm_cleanup, &purge_ctx.cbitmask);
    header->cleanup_bitmask = bm_cleanup;
    stats->purged = purge_ctx.count;

    ret = encode_index_header(header, &header_outbuf->buf, &header_outbuf->size);
    if (ret != COUCHSTORE_SUCCESS) {
        goto cleanup;
    }

    ret = COUCHSTORE_SUCCESS;

cleanup:
    free_index_header(header);
    close_view_group_file(info);
    tree_file_close(&index_file);
    cb_free(id_root);
    if (view_roots != NULL) {
        for (i = 0; i < info->num_btrees; ++i) {
            cb_free(view_roots[i]);
        }
        cb_free(view_roots);
    }

    return ret;
}

/* Add the kv pair to modify result */
static couchstore_error_t compact_view_fetchcb(couchfile_lookup_request *rq,
                                        const sized_buf *k,
                                        const sized_buf *v)
{
    int ret;
    sized_buf *k_c, *v_c;
    view_compact_ctx_t *ctx = (view_compact_ctx_t *) rq->callback_ctx;
    compactor_stats_t *stats = ctx->stats;

    if (k == NULL || v == NULL) {
        return COUCHSTORE_ERROR_READ;
    }

    if (ctx->filter_fun) {
        ret = ctx->filter_fun(k, v, ctx->filterbm);
        if (ret < 0) {
            return (couchstore_error_t) ret;
        } else if (ret) {
            return COUCHSTORE_SUCCESS;
        }
    }

    k_c = arena_copy_buf(ctx->transient_arena, k);
    v_c = arena_copy_buf(ctx->transient_arena, v);
    ret = mr_push_item(k_c, v_c, ctx->mr);
    if (ret != COUCHSTORE_SUCCESS) {
        return static_cast<couchstore_error_t>(ret);
    }

    if (stats) {
        stats->inserted++;
        if (stats->update_fun) {
            stats->update_fun(stats->freq, stats->inserted);
        }
    }

    if (ctx->mr->count == 0) {
        arena_free_all(ctx->transient_arena);
    }

    return (couchstore_error_t) ret;
}

static couchstore_error_t compact_btree(tree_file *source,
                                 tree_file *target,
                                 const node_pointer *root,
                                 compare_info *cmp,
                                 reduce_fn reduce_fun,
                                 reduce_fn rereduce_fun,
                                 compact_filter_fn filter_fun,
                                 view_reducer_ctx_t *red_ctx,
                                 const bitmap_t *filterbm,
                                 compactor_stats_t *stats,
                                 node_pointer **out_root)
{
    couchstore_error_t ret = COUCHSTORE_SUCCESS;
    arena *transient_arena;
    arena *persistent_arena;
    couchfile_modify_result *modify_result;
    couchfile_lookup_request lookup_rq;
    view_compact_ctx_t compact_ctx;
    sized_buf nullkey = {NULL, 0};
    sized_buf *lowkeys = &nullkey;

    if (!root) {
        return COUCHSTORE_SUCCESS;
    }

    transient_arena = new_arena(0);
    persistent_arena = new_arena(0);

    if (transient_arena == NULL || persistent_arena == NULL) {
        ret = COUCHSTORE_ERROR_ALLOC_FAIL;
        goto cleanup;
    }

    /* Create new btree on new file */
    modify_result = new_btree_modres(persistent_arena,
                          transient_arena,
                          target,
                          cmp,
                          reduce_fun,
                          rereduce_fun,
                          red_ctx,
                          VIEW_KV_CHUNK_THRESHOLD + (VIEW_KV_CHUNK_THRESHOLD / 3),
                          VIEW_KP_CHUNK_THRESHOLD + (VIEW_KP_CHUNK_THRESHOLD / 3));
    if (modify_result == NULL) {
        ret = COUCHSTORE_ERROR_ALLOC_FAIL;
        goto cleanup;
    }

    compact_ctx.filter_fun = NULL;
    compact_ctx.mr = modify_result;
    compact_ctx.transient_arena = transient_arena;
    compact_ctx.stats = stats;

    if (filterbm) {
        compact_ctx.filterbm = filterbm;
        compact_ctx.filter_fun = filter_fun;
    }

    lookup_rq.cmp.compare = cmp->compare;
    lookup_rq.file = source;
    lookup_rq.num_keys = 1;
    lookup_rq.keys = &lowkeys;
    lookup_rq.callback_ctx = &compact_ctx;
    lookup_rq.fetch_callback = compact_view_fetchcb;
    lookup_rq.node_callback = NULL;
    lookup_rq.fold = 1;

    ret = btree_lookup(&lookup_rq, root->pointer);
    if (ret != COUCHSTORE_SUCCESS) {
        goto cleanup;
    }

    *out_root = complete_new_btree(modify_result, &ret);

cleanup:
    if (transient_arena != NULL) {
        delete_arena(transient_arena);
    }

    if (persistent_arena != NULL) {
        delete_arena(persistent_arena);
    }

    return ret;
}

static couchstore_error_t compact_id_btree(tree_file *source,
                                    tree_file *target,
                                    const node_pointer *root,
                                    const bitmap_t *filterbm,
                                    compactor_stats_t *stats,
                                    node_pointer **out_root)
{
    couchstore_error_t ret;
    compare_info cmp;

    cmp.compare = id_btree_cmp;

    ret = compact_btree(source,
                        target,
                        root,
                        &cmp,
                        view_id_btree_reduce,
                        view_id_btree_rereduce,
                        view_id_btree_filter,
                        NULL,
                        filterbm,
                        stats,
                        out_root);

    return ret;
}

static couchstore_error_t compact_view_btree(tree_file *source,
                                      tree_file *target,
                                      const view_btree_info_t *info,
                                      const node_pointer *root,
                                      const bitmap_t *filterbm,
                                      compactor_stats_t *stats,
                                      node_pointer **out_root,
                                      view_error_t *error_info)
{
    couchstore_error_t ret = COUCHSTORE_SUCCESS;
    compare_info cmp;
    view_reducer_ctx_t *red_ctx = NULL;
    char *error_msg = NULL;

    cmp.compare = view_btree_cmp;
    red_ctx = make_view_reducer_ctx(info->reducers,
                                    info->num_reducers,
                                    &error_msg);
    if (red_ctx == NULL) {
        set_error_info(info, (const char *) error_msg, ret, error_info);
        cb_free(error_msg);
        return COUCHSTORE_ERROR_REDUCER_FAILURE;
    }

    ret = compact_btree(source,
                        target,
                        root,
                        &cmp,
                        view_btree_reduce,
                        view_btree_rereduce,
                        view_btree_filter,
                        red_ctx,
                        filterbm,
                        stats,
                        out_root);

    if (ret != COUCHSTORE_SUCCESS) {
        set_error_info(info, red_ctx->error, ret, error_info);
    }

    free_view_reducer_ctx(red_ctx);

    return ret;
}

couchstore_error_t couchstore_compact_view_group(view_group_info_t *info,
                                                 const char *target_file,
                                                 const sized_buf *header_buf,
                                                 compactor_stats_t *stats,
                                                 sized_buf *header_outbuf,
                                                 view_error_t *error_info)
{
    couchstore_error_t ret;
    tree_file index_file;
    tree_file compact_file;
    index_header_t *header = NULL;
    node_pointer *id_root = NULL;
    node_pointer **view_roots = NULL;
    bitmap_t *filterbm = NULL;
    bitmap_t emptybm;
    int i;

    memset(&emptybm, 0, sizeof(bitmap_t));
    error_info->view_name = NULL;
    error_info->error_msg = NULL;
    index_file.handle = NULL;
    index_file.ops = NULL;
    index_file.path = NULL;
    compact_file.handle = NULL;
    compact_file.ops = NULL;
    compact_file.path = NULL;

    ret = decode_index_header(header_buf->buf, header_buf->size, &header);
    if (ret < 0) {
        goto cleanup;
    }

    /* Set filter bitmask if required */
    if (!is_equal_bitmap(&emptybm, &header->cleanup_bitmask)) {
        filterbm = &header->cleanup_bitmask;
    }

    view_roots = (node_pointer **) cb_calloc(info->num_btrees,
                                          sizeof(node_pointer *));
    if (view_roots == NULL) {
        ret = COUCHSTORE_ERROR_ALLOC_FAIL;
        goto cleanup;
    }

    cb_assert(info->num_btrees == header->num_views);

    ret = open_view_group_file(info->filepath,
                               COUCHSTORE_OPEN_FLAG_RDONLY,
                               &index_file);
    if (ret != COUCHSTORE_SUCCESS) {
        goto cleanup;
    }

    /*
     * Open target file for compaction
     * Expects that caller created the target file
     */
    ret = open_view_group_file(target_file, 0, &compact_file);
    if (ret != COUCHSTORE_SUCCESS) {
        goto cleanup;
    }

    compact_file.pos = compact_file.ops->goto_eof(&compact_file.lastError,
                                                  compact_file.handle);
    ret = compact_id_btree(&index_file, &compact_file,
                                        header->id_btree_state,
                                        filterbm,
                                        stats,
                                        &id_root);
    if (ret != COUCHSTORE_SUCCESS) {
        goto cleanup;
    }

    cb_free(header->id_btree_state);
    header->id_btree_state = id_root;
    id_root = NULL;

    for (i = 0; i < info->num_btrees; ++i) {
        switch(info->type) {
        case VIEW_INDEX_TYPE_MAPREDUCE:
            ret = compact_view_btree(&index_file,
                                     &compact_file,
                                     &info->view_infos.btree[i],
                                     header->view_states[i],
                                     filterbm,
                                     stats,
                                     &view_roots[i],
                                     error_info);
            break;
        case VIEW_INDEX_TYPE_SPATIAL:
            ret = compact_view_spatial(&index_file,
                                       &compact_file,
                                       &info->view_infos.spatial[i],
                                       header->view_states[i],
                                       filterbm,
                                       stats,
                                       &view_roots[i],
                                       error_info);
            break;
        }
        if (ret != COUCHSTORE_SUCCESS) {
            goto cleanup;
        }

        cb_free(header->view_states[i]);
        header->view_states[i] = view_roots[i];
        view_roots[i] = NULL;
    }

    header->cleanup_bitmask = emptybm;
    ret = encode_index_header(header, &header_outbuf->buf, &header_outbuf->size);
    if (ret != COUCHSTORE_SUCCESS) {
        goto cleanup;
    }

    ret = COUCHSTORE_SUCCESS;

cleanup:
    free_index_header(header);
    close_view_group_file(info);
    tree_file_close(&index_file);
    tree_file_close(&compact_file);
    cb_free(id_root);
    if (view_roots != NULL) {
        for (i = 0; i < info->num_btrees; ++i) {
            cb_free(view_roots[i]);
        }
        cb_free(view_roots);
    }

    return ret;
}


/*
 * For initial spatial build, feed the spatial builder as soon as
 * sorted records are available.
 */
static file_merger_error_t build_spatial_record_callback(void *buf, void *ctx)
{
    int ret;
    sized_buf *k, *v;
    view_file_merge_record_t *rec = (view_file_merge_record_t *) buf;
    view_file_merge_ctx_t *merge_ctx = (view_file_merge_ctx_t *) ctx;
    view_spatial_builder_ctx_t *build_ctx =
            (view_spatial_builder_ctx_t *) merge_ctx->user_ctx;
    sized_buf src_k, src_v;

    src_k.size = rec->ksize;
    src_k.buf = VIEW_RECORD_KEY(rec);
    src_v.size = rec->vsize;
    src_v.buf = VIEW_RECORD_VAL(rec);

    k = arena_copy_buf(build_ctx->transient_arena, &src_k);
    v = arena_copy_buf(build_ctx->transient_arena, &src_v);
    ret = spatial_push_item(k, v, build_ctx->modify_result);

    if (ret != COUCHSTORE_SUCCESS) {
        return static_cast<file_merger_error_t>(ret);
    }

    if (build_ctx->modify_result->count == 0) {
        arena_free_all(build_ctx->transient_arena);
    }

    return static_cast<file_merger_error_t>(ret);
}


static couchstore_error_t build_view_spatial(const char *source_file,
                                             const view_spatial_info_t *info,
                                             tree_file *dest_file,
                                             const char *tmpdir,
                                             node_pointer **out_root,
                                             view_error_t *error_info)
{
    couchstore_error_t ret;
    compare_info cmp;

    /* cmp.compare is only needed when you read a b-tree node or modify a
     * b-tree node (btree_modify:modify_node()). We don't do either in the
     * spatial view. */
    cmp.compare = NULL;
    ret = build_spatial(source_file,
                        dest_file,
                        &cmp,
                        view_spatial_reduce,
                        /* Use the reduce function also for the re-reduce */
                        view_spatial_reduce,
                        info->dimension,
                        info->mbb,
                        tmpdir,
                        sort_spatial_kvs_file,
                        out_root);

    if (ret != COUCHSTORE_SUCCESS) {
        const int buffsize = 64;
        char* buf = (char*) cb_malloc(buffsize);
        if (buf != NULL) {
            int len = snprintf(buf, buffsize, "ret = %d", ret);
            if (len > 0 && len < buffsize) {
                error_info->error_msg = buf;
            } else {
                error_info->error_msg = cb_strdup("Failed to build error message");
                cb_free(buf);
            }
        }
    }

    return ret;
}


static couchstore_error_t build_spatial(const char *source_file,
                                        tree_file *dest_file,
                                        compare_info *cmp,
                                        reduce_fn reduce_fun,
                                        reduce_fn rereduce_fun,
                                        const uint16_t dimension,
                                        const double *mbb,
                                        const char *tmpdir,
                                        sort_record_fn sort_fun,
                                        node_pointer **out_root)
{
    couchstore_error_t ret = COUCHSTORE_SUCCESS;
    arena *transient_arena = new_arena(0);
    arena *persistent_arena = new_arena(0);
    couchfile_modify_result *mr;
    view_spatial_builder_ctx_t build_ctx;

    if (transient_arena == NULL || persistent_arena == NULL) {
        ret = COUCHSTORE_ERROR_ALLOC_FAIL;
        goto out;
    }

    mr = new_btree_modres(persistent_arena,
                          transient_arena,
                          dest_file,
                          cmp,
                          reduce_fun,
                          rereduce_fun,
                          NULL,
                          /* Normally the nodes are flushed to disk when 2/3 of
                           * the threshold is reached. In order to have a
                           * higher fill grade, we add 1/3 */
                          VIEW_KV_CHUNK_THRESHOLD + (VIEW_KV_CHUNK_THRESHOLD / 3),
                          VIEW_KP_CHUNK_THRESHOLD + (VIEW_KP_CHUNK_THRESHOLD / 3));
    if (mr == NULL) {
        ret = COUCHSTORE_ERROR_ALLOC_FAIL;
        goto out;
    }

    build_ctx.transient_arena = transient_arena;
    build_ctx.modify_result = mr;
    build_ctx.scale_factor = spatial_scale_factor(mbb, dimension,
                                                  ZCODE_MAX_VALUE);

    ret = (couchstore_error_t) sort_fun(source_file,
                                        tmpdir,
                                        build_spatial_record_callback,
                                        &build_ctx);
    free_spatial_scale_factor(build_ctx.scale_factor);
    if (ret != COUCHSTORE_SUCCESS) {
        goto out;
    }

    *out_root = complete_new_spatial(mr, &ret);
    if (ret != COUCHSTORE_SUCCESS) {
        goto out;
    }

    /* Don't care about success/failure. Erlang side will eventually delete it. */
    remove(source_file);

out:
    if (transient_arena != NULL) {
        delete_arena(transient_arena);
    }

    return ret;
}

/* Add the kv pair to modify result
 * The difference to the mapreduce views is the call to `spatial_push_item` */
static couchstore_error_t compact_spatial_fetchcb(couchfile_lookup_request *rq,
                                                  const sized_buf *k,
                                                  const sized_buf *v)
{
    int ret;
    sized_buf *k_c, *v_c;
    view_compact_ctx_t *ctx = (view_compact_ctx_t *) rq->callback_ctx;
    compactor_stats_t *stats = ctx->stats;

    if (k == NULL || v == NULL) {
        return COUCHSTORE_ERROR_READ;
    }

    if (ctx->filter_fun) {
        ret = ctx->filter_fun(k, v, ctx->filterbm);
        if (ret < 0) {
            return (couchstore_error_t) ret;
        } else if (ret) {
            return COUCHSTORE_SUCCESS;
        }
    }

    k_c = arena_copy_buf(ctx->transient_arena, k);
    v_c = arena_copy_buf(ctx->transient_arena, v);
    ret = spatial_push_item(k_c, v_c, ctx->mr);
    if (ret != COUCHSTORE_SUCCESS) {
        return static_cast<couchstore_error_t>(ret);
    }

    if (stats) {
        stats->inserted++;
        if (stats->update_fun) {
            stats->update_fun(stats->freq, stats->inserted);
        }
    }

    if (ctx->mr->count == 0) {
        arena_free_all(ctx->transient_arena);
    }

    return (couchstore_error_t) ret;
}

static couchstore_error_t compact_view_spatial(tree_file *source,
                                               tree_file *target,
                                               const view_spatial_info_t *info,
                                               const node_pointer *root,
                                               const bitmap_t *filterbm,
                                               compactor_stats_t *stats,
                                               node_pointer **out_root,
                                               view_error_t *error_info)
{
    couchstore_error_t ret;
    compare_info cmp;

    cmp.compare = view_btree_cmp;
    ret = compact_spatial(source,
                          target,
                          root,
                          &cmp,
                          view_spatial_reduce,
                          /* Use the reduce function also for the re-reduce */
                          view_spatial_reduce,
                          view_spatial_filter,
                          filterbm,
                          stats,
                          out_root);

    return ret;
}

static couchstore_error_t compact_spatial(tree_file *source,
                                          tree_file *target,
                                          const node_pointer *root,
                                          compare_info *cmp,
                                          reduce_fn reduce_fun,
                                          reduce_fn rereduce_fun,
                                          compact_filter_fn filter_fun,
                                          const bitmap_t *filterbm,
                                          compactor_stats_t *stats,
                                          node_pointer **out_root)
{
    couchstore_error_t ret = COUCHSTORE_SUCCESS;
    arena *transient_arena = new_arena(0);
    arena *persistent_arena = new_arena(0);
    couchfile_modify_result *modify_result;
    couchfile_lookup_request lookup_rq;
    view_compact_ctx_t compact_ctx;
    sized_buf nullkey = {NULL, 0};
    sized_buf *lowkeys = &nullkey;

    if (!root) {
        return COUCHSTORE_SUCCESS;
    }

    if (transient_arena == NULL || persistent_arena == NULL) {
        ret = COUCHSTORE_ERROR_ALLOC_FAIL;
        goto cleanup;
    }

    /* Create new spatial index on new file */
    modify_result = new_btree_modres(persistent_arena,
                                     transient_arena,
                                     target,
                                     cmp,
                                     reduce_fun,
                                     rereduce_fun,
                                     NULL,
                                     /* Normally the nodes are flushed to disk
                                      * when 2/3 of the threshold is reached.
                                      * In order to have a higher fill grade,
                                      * we add 1/3 */
                                     VIEW_KV_CHUNK_THRESHOLD +
                                         (VIEW_KV_CHUNK_THRESHOLD / 3),
                                     VIEW_KP_CHUNK_THRESHOLD +
                                         (VIEW_KP_CHUNK_THRESHOLD / 3));
    if (modify_result == NULL) {
        ret = COUCHSTORE_ERROR_ALLOC_FAIL;
        goto cleanup;
    }

    compact_ctx.filter_fun = NULL;
    compact_ctx.mr = modify_result;
    compact_ctx.transient_arena = transient_arena;
    compact_ctx.stats = stats;

    if (filterbm) {
        compact_ctx.filterbm = filterbm;
        compact_ctx.filter_fun = filter_fun;
    }

    lookup_rq.cmp.compare = cmp->compare;
    lookup_rq.file = source;
    lookup_rq.num_keys = 1;
    lookup_rq.keys = &lowkeys;
    lookup_rq.callback_ctx = &compact_ctx;
    lookup_rq.fetch_callback = compact_spatial_fetchcb;
    lookup_rq.node_callback = NULL;
    lookup_rq.fold = 1;

    ret = btree_lookup(&lookup_rq, root->pointer);
    if (ret != COUCHSTORE_SUCCESS) {
        goto cleanup;
    }

    *out_root = complete_new_spatial(modify_result, &ret);

cleanup:
    if (transient_arena != NULL) {
        delete_arena(transient_arena);
    }

    if (persistent_arena != NULL) {
        delete_arena(persistent_arena);
    }

    return ret;
}
