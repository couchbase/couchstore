/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#include "couchstore_config.h"
#include "internal.h"
#include "couch_btree.h"
#include "reduces.h"
#include "bitfield.h"
#include "arena.h"
#include "tree_writer.h"
#include "node_types.h"
#include "util.h"
#include "couch_latency_internal.h"

#include <platform/cb_malloc.h>
#include <stdexcept>
#include <stdio.h>
#include <stdlib.h>

struct compact_ctx {
    compact_ctx(cb::couchstore::CompactFilterCallback filterCallback,
                cb::couchstore::CompactRewriteDocInfoCallback
                        rewriteDocInfoCallback,
                couchstore_compact_flags flags)
        : transient_arena(new_arena(0)),
          persistent_arena(new_arena(0)),
          filterCallback(std::move(filterCallback)),
          rewriteDocInfoCallback(std::move(rewriteDocInfoCallback)),
          flags(flags) {
    }
    TreeWriter* tree_writer = nullptr;
    /* Using this for stuff that doesn't need to live longer than it takes to write
     * out a b-tree node (the k/v pairs) */
    arena* transient_arena = nullptr;
    /* This is for stuff that lasts the duration of the b-tree writing (node pointers) */
    arena* persistent_arena = nullptr;
    couchfile_modify_result* target_mr = nullptr;
    Db* target = nullptr;
    cb::couchstore::CompactFilterCallback filterCallback;
    cb::couchstore::CompactRewriteDocInfoCallback rewriteDocInfoCallback;
    couchstore_compact_flags flags = 0;
};

static couchstore_error_t compact_seq_tree(Db* source, Db* target, compact_ctx *ctx);
static couchstore_error_t compact_localdocs_tree(Db* source, Db* target, compact_ctx *ctx);

couchstore_error_t couchstore_compact_db_ex(Db* source,
                                            const char* target_filename,
                                            couchstore_compact_flags flags,
                                            couchstore_compact_hook hook,
                                            couchstore_docinfo_hook dhook,
                                            void* hook_ctx,
                                            FileOpsInterface* ops) {
    return cb::couchstore::compact(
            *source,
            target_filename,
            flags,
            [hook, hook_ctx](Db& db, DocInfo* info, sized_buf body) -> int {
                if (hook == nullptr) {
                    return COUCHSTORE_COMPACT_KEEP_ITEM;
                }
                return hook(&db, info, body, hook_ctx);
            },
            [dhook](DocInfo*& docInfo, sized_buf body) -> int {
                if (dhook == nullptr) {
                    return COUCHSTORE_SUCCESS;
                }
                return dhook(&docInfo, &body);
            },
            ops);
}

couchstore_error_t couchstore_compact_db(Db* source,
                                         const char* target_filename) {
    return couchstore_compact_db_ex(source,
                                    target_filename,
                                    0,
                                    nullptr,
                                    nullptr,
                                    nullptr,
                                    couchstore_get_default_file_ops());
}

LIBCOUCHSTORE_API
couchstore_error_t cb::couchstore::compact(
        Db& source,
        const char* target_filename,
        couchstore_compact_flags flags,
        CompactFilterCallback filterCallback,
        CompactRewriteDocInfoCallback rewriteDocInfoCallback,
        FileOpsInterface* ops) {
    COLLECT_LATENCY();

    if (!filterCallback && rewriteDocInfoCallback) {
        throw std::invalid_argument(
                "cb::couchstore::compact(): filterCallback must be set when "
                "using rewriteDocInfoCallback");
    }

    Db* target = nullptr;
    std::array<char, PATH_MAX> tmpFile;
    couchstore_error_t errcode;
    // Local error code for seq-tree scan.
    couchstore_error_t scan_err = COUCHSTORE_SUCCESS;
    compact_ctx ctx(std::move(filterCallback),
                    std::move(rewriteDocInfoCallback),
                    flags);
    couchstore_open_flags open_flags = COUCHSTORE_OPEN_FLAG_CREATE;
    error_unless(!source.dropped, COUCHSTORE_ERROR_FILE_CLOSED);
    error_unless(ctx.transient_arena && ctx.persistent_arena, COUCHSTORE_ERROR_ALLOC_FAIL);

    // If the old file is downlevel ...
    // ... and upgrade is not requested
    // then the new file must use the old/legacy crc
    if (source.header.disk_version <= COUCH_DISK_VERSION_11 &&
        !(flags & COUCHSTORE_COMPACT_FLAG_UPGRADE_DB)) {
        open_flags |= COUCHSTORE_OPEN_WITH_LEGACY_CRC;
    }

    if (flags & COUCHSTORE_COMPACT_FLAG_UNBUFFERED) {
        open_flags |= COUCHSTORE_OPEN_FLAG_UNBUFFERED;
    }

    if (flags & COUCHSTORE_COMPACT_WITH_PERIODIC_SYNC) {
        static_assert(
                uint64_t(COUCHSTORE_OPEN_WITH_PERIODIC_SYNC) ==
                        uint64_t(COUCHSTORE_COMPACT_WITH_PERIODIC_SYNC),
                "COUCHSTORE_OPEN_WITH_PERIODIC_SYNC and "
                "COUCHSTORE_COMPACT_WITH_PERIODIC_SYNC should have the same"
                "encoding");

        open_flags |= (flags & COUCHSTORE_OPEN_WITH_PERIODIC_SYNC);
    }

    // Transfer current B+tree node settings to new file.
    if (source.file.options.kp_nodesize) {
        uint32_t kp_flag = source.file.options.kp_nodesize / 1024;
        open_flags |= (kp_flag << 20);
    }
    if (source.file.options.kv_nodesize) {
        uint32_t kv_flag = source.file.options.kv_nodesize / 1024;
        open_flags |= (kv_flag << 16);
    }

    error_pass(couchstore_open_db_ex(target_filename, open_flags, ops, &target));

    ctx.target = target;
    target->file.pos = 1;
    target->header.update_seq = source.header.update_seq;
    if (flags & COUCHSTORE_COMPACT_FLAG_DROP_DELETES) {
        //Count the number of times purge has happened
        target->header.purge_seq = source.header.purge_seq + 1;
    } else {
        target->header.purge_seq = source.header.purge_seq;
    }
    target->header.purge_ptr = source.header.purge_ptr;

    if (source.header.by_seq_root) {
        strcpy(tmpFile.data(), target_filename);
        strcat(tmpFile.data(), ".btree-tmp_0");
        error_pass(TreeWriterOpen(tmpFile.data(),
                                  ebin_cmp,
                                  by_id_reduce,
                                  by_id_rereduce,
                                  nullptr,
                                  &ctx.tree_writer));
        scan_err = compact_seq_tree(&source, target, &ctx);
        if (!(flags & COUCHSTORE_COMPACT_RECOVERY_MODE)) {
            // Normal mode: 'compact_seq_tree()' should succeed.
            error_pass(scan_err);
        } // Recovery mode: we can tolerate corruptions.
        error_pass(TreeWriterSort(ctx.tree_writer));
        error_pass(TreeWriterWrite(ctx.tree_writer, &target->file, &target->header.by_id_root));
        TreeWriterFree(ctx.tree_writer);
        ctx.tree_writer = nullptr;
    }

    if (source.header.local_docs_root) {
        error_pass(compact_localdocs_tree(&source, target, &ctx));
    }
    if (ctx.filterCallback) {
        error_pass(static_cast<couchstore_error_t>(
                ctx.filterCallback(*ctx.target,
                                   nullptr, // docinfo
                                   {})));
    }
    error_pass(couchstore_commit_ex(target, source.header.timestamp));
cleanup:
    TreeWriterFree(ctx.tree_writer);
    delete_arena(ctx.transient_arena);
    delete_arena(ctx.persistent_arena);
    if (target != nullptr) {
        couchstore_close_file(target);
        couchstore_free_db(target);
        if (errcode != COUCHSTORE_SUCCESS) {
            remove(target_filename);
        }
    }

    if (errcode == COUCHSTORE_SUCCESS) {
        return scan_err;
    }
    return errcode;
}

static couchstore_error_t output_seqtree_item(const sized_buf *k,
                                              const sized_buf *v,
                                              const DocInfo *docinfo,
                                              compact_ctx *ctx)
{
    couchstore_error_t errcode = COUCHSTORE_SUCCESS;
    sized_buf *v_c;
    const raw_seq_index_value* rawSeq;
    uint32_t idsize, datasize;
    uint32_t revMetaSize;
    sized_buf id_k, id_v;
    raw_id_index_value *raw;
    sized_buf *k_c = arena_copy_buf(ctx->transient_arena, k);

    if (k_c == NULL) {
        error_pass(COUCHSTORE_ERROR_READ);
    }

    if (docinfo) {
        v_c = arena_special_copy_buf_and_revmeta(ctx->transient_arena,
                                                 v, docinfo);
    } else {
        v_c = arena_copy_buf(ctx->transient_arena, v);
    }

    if (v_c == NULL) {
        error_pass(COUCHSTORE_ERROR_READ);
    }

    error_pass(mr_push_item(k_c, v_c, ctx->target_mr));

    // Decode the by-sequence index value. See the file format doc or
    // assemble_id_index_value in couch_db.c:
    rawSeq = (const raw_seq_index_value*)v_c->buf;
    decode_kv_length(&rawSeq->sizes, &idsize, &datasize);
    revMetaSize = (uint32_t)v_c->size - (sizeof(raw_seq_index_value) + idsize);

    // Set up sized_bufs for the ID tree key and value:
    id_k.buf = (char*)(rawSeq + 1);
    id_k.size = idsize;
    id_v.size = sizeof(raw_id_index_value) + revMetaSize;
    id_v.buf = static_cast<char*>(arena_alloc(ctx->transient_arena, id_v.size));

    raw = (raw_id_index_value*)id_v.buf;
    raw->db_seq = *(raw_48*)k->buf;  //Copy db seq from seq tree key
    raw->physical_size = encode_raw32(datasize);
    raw->bp = rawSeq->bp;
    raw->content_meta = rawSeq->content_meta;
    raw->rev_seq = rawSeq->rev_seq;
    memcpy(raw + 1, (uint8_t*)(rawSeq + 1) + idsize, revMetaSize); //Copy rev_meta

    error_pass(TreeWriterAddItem(ctx->tree_writer, id_k, id_v));

    if (ctx->target_mr->count == 0) {
        /* No items queued, we must have just flushed. We can safely rewind the transient arena. */
        arena_free_all(ctx->transient_arena);
    }

cleanup:
    return errcode;
}

static couchstore_error_t compact_seq_fetchcb(couchfile_lookup_request *rq,
                                              const sized_buf *k,
                                              const sized_buf *v)
{
    DocInfo* info = NULL;
    couchstore_error_t errcode = COUCHSTORE_SUCCESS;
    compact_ctx *ctx = (compact_ctx *) rq->callback_ctx;
    raw_seq_index_value* rawSeq = (raw_seq_index_value*)v->buf;
    uint64_t bpWithDeleted = decode_raw48(rawSeq->bp);
    uint64_t bp = bpWithDeleted & ~BP_DELETED_FLAG;
    int ret_val = 0;

    if ((bpWithDeleted & BP_DELETED_FLAG) && (!ctx->filterCallback) &&
        (ctx->flags & COUCHSTORE_COMPACT_FLAG_DROP_DELETES)) {
        return COUCHSTORE_SUCCESS;
    }

    sized_buf item;
    item.buf = nullptr;
    item.size = 0xffffff;

    if (ctx->filterCallback) {
        error_pass(by_seq_read_docinfo(&info, k, v));
        /* If the hook returns with the client requiring the whole body,
         * then the whole body is read from disk and the hook is called
         * again
         */
        int hook_action = ctx->filterCallback(*ctx->target, info, item);
        if (hook_action == COUCHSTORE_COMPACT_NEED_BODY) {
            int size = pread_bin(rq->file, bp, &item.buf);
            if (size < 0) {
                couchstore_free_docinfo(info);
                return static_cast<couchstore_error_t>(size);
            }
            item.size = size_t(size);
            hook_action = ctx->filterCallback(*ctx->target, info, item);
        }

        switch (hook_action) {
        case COUCHSTORE_COMPACT_NEED_BODY:
            throw std::logic_error(
                "compact_seq_fetchcb: COUCHSTORE_COMPACT_NEED_BODY should not be returned "
                "if the body was provided");
        case COUCHSTORE_COMPACT_KEEP_ITEM:
            break;
        case COUCHSTORE_COMPACT_DROP_ITEM:
            goto cleanup;
        default:
            error_pass(static_cast<couchstore_error_t>(hook_action));
        }
    }

    if (bp != 0) {
        cs_off_t new_bp = 0;
        // Copy the document from the old db file to the new one:
        size_t new_size = 0;

        if (item.buf == nullptr) {
            int size = pread_bin(rq->file, bp, &item.buf);
            if (size < 0) {
                couchstore_free_docinfo(info);
                return static_cast<couchstore_error_t>(size);
            }
            item.size = size_t(size);
        }

        if (ctx->rewriteDocInfoCallback) {
            ret_val = ctx->rewriteDocInfoCallback(info, item);
        }
        int err = db_write_buf(ctx->target_mr->rq->file, &item, &new_bp,
                               &new_size);

        bpWithDeleted = (bpWithDeleted & BP_DELETED_FLAG) | new_bp;  //Preserve high bit
        encode_raw48(bpWithDeleted, &rawSeq->bp);
        error_pass(static_cast<couchstore_error_t>(err));
    }

    if (ret_val) {
        error_pass(output_seqtree_item(k, v, info, ctx));
    } else {
        error_pass(output_seqtree_item(k, v, NULL, ctx));
    }

cleanup:
    cb_free(item.buf);
    couchstore_free_docinfo(info);
    return errcode;
}

static couchstore_error_t compact_seq_tree(Db* source, Db* target, compact_ctx *ctx)
{
    couchstore_error_t errcode;
    compare_info seqcmp;
    seqcmp.compare = seq_cmp;
    couchfile_lookup_request srcfold;
    sized_buf low_key;
    //Keys in seq tree are 48-bit numbers, this is 0, lowest possible key
    low_key.buf = const_cast<char*>("\0\0\0\0\0\0");
    low_key.size = 6;
    sized_buf *low_key_list = &low_key;

    ctx->target_mr = new_btree_modres(ctx->persistent_arena,
                                      ctx->transient_arena,
                                      &target->file,
                                      &seqcmp,
                                      by_seq_reduce,
                                      by_seq_rereduce,
                                      NULL,
                                      source->file.options.kv_nodesize,
                                      source->file.options.kp_nodesize);
    if (ctx->target_mr == NULL) {
        error_pass(COUCHSTORE_ERROR_ALLOC_FAIL);
    }

    srcfold.cmp = seqcmp;
    srcfold.file = &source->file;
    srcfold.num_keys = 1;
    srcfold.keys = &low_key_list;
    srcfold.fold = 1;
    srcfold.in_fold = 1;
    srcfold.tolerate_corruption =
            (ctx->flags & COUCHSTORE_COMPACT_RECOVERY_MODE) != 0;
    srcfold.callback_ctx = ctx;
    srcfold.fetch_callback = compact_seq_fetchcb;
    srcfold.node_callback = NULL;

    errcode = btree_lookup(&srcfold, source->header.by_seq_root->pointer);
    if (errcode == COUCHSTORE_SUCCESS || srcfold.tolerate_corruption) {
        if(target->header.by_seq_root != nullptr) {
            cb_free(target->header.by_seq_root);
        }
        couchstore_error_t errcode_local;
        target->header.by_seq_root =
                complete_new_btree(ctx->target_mr, &errcode_local);
        error_tolerate(errcode_local);
    }
cleanup:
    arena_free_all(ctx->persistent_arena);
    arena_free_all(ctx->transient_arena);
    return errcode;
}

static couchstore_error_t compact_localdocs_fetchcb(couchfile_lookup_request *rq,
                                                    const sized_buf *k,
                                                    const sized_buf *v)
{
    compact_ctx *ctx = (compact_ctx *) rq->callback_ctx;
    //printf("V: '%.*s'\n", v->size, v->buf);
    return mr_push_item(arena_copy_buf(ctx->persistent_arena, k),
                        arena_copy_buf(ctx->persistent_arena, v),
                        ctx->target_mr);
}

static couchstore_error_t compact_localdocs_tree(Db* source, Db* target, compact_ctx *ctx)
{
    couchstore_error_t errcode;
    compare_info idcmp;
    idcmp.compare = ebin_cmp;
    couchfile_lookup_request srcfold;

    sized_buf low_key;
    low_key.buf = NULL;
    low_key.size = 0;
    sized_buf *low_key_list = &low_key;

    ctx->target_mr = new_btree_modres(ctx->persistent_arena, NULL, &target->file,
                                      &idcmp, NULL, NULL, NULL,
                                      source->file.options.kv_nodesize,
                                      source->file.options.kp_nodesize);
    if (ctx->target_mr == NULL) {
        error_pass(COUCHSTORE_ERROR_ALLOC_FAIL);
    }

    srcfold.cmp = idcmp;
    srcfold.file = &source->file;
    srcfold.num_keys = 1;
    srcfold.keys = &low_key_list;
    srcfold.fold = 1;
    srcfold.in_fold = 1;
    srcfold.callback_ctx = ctx;
    srcfold.fetch_callback = compact_localdocs_fetchcb;
    srcfold.node_callback = NULL;

    errcode = btree_lookup(&srcfold, source->header.local_docs_root->pointer);
    if (errcode == COUCHSTORE_SUCCESS) {
        target->header.local_docs_root = complete_new_btree(ctx->target_mr, &errcode);
    }
cleanup:
    arena_free_all(ctx->persistent_arena);
    return errcode;
}

couchstore_error_t couchstore_set_purge_seq(Db* target, uint64_t purge_seq) {
    target->header.purge_seq = purge_seq;
    return COUCHSTORE_SUCCESS;

}

