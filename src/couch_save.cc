/*
 *     Copyright 2020 Couchbase, Inc.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */
#include "couchstore_config.h"

#include "couch_btree.h"
#include "couch_latency_internal.h"
#include "internal.h"
#include "node_types.h"
#include "reduces.h"
#include "util.h"
#include <platform/cb_malloc.h>
#include <cstddef>
#include <cstdlib>
#include <cstring>

#define SEQ_INDEX_RAW_VALUE_SIZE(doc_info) \
    (sizeof(raw_seq_index_value) + (doc_info).id.size + (doc_info).rev_meta.size)

#define ID_INDEX_RAW_VALUE_SIZE(doc_info) \
    (sizeof(raw_id_index_value) + (doc_info).rev_meta.size)

#define RAW_SEQ_SIZE sizeof(raw_48)

static size_t assemble_seq_index_value(DocInfo *docinfo, char *dst)
{
    char* const start = dst;
    auto* raw = reinterpret_cast<raw_seq_index_value*>(dst);
    raw->sizes = encode_kv_length(docinfo->id.size, docinfo->physical_size);
    encode_raw48(docinfo->bp | (docinfo->deleted ? 1LL<<47 : 0), &raw->bp);
    raw->content_meta = encode_raw08(docinfo->content_meta);
    encode_raw48(docinfo->rev_seq, &raw->rev_seq);
    dst += sizeof(*raw);

    memcpy(dst, docinfo->id.buf, docinfo->id.size);
    dst += docinfo->id.size;
    if (docinfo->rev_meta.size > 0) {
        memcpy(dst, docinfo->rev_meta.buf, docinfo->rev_meta.size);
        dst += docinfo->rev_meta.size;
    }
    return dst - start;
}

static size_t assemble_id_index_value(DocInfo *docinfo, char *dst)
{
    char* const start = dst;
    auto* raw = reinterpret_cast<raw_id_index_value*>(dst);
    encode_raw48(docinfo->db_seq, &raw->db_seq);
    raw->physical_size = encode_raw32((uint32_t)docinfo->physical_size);
    encode_raw48(docinfo->bp | (docinfo->deleted ? 1LL<<47 : 0), &raw->bp);
    raw->content_meta = encode_raw08(docinfo->content_meta);
    encode_raw48(docinfo->rev_seq, &raw->rev_seq);
    dst += sizeof(*raw);

    if (docinfo->rev_meta.size > 0) {
        memcpy(dst, docinfo->rev_meta.buf, docinfo->rev_meta.size);
        dst += docinfo->rev_meta.size;
    }
    return dst - start;
}

static couchstore_error_t write_doc(Db *db, const Doc *doc, uint64_t *bp,
                                    size_t* disk_size, couchstore_save_options writeopts)
{
    couchstore_error_t errcode;
    if (writeopts & COMPRESS_DOC_BODIES) {
        errcode = db_write_buf_compressed(&db->file, &doc->data, (cs_off_t *) bp, disk_size);
    } else {
        errcode = static_cast<couchstore_error_t>(db_write_buf(&db->file, &doc->data, (cs_off_t *) bp, disk_size));
    }

    return errcode;
}

static int ebin_ptr_compare(const void* a, const void* b) {
    const auto* const* buf1 = static_cast<const sized_buf* const*>(a);
    const auto* const* buf2 = static_cast<const sized_buf* const*>(b);
    return ebin_cmp(*buf1, *buf2);
}

static int seq_action_compare(const void *actv1, const void *actv2)
{
    const couchfile_modify_action *act1, *act2;
    act1 = static_cast<const couchfile_modify_action *>(actv1);
    act2 = static_cast<const couchfile_modify_action *>(actv2);

    uint64_t seq1, seq2;

    seq1 = decode_sequence_key(act1->getKey());
    seq2 = decode_sequence_key(act2->getKey());

    if (seq1 < seq2) {
        return -1;
    }
    if (seq1 == seq2) {
        if (act1->getType() < act2->getType()) {
            return -1;
        }
        if (act1->getType() > act2->getType()) {
            return 1;
        }
        return 0;
    }
    if (seq1 > seq2) {
        return 1;
    }
    return 0;
}

struct index_update_ctx {
    index_update_ctx(couchfile_modify_action* seqacts, fatbuf& deltermbuf)
        : seqacts(seqacts), deltermbuf(deltermbuf) {
    }
    couchfile_modify_action* seqacts = nullptr;
    int actpos = 0;
    int valpos = 0;
    fatbuf& deltermbuf;
};

static couchstore_error_t idfetch_update_cb(couchfile_modify_request*,
                                            sized_buf*,
                                            sized_buf* v,
                                            void* arg) {
    if (v == nullptr) { // Doc not found
        return COUCHSTORE_SUCCESS;
    }

    // v contains a seq we need to remove ( {Seq,_,_,_,_} )
    auto* ctx = static_cast<index_update_ctx*>(arg);
    const raw_id_index_value *raw = (raw_id_index_value*) v->buf;
    uint64_t oldseq = decode_raw48(raw->db_seq);

    auto* delbuf = static_cast<sized_buf*>(
            fatbuf_get(&ctx->deltermbuf, sizeof(sized_buf)));

    if (!delbuf) {
        return COUCHSTORE_ERROR_ALLOC_FAIL;
    }

    delbuf->buf = static_cast<char*>(fatbuf_get(&ctx->deltermbuf, 6));
    delbuf->size = 6;
    memset(delbuf->buf, 0, 6);
    encode_raw48(oldseq, (raw_48*)delbuf->buf);

    ctx->seqacts[ctx->actpos].setType(ACTION_REMOVE);
    ctx->seqacts[ctx->actpos].data = nullptr;
    ctx->seqacts[ctx->actpos].setKey(delbuf);

    ctx->actpos++;
    return COUCHSTORE_SUCCESS;
}

static couchstore_error_t update_indexes(Db* db,
                                         sized_buf* seqs,
                                         sized_buf* seqvals,
                                         sized_buf* ids,
                                         sized_buf* idvals,
                                         int numdocs,
                                         save_callback_fn save_callback,
                                         void* save_callback_ctx,
                                         void* const userReqs[]) {
    /**
     * Buffer size breakdown (per item) by use order:
     * 1 x sizeof(couchfile_modify_action) for seq tree Removes generated by
     *     the idfetch_update_cb (id tree Fetch callback)
     *
     * 1 x sizeof(couchfile_modify_action) for id tree FetchInserts
     *
     * 1 x sizeof(sized_buf) for the delbuf sized_buffer created in
     *     idfetch_update_cb
     * 1 x 6 bytes for the seqno of the item to remove from the seq tree pointed
     *     to by the delbuf created in idfetch_update_cb
     */
    const size_t size =
            2 * sizeof(couchfile_modify_action) + sizeof(sized_buf) + 6;

    cb::couchstore::unique_fatbuf_ptr actbuf(fatbuf_alloc(numdocs * size));
    if (!actbuf) {
        return COUCHSTORE_ERROR_ALLOC_FAIL;
    }

    auto* seqacts = static_cast<couchfile_modify_action*>(fatbuf_get(
            actbuf.get(), numdocs * sizeof(couchfile_modify_action)));
    auto* idacts = static_cast<couchfile_modify_action*>(fatbuf_get(
            actbuf.get(), numdocs * sizeof(couchfile_modify_action)));
    if (!idacts || !seqacts) {
        return COUCHSTORE_ERROR_ALLOC_FAIL;
    }

    // Sort the array indexes of ids[] by ascending id. Since we can't pass context info to qsort,
    // actually sort an array of pointers to the elements of ids[], rather than the array indexes.
    std::vector<sized_buf*> sorted_ids(numdocs);
    for (int ii = 0; ii < numdocs; ++ii) {
        sorted_ids[ii] = &ids[ii];
    }
    qsort(sorted_ids.data(), numdocs, sizeof(sorted_ids[0]), &ebin_ptr_compare);

    // Assemble idacts[] array, in sorted order by id:
    for (int ii = 0; ii < numdocs; ii++) {
        ptrdiff_t isorted = sorted_ids[ii] - ids;   // recover index of ii'th id in sort order

        idacts[ii].setType(ACTION_FETCH_INSERT);
        idacts[ii].data = &idvals[isorted];
        idacts[ii].setKey(&ids[isorted]);
        // Compaction doesn't provide any save-doc-callback / userReqs
        idacts[ii].userReq = userReqs ? userReqs[isorted] : nullptr;
    }

    // Update the by id index
    index_update_ctx fetcharg(seqacts, *actbuf);
    couchfile_modify_request idrq;
    idrq.cmp.compare = ebin_cmp;
    idrq.file = &db->file;
    idrq.actions = idacts;
    idrq.num_actions = numdocs;
    idrq.reduce = by_id_reduce;
    idrq.rereduce = by_id_rereduce;
    idrq.fetch_callback = idfetch_update_cb;
    idrq.fetch_callback_ctx = &fetcharg;
    idrq.compacting = 0;
    idrq.enable_purging = false;
    idrq.purge_kp = nullptr;
    idrq.purge_kv = nullptr;
    idrq.kv_chunk_threshold = db->file.options.kv_nodesize;
    idrq.kp_chunk_threshold = db->file.options.kp_nodesize;
    idrq.save_callback = save_callback;
    idrq.save_callback_ctx = save_callback_ctx;
    idrq.docinfo_callback = by_id_read_docinfo;

    couchstore_error_t errcode;
    auto* new_id_root = modify_btree(&idrq, db->header.by_id_root, &errcode);
    if (errcode != COUCHSTORE_SUCCESS) {
        return errcode;
    }

    // Append our seqno index updates from the last action added to seqacts. If
    // we have added anything to seqacts then this will overrun the memory that
    // we allocated specifically for seqacts and run into idacts which we no
    // longer need as we have finished processing them.
    while (fetcharg.valpos < numdocs) {
        seqacts[fetcharg.actpos].setType(ACTION_INSERT);
        seqacts[fetcharg.actpos].data = &seqvals[fetcharg.valpos];
        seqacts[fetcharg.actpos].setKey(&seqs[fetcharg.valpos]);
        fetcharg.valpos++;
        fetcharg.actpos++;
    }

    qsort(seqacts, fetcharg.actpos, sizeof(couchfile_modify_action),
          seq_action_compare);

    // Update the by seqno index
    couchfile_modify_request seqrq;
    seqrq.cmp.compare = seq_cmp;
    seqrq.actions = seqacts;
    seqrq.num_actions = fetcharg.actpos;
    seqrq.reduce = by_seq_reduce;
    seqrq.rereduce = by_seq_rereduce;
    seqrq.file = &db->file;
    seqrq.compacting = 0;
    seqrq.enable_purging = false;
    seqrq.purge_kp = nullptr;
    seqrq.purge_kv = nullptr;
    seqrq.kv_chunk_threshold = db->file.options.kv_nodesize;
    seqrq.kp_chunk_threshold = db->file.options.kp_nodesize;

    auto* new_seq_root = modify_btree(&seqrq, db->header.by_seq_root, &errcode);
    if (errcode != COUCHSTORE_SUCCESS) {
        cb_free(new_id_root);
        return errcode;
    }

    if (db->header.by_id_root != new_id_root) {
        cb_free(db->header.by_id_root);
        db->header.by_id_root = new_id_root;
    }

    if (db->header.by_seq_root != new_seq_root) {
        cb_free(db->header.by_seq_root);
        db->header.by_seq_root = new_seq_root;
    }

    return COUCHSTORE_SUCCESS;
}

static couchstore_error_t add_doc_to_update_list(Db *db,
                                                 const Doc *doc,
                                                 const DocInfo *info,
                                                 fatbuf *fb,
                                                 sized_buf *seqterm,
                                                 sized_buf *idterm,
                                                 sized_buf *seqval,
                                                 sized_buf *idval,
                                                 couchstore_save_options options)
{
    couchstore_error_t errcode = COUCHSTORE_SUCCESS;
    DocInfo updated = *info;

    seqterm->buf = (char *) fatbuf_get(fb, RAW_SEQ_SIZE);
    seqterm->size = RAW_SEQ_SIZE;
    error_unless(seqterm->buf, COUCHSTORE_ERROR_ALLOC_FAIL);
    encode_raw48(updated.db_seq, (raw_48*)seqterm->buf);

    if (doc) {
        size_t disk_size;

        // Don't compress a doc unless the meta flag is set
        if (!(info->content_meta & COUCH_DOC_IS_COMPRESSED)) {
            options &= ~COMPRESS_DOC_BODIES;
        }
        errcode = write_doc(db, doc, &updated.bp, &disk_size, options);

        if (errcode != COUCHSTORE_SUCCESS) {
            return errcode;
        }
        updated.physical_size = disk_size;
    } else {
        updated.deleted = 1;
        updated.bp = 0;
        updated.physical_size = 0;
    }

    *idterm = updated.id;

    seqval->buf = (char *) fatbuf_get(fb, SEQ_INDEX_RAW_VALUE_SIZE(updated));
    error_unless(seqval->buf, COUCHSTORE_ERROR_ALLOC_FAIL);
    seqval->size = assemble_seq_index_value(&updated, seqval->buf);

    idval->buf = (char *) fatbuf_get(fb, ID_INDEX_RAW_VALUE_SIZE(updated));
    error_unless(idval->buf, COUCHSTORE_ERROR_ALLOC_FAIL);
    idval->size = assemble_id_index_value(&updated, idval->buf);

    //We use 37 + id.size + 2 * rev_meta.size bytes
cleanup:
    return errcode;
}

couchstore_error_t couchstore_save_documents_and_callback(
        Db* db,
        const Doc* const docs[],
        DocInfo* const infos[],
        void* const userReqs[],
        unsigned numdocs,
        couchstore_save_options options,
        save_callback_fn save_cb,
        void* save_cb_ctx) {
    if (db->dropped) {
        return COUCHSTORE_ERROR_FILE_CLOSED;
    }

    COLLECT_LATENCY();

    size_t term_meta_size = 0;
    for (unsigned ii = 0; ii < numdocs; ii++) {
        // Get additional size for terms to be inserted into indexes
        // IMPORTANT: This must match the sizes of the fatbuf_get calls in add_doc_to_update_list!
        term_meta_size += RAW_SEQ_SIZE;
        term_meta_size += SEQ_INDEX_RAW_VALUE_SIZE(*infos[ii]);
        term_meta_size += ID_INDEX_RAW_VALUE_SIZE(*infos[ii]);
    }

    cb::couchstore::unique_fatbuf_ptr fb(fatbuf_alloc(
            term_meta_size +
            numdocs * (sizeof(sized_buf) * 4))); // seq/id key and value lists

    if (!fb) {
        return COUCHSTORE_ERROR_ALLOC_FAIL;
    }

    auto* seqklist = static_cast<sized_buf*>(
            fatbuf_get(fb.get(), numdocs * sizeof(sized_buf)));
    auto* idklist = static_cast<sized_buf*>(
            fatbuf_get(fb.get(), numdocs * sizeof(sized_buf)));
    auto* seqvlist = static_cast<sized_buf*>(
            fatbuf_get(fb.get(), numdocs * sizeof(sized_buf)));
    auto* idvlist = static_cast<sized_buf*>(
            fatbuf_get(fb.get(), numdocs * sizeof(sized_buf)));

    uint64_t seq = db->header.update_seq;
    for (unsigned ii = 0; ii < numdocs; ii++) {
        const Doc* curdoc;

        if(options & COUCHSTORE_SEQUENCE_AS_IS) {
            seq = std::max(seq, infos[ii]->db_seq);
        } else {
            infos[ii]->db_seq = ++seq;
        }

        if (docs) {
            curdoc = docs[ii];
        } else {
            curdoc = nullptr;
        }

        const auto errcode = add_doc_to_update_list(db,
                                                    curdoc,
                                                    infos[ii],
                                                    fb.get(),
                                                    &seqklist[ii],
                                                    &idklist[ii],
                                                    &seqvlist[ii],
                                                    &idvlist[ii],
                                                    options);
        if (errcode != COUCHSTORE_SUCCESS) {
            return errcode;
        }
    }

    const auto errcode = update_indexes(db,
                                        seqklist,
                                        seqvlist,
                                        idklist,
                                        idvlist,
                                        numdocs,
                                        save_cb,
                                        save_cb_ctx,
                                        userReqs);

    if (errcode != COUCHSTORE_SUCCESS) {
        return errcode;
    }

    db->header.update_seq = seq;

    return COUCHSTORE_SUCCESS;
}

couchstore_error_t couchstore_save_documents(Db* db,
                                             Doc* const docs[],
                                             DocInfo* infos[],
                                             unsigned numDocs,
                                             couchstore_save_options options) {
    return couchstore_save_documents_and_callback(
            db, docs, infos, nullptr, numDocs, options, nullptr, nullptr);
}

couchstore_error_t couchstore_save_document(Db *db, const Doc *doc,
                                            DocInfo *info, couchstore_save_options options)
{
    return couchstore_save_documents_and_callback(db,
                                                  (Doc**)&doc,
                                                  (DocInfo**)&info,
                                                  nullptr,
                                                  1,
                                                  options,
                                                  nullptr,
                                                  nullptr);
}
