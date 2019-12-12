/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#include "couchstore_config.h"

#include <platform/cb_malloc.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>

#include "internal.h"
#include "node_types.h"
#include "util.h"
#include "reduces.h"
#include "couch_btree.h"

#include "couch_latency_internal.h"


#define SEQ_INDEX_RAW_VALUE_SIZE(doc_info) \
    (sizeof(raw_seq_index_value) + (doc_info).id.size + (doc_info).rev_meta.size)

#define ID_INDEX_RAW_VALUE_SIZE(doc_info) \
    (sizeof(raw_id_index_value) + (doc_info).rev_meta.size)

#define RAW_SEQ_SIZE sizeof(raw_48)


static size_t assemble_seq_index_value(DocInfo *docinfo, char *dst)
{
    char* const start = dst;
    raw_seq_index_value *raw = (raw_seq_index_value*)dst;
    raw->sizes = encode_kv_length(docinfo->id.size, docinfo->size);
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
    raw_id_index_value *raw = (raw_id_index_value*)dst;
    encode_raw48(docinfo->db_seq, &raw->db_seq);
    raw->size = encode_raw32((uint32_t)docinfo->size);
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

static int ebin_ptr_compare(const void *a, const void *b)
{
    const sized_buf* const* buf1 = static_cast<const sized_buf* const *>(a);
    const sized_buf* const* buf2 = static_cast<const sized_buf* const *>(b);
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

typedef struct _idxupdatectx {
    couchfile_modify_action *seqacts;
    int actpos;

    sized_buf **seqs;
    sized_buf **seqvals;
    int valpos;

    fatbuf *deltermbuf;
} index_update_ctx;

static void idfetch_update_cb(couchfile_modify_request *rq,
                              sized_buf *k, sized_buf *v, void *arg)
{
    (void)k;
    (void)rq;
    //v contains a seq we need to remove ( {Seq,_,_,_,_} )
    uint64_t oldseq;
    sized_buf *delbuf = NULL;
    index_update_ctx *ctx = (index_update_ctx *) arg;

    if (v == NULL) { //Doc not found
        return;
    }

    const raw_id_index_value *raw = (raw_id_index_value*) v->buf;
    oldseq = decode_raw48(raw->db_seq);

    delbuf = (sized_buf *) fatbuf_get(ctx->deltermbuf, sizeof(sized_buf));
    delbuf->buf = (char *) fatbuf_get(ctx->deltermbuf, 6);
    delbuf->size = 6;
    memset(delbuf->buf, 0, 6);
    encode_raw48(oldseq, (raw_48*)delbuf->buf);

    ctx->seqacts[ctx->actpos].setType(ACTION_REMOVE);
    ctx->seqacts[ctx->actpos].data = NULL;
    ctx->seqacts[ctx->actpos].setKey(delbuf);

    ctx->actpos++;
}

static couchstore_error_t update_indexes(Db* db,
                                         sized_buf* seqs,
                                         sized_buf* seqvals,
                                         sized_buf* ids,
                                         sized_buf* idvals,
                                         int numdocs,
                                         save_callback_fn save_callback,
                                         void* save_callback_ctx) {
    couchfile_modify_action *idacts;
    couchfile_modify_action *seqacts;
    const sized_buf **sorted_ids = NULL;
    size_t size;
    fatbuf *actbuf;
    node_pointer *new_id_root;
    node_pointer *new_seq_root;
    couchstore_error_t errcode;
    couchstore_error_t err;
    couchfile_modify_request seqrq, idrq;
    int ii;
    index_update_ctx fetcharg;

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
    size = 2 * sizeof(couchfile_modify_action) + sizeof(sized_buf) + 6;

    actbuf = fatbuf_alloc(numdocs * size);
    error_unless(actbuf, COUCHSTORE_ERROR_ALLOC_FAIL);

    seqacts = static_cast<couchfile_modify_action*>(
            fatbuf_get(actbuf, numdocs * sizeof(couchfile_modify_action)));
    idacts = static_cast<couchfile_modify_action*>(
            fatbuf_get(actbuf, numdocs * sizeof(couchfile_modify_action)));
    error_unless(idacts && seqacts, COUCHSTORE_ERROR_ALLOC_FAIL);

    memset(&fetcharg, 0, sizeof(fetcharg));
    fetcharg.seqacts = seqacts;
    fetcharg.actpos = 0;
    fetcharg.seqs = &seqs;
    fetcharg.seqvals = &seqvals;
    fetcharg.valpos = 0;
    fetcharg.deltermbuf = actbuf;

    // Sort the array indexes of ids[] by ascending id. Since we can't pass context info to qsort,
    // actually sort an array of pointers to the elements of ids[], rather than the array indexes.
    sorted_ids = static_cast<const sized_buf**>(cb_malloc(numdocs * sizeof(sized_buf*)));
    error_unless(sorted_ids, COUCHSTORE_ERROR_ALLOC_FAIL);
    for (ii = 0; ii < numdocs; ++ii) {
        sorted_ids[ii] = &ids[ii];
    }
    qsort(sorted_ids, numdocs, sizeof(sorted_ids[0]), &ebin_ptr_compare);

    // Assemble idacts[] array, in sorted order by id:
    for (ii = 0; ii < numdocs; ii++) {
        ptrdiff_t isorted = sorted_ids[ii] - ids;   // recover index of ii'th id in sort order

        idacts[ii].setType(ACTION_FETCH_INSERT);
        idacts[ii].data = &idvals[isorted];
        // Allow the by_id building to find the by_seqno for each id.
        // The save_callback method passes back id and seqno to the caller.
        idacts[ii].seq = &seqs[isorted];
        idacts[ii].setKey(&ids[isorted]);
    }

    // Update the by id index
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
    idrq.purge_kp = NULL;
    idrq.purge_kv = NULL;
    idrq.kv_chunk_threshold = db->file.options.kv_nodesize;
    idrq.kp_chunk_threshold = db->file.options.kp_nodesize;
    idrq.save_callback = save_callback;
    idrq.save_callback_ctx = save_callback_ctx;
    idrq.docinfo_callback = by_id_read_docinfo;

    new_id_root = modify_btree(&idrq, db->header.by_id_root, &err);
    error_pass(err);

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
    seqrq.cmp.compare = seq_cmp;
    seqrq.actions = seqacts;
    seqrq.num_actions = fetcharg.actpos;
    seqrq.reduce = by_seq_reduce;
    seqrq.rereduce = by_seq_rereduce;
    seqrq.file = &db->file;
    seqrq.compacting = 0;
    seqrq.enable_purging = false;
    seqrq.purge_kp = NULL;
    seqrq.purge_kv = NULL;
    seqrq.kv_chunk_threshold = db->file.options.kv_nodesize;
    seqrq.kp_chunk_threshold = db->file.options.kp_nodesize;

    new_seq_root = modify_btree(&seqrq, db->header.by_seq_root, &errcode);
    if (errcode != COUCHSTORE_SUCCESS) {
        cb_free(new_id_root);
        error_pass(errcode);
    }

    if (db->header.by_id_root != new_id_root) {
        cb_free(db->header.by_id_root);
        db->header.by_id_root = new_id_root;
    }

    if (db->header.by_seq_root != new_seq_root) {
        cb_free(db->header.by_seq_root);
        db->header.by_seq_root = new_seq_root;
    }

cleanup:
    cb_free(sorted_ids);
    fatbuf_free(actbuf);
    return errcode;
}

static couchstore_error_t add_doc_to_update_list(Db *db,
                                                 const Doc *doc,
                                                 const DocInfo *info,
                                                 fatbuf *fb,
                                                 sized_buf *seqterm,
                                                 sized_buf *idterm,
                                                 sized_buf *seqval,
                                                 sized_buf *idval,
                                                 uint64_t seq,
                                                 couchstore_save_options options)
{
    couchstore_error_t errcode = COUCHSTORE_SUCCESS;
    DocInfo updated = *info;
    updated.db_seq = seq;

    seqterm->buf = (char *) fatbuf_get(fb, RAW_SEQ_SIZE);
    seqterm->size = RAW_SEQ_SIZE;
    error_unless(seqterm->buf, COUCHSTORE_ERROR_ALLOC_FAIL);
    encode_raw48(seq, (raw_48*)seqterm->buf);

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
        updated.size = disk_size;
    } else {
        updated.deleted = 1;
        updated.bp = 0;
        updated.size = 0;
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
        Doc* const docs[],
        DocInfo* infos[],
        unsigned numdocs,
        couchstore_save_options options,
        save_callback_fn save_cb,
        void* save_cb_ctx) {
    COLLECT_LATENCY();

    couchstore_error_t errcode = COUCHSTORE_SUCCESS;
    unsigned ii;
    sized_buf *seqklist, *idklist, *seqvlist, *idvlist;
    size_t term_meta_size = 0;
    const Doc *curdoc;
    uint64_t seq = db->header.update_seq;

    fatbuf *fb;

    error_unless(!db->dropped, COUCHSTORE_ERROR_FILE_CLOSED);

    for (ii = 0; ii < numdocs; ii++) {
        // Get additional size for terms to be inserted into indexes
        // IMPORTANT: This must match the sizes of the fatbuf_get calls in add_doc_to_update_list!
        term_meta_size += RAW_SEQ_SIZE;
        term_meta_size += SEQ_INDEX_RAW_VALUE_SIZE(*infos[ii]);
        term_meta_size += ID_INDEX_RAW_VALUE_SIZE(*infos[ii]);
    }

    fb = fatbuf_alloc(term_meta_size +
                      numdocs * (sizeof(sized_buf) * 4)); //seq/id key and value lists

    if (fb == NULL) {
        return COUCHSTORE_ERROR_ALLOC_FAIL;
    }


    seqklist = static_cast<sized_buf*>(fatbuf_get(fb, numdocs * sizeof(sized_buf)));
    idklist = static_cast<sized_buf*>(fatbuf_get(fb, numdocs * sizeof(sized_buf)));
    seqvlist = static_cast<sized_buf*>(fatbuf_get(fb, numdocs * sizeof(sized_buf)));
    idvlist = static_cast<sized_buf*>(fatbuf_get(fb, numdocs * sizeof(sized_buf)));

    for (ii = 0; ii < numdocs; ii++) {
        if(options & COUCHSTORE_SEQUENCE_AS_IS) {
            seq = infos[ii]->db_seq;
        } else {
            seq++;
        }

        if (docs) {
            curdoc = docs[ii];
        } else {
            curdoc = NULL;
        }

        errcode = add_doc_to_update_list(db, curdoc, infos[ii], fb,
                                         &seqklist[ii], &idklist[ii],
                                         &seqvlist[ii], &idvlist[ii],
                                         seq, options);
        if (errcode != COUCHSTORE_SUCCESS) {
            break;
        }
    }

    if (errcode == COUCHSTORE_SUCCESS) {
        errcode = update_indexes(db,
                                 seqklist,
                                 seqvlist,
                                 idklist,
                                 idvlist,
                                 numdocs,
                                 save_cb,
                                 save_cb_ctx);
    }

    fatbuf_free(fb);
    if (errcode == COUCHSTORE_SUCCESS) {
        if(options & COUCHSTORE_SEQUENCE_AS_IS) {
            // Sequences are passed as-is, make sure update_seq is >= the highest.
            seq = db->header.update_seq;
            for(ii = 0; ii < numdocs; ii++) {
                if(infos[ii]->db_seq >= seq) {
                    seq = infos[ii]->db_seq;
                }
            }
            db->header.update_seq = seq;
        } else {
            // Fill in the assigned sequence numbers for caller's later use:
            seq = db->header.update_seq;
            for (ii = 0; ii < numdocs; ii++) {
                infos[ii]->db_seq = ++seq;
            }
            db->header.update_seq = seq;
        }
    }
 cleanup:
    return errcode;
}

couchstore_error_t couchstore_save_documents(Db* db,
                                             Doc* const docs[],
                                             DocInfo* infos[],
                                             unsigned numDocs,
                                             couchstore_save_options options) {
    return couchstore_save_documents_and_callback(
            db, docs, infos, numDocs, options, nullptr, nullptr);
}

couchstore_error_t couchstore_save_document(Db *db, const Doc *doc,
                                            DocInfo *info, couchstore_save_options options)
{
    return couchstore_save_documents_and_callback(
            db, (Doc**)&doc, (DocInfo**)&info, 1, options, nullptr, nullptr);
}
