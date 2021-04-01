/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#include "couchstore_config.h"
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include "couch_btree.h"
#include "util.h"
#include "arena.h"
#include "node_types.h"
#include "../util.h"
#include "spatial.h"
#include <platform/cb_malloc.h>
#include <platform/cbassert.h>

/* NOTE vmx 2014-07-21: spatial_modify.c uses a lot of code from
 * btree_modify.cc. The difference is the different handling of the reduce.
 * In spatial views, we use a reduce function to calculate the enclosing
 * MBB of the parent node, which is then used as key.
 * In the future there should also be a different flushing/leaf node
 * partitioning strategy */

static couchstore_error_t flush_spatial_partial(couchfile_modify_result *res,
                                                size_t mr_quota);

static couchstore_error_t flush_spatial(couchfile_modify_result *res);

/* When flushing the nodes, only fill them up to 2/3 of the threshold.
 * This way future inserts still have room within the nodes without
 * forcing a split immediately */
static couchstore_error_t maybe_flush_spatial(couchfile_modify_result *mr)
{
    if(mr->rq->compacting) {
        /* The compactor can (and should), just write out nodes
         * of size CHUNK_SIZE as soon as it can, so that it can
         * free memory it no longer needs. */
        if (mr->modified && (((mr->node_type == KV_NODE) &&
            mr->node_len > (mr->rq->kv_chunk_threshold * 2 / 3)) ||
            ((mr->node_type == KP_NODE) &&
             mr->node_len > (mr->rq->kp_chunk_threshold * 2 / 3) &&
             mr->count > 1))) {
            return flush_spatial(mr);
        }
    } else if (mr->modified && mr->count > 3) {
        /* Don't write out a partial node unless we've collected
         * at least three items */
        if ((mr->node_type == KV_NODE) &&
             mr->node_len > mr->rq->kv_chunk_threshold) {
            return flush_spatial_partial(
                mr, (mr->rq->kv_chunk_threshold * 2 / 3));
        }
        if ((mr->node_type == KP_NODE) &&
             mr->node_len > mr->rq->kp_chunk_threshold) {
            return flush_spatial_partial(
                mr, (mr->rq->kp_chunk_threshold * 2 / 3));
        }
    }

    return COUCHSTORE_SUCCESS;
}

static nodelist *make_nodelist(arena* a, size_t bufsize)
{
    nodelist *r = (nodelist *) arena_alloc(a, sizeof(nodelist) + bufsize);
    if (r == nullptr) {
        return nullptr;
    }
    r = {};
    r->data.size = bufsize;
    r->data.buf = ((char *) r) + (sizeof(nodelist));
    return r;
}

static couchfile_modify_result *spatial_make_modres(arena* a,
                                            couchfile_modify_request *rq)
{
    couchfile_modify_result *res = (couchfile_modify_result *) arena_alloc(
        a, sizeof(couchfile_modify_result));
    if (res == nullptr) {
        return nullptr;
    }
    res->rq = rq;
    res->arena = a;
    res->arena_transient = nullptr;
    res->values = make_nodelist(a, 0);
    if (res->values == nullptr) {
        return nullptr;
    }
    res->values_end = res->values;
    res->node_len = 0;
    res->count = 0;
    res->pointers = make_nodelist(a, 0);
    if (res->pointers == nullptr) {
        return nullptr;
    }
    res->pointers_end = res->pointers;
    res->modified = 0;
    res->node_type = 0;
    res->error_state = 0;
    return res;
}

couchstore_error_t spatial_push_item(sized_buf *k,
                                     sized_buf *v,
                                     couchfile_modify_result *dst)
{
    nodelist* itm = nullptr;
    if (dst->arena_transient != nullptr) {
        itm = make_nodelist(dst->arena_transient, 0);
    } else {
        cb_assert(dst->arena != nullptr);
        itm = make_nodelist(dst->arena, 0);
    }
    if (itm == nullptr) {
        return COUCHSTORE_ERROR_ALLOC_FAIL;
    }
    itm->data = *v;
    itm->key = *k;
    itm->pointer = nullptr;
    dst->values_end->next = itm;
    dst->values_end = itm;
    /* Encoded size (see flush_spatial) */
    dst->node_len += k->size + v->size + sizeof(raw_kv_length);
    dst->count++;
    return maybe_flush_spatial(dst);
}

static nodelist *encode_pointer(arena* a, node_pointer *ptr)
{
    raw_node_pointer *raw;
    nodelist *pel = make_nodelist(
        a, sizeof(raw_node_pointer) + ptr->reduce_value.size);
    if (pel == nullptr) {
        return nullptr;
    }
    raw = (raw_node_pointer*)pel->data.buf;
    encode_raw48(ptr->pointer, &raw->pointer);
    encode_raw48(ptr->subtreesize, &raw->subtreesize);
    raw->reduce_value_size = encode_raw16((uint16_t)ptr->reduce_value.size);
    memcpy(raw + 1, ptr->reduce_value.buf, ptr->reduce_value.size);
    pel->pointer = ptr;
    pel->key = ptr->key;
    return pel;
}

/* Write the current contents of the values list to disk as a node
 * and add the resulting pointer to the pointers list. */
static couchstore_error_t flush_spatial(couchfile_modify_result *res)
{
    return flush_spatial_partial(res, res->node_len);
}

/* Write a node using enough items from the values list to create a node
 * with uncompressed size of at least mr_quota */
static couchstore_error_t flush_spatial_partial(couchfile_modify_result *res,
                                                size_t mr_quota)
{
    char *dst;
    couchstore_error_t errcode = COUCHSTORE_SUCCESS;
    int itmcount = 0;
    char* nodebuf = nullptr;
    sized_buf writebuf;
    char reducebuf[MAX_REDUCTION_SIZE];
    size_t reducesize = 0;
    uint64_t subtreesize = 0;
    cs_off_t diskpos;
    size_t disk_size;
    nodelist *i, *pel;
    node_pointer *ptr;

    if (res->values_end == res->values || ! res->modified) {
        /* Empty */
        return COUCHSTORE_SUCCESS;
    }

    /* nodebuf/writebuf is very short-lived and can be large, so use regular
     * malloc heap for it: */
    nodebuf = (char *) cb_malloc(res->node_len + 1);
    if (nodebuf == nullptr) {
        return COUCHSTORE_ERROR_ALLOC_FAIL;
    }

    writebuf.buf = nodebuf;

    dst = nodebuf;
    *(dst++) = (char) res->node_type;

    i = res->values->next;
    /* We don't care that we've reached mr_quota if we haven't written out
     * at least two items and we're not writing a leaf node. */
    while (i != nullptr &&
           (mr_quota > 0 || (itmcount < 2 && res->node_type == KP_NODE))) {
        dst = (char *) write_kv(dst, i->key, i->data);
        if (i->pointer) {
            subtreesize += i->pointer->subtreesize;
        }
        mr_quota -= i->key.size + i->data.size + sizeof(raw_kv_length);
        i = i->next;
        res->count--;
        itmcount++;
    }

    writebuf.size = dst - nodebuf;

    errcode = (couchstore_error_t) db_write_buf_compressed(
        res->rq->file, &writebuf, &diskpos, &disk_size);
    cb_free(nodebuf);  /* here endeth the nodebuf. */
    if (errcode != COUCHSTORE_SUCCESS) {
        return errcode;
    }

    /* Store the enclosing MBB in the reducebuf */
    if (res->node_type == KV_NODE && res->rq->reduce) {
        errcode = res->rq->reduce(
            reducebuf, &reducesize, res->values->next, itmcount,
            res->rq->user_reduce_ctx);
        if (errcode != COUCHSTORE_SUCCESS) {
            return errcode;
        }
        cb_assert(reducesize <= sizeof(reducebuf));
    }

    if (res->node_type == KP_NODE && res->rq->rereduce) {
        errcode = res->rq->rereduce(
            reducebuf, &reducesize, res->values->next, itmcount,
            res->rq->user_reduce_ctx);
        if (errcode != COUCHSTORE_SUCCESS) {
            return errcode;
        }
        cb_assert(reducesize <= sizeof(reducebuf));
    }

    /* `reducesize` one time for the key, one time for the actual reduce */
    ptr = (node_pointer *) arena_alloc(
        res->arena, sizeof(node_pointer) + 2 * reducesize);
    if (ptr == nullptr) {
        return COUCHSTORE_ERROR_ALLOC_FAIL;
    }

    ptr->key.buf = ((char *)ptr) + sizeof(node_pointer);
    ptr->reduce_value.buf = ((char *)ptr) + sizeof(node_pointer) + reducesize;

    ptr->key.size = reducesize;
    ptr->reduce_value.size = reducesize;

    /* Store the enclosing MBB that was calculate in the reduce function
     * as the key. The reduce also stores it as it is the "Original MBB"
     * used in the RR*-tree algorithm */
    memcpy(ptr->key.buf, reducebuf, reducesize);
    memcpy(ptr->reduce_value.buf, reducebuf, reducesize);

    ptr->subtreesize = subtreesize + disk_size;
    ptr->pointer = diskpos;

    pel = encode_pointer(res->arena, ptr);
    if (pel == nullptr) {
        return COUCHSTORE_ERROR_ALLOC_FAIL;
    }

    res->pointers_end->next = pel;
    res->pointers_end = pel;

    res->node_len -= (writebuf.size - 1);

    res->values->next = i;
    if (i == nullptr) {
        res->values_end = res->values;
    }

    return COUCHSTORE_SUCCESS;
}

/* Move src pointers list to dst node's values list. */
static couchstore_error_t spatial_move_pointers(couchfile_modify_result *src,
                                                couchfile_modify_result *dst)
{
    nodelist *ptr, *next;

    couchstore_error_t errcode = COUCHSTORE_SUCCESS;
    if (src->pointers_end == src->pointers) {
        return COUCHSTORE_SUCCESS;
    }

    ptr = src->pointers->next;
    next = ptr;
    while (ptr != nullptr && errcode == 0) {
        dst->node_len += ptr->data.size + ptr->key.size +
                sizeof(raw_kv_length);
        dst->count++;

        next = ptr->next;
        ptr->next = nullptr;

        dst->values_end->next = ptr;
        dst->values_end = ptr;
        ptr = next;
        error_pass(maybe_flush_spatial(dst));
    }

cleanup:
    src->pointers->next = next;
    src->pointers_end = src->pointers;
    return errcode;
}


static node_pointer *spatial_finish_root(couchfile_modify_request *rq,
                                 couchfile_modify_result *root_result,
                                 couchstore_error_t *errcode)
{
    node_pointer* ret_ptr = nullptr;
    couchfile_modify_result *collector = spatial_make_modres(root_result->arena, rq);
    if (collector == nullptr) {
        *errcode = COUCHSTORE_ERROR_ALLOC_FAIL;
        return nullptr;
    }
    collector->modified = 1;
    collector->node_type = KP_NODE;
    flush_spatial(root_result);
    while (1) {
        if (root_result->pointers_end == root_result->pointers->next) {
            /* The root result split into exactly one kp_node.
             * Return the pointer to it. */
            ret_ptr = root_result->pointers_end->pointer;
            break;
        } else {
            couchfile_modify_result *tmp;
            /* The root result split into more than one kp_node.
             * Move the pointer list to the value list and write out the new
             * node. */
            *errcode = spatial_move_pointers(root_result, collector);

            if (*errcode < 0) {
                return nullptr;
            }

            *errcode = flush_spatial(collector);
            if (*errcode < 0) {
                return nullptr;
            }
            /* Swap root_result and collector mr's. */
            tmp = root_result;
            root_result = collector;
            collector = tmp;
        }
    }

    return ret_ptr;
}


/* Finished creating a new spatial tree, build pointers and get a root node. */
node_pointer* complete_new_spatial(couchfile_modify_result* mr,
                                   couchstore_error_t *errcode)
{
    couchfile_modify_result* targ_mr;
    node_pointer* ret_ptr;

    *errcode = flush_spatial(mr);
    if(*errcode != COUCHSTORE_SUCCESS) {
        return nullptr;
    }

    targ_mr = spatial_make_modres(mr->arena, mr->rq);
    if (targ_mr == nullptr) {
        *errcode = COUCHSTORE_ERROR_ALLOC_FAIL;
        return nullptr;
    }
    targ_mr->modified = 1;
    targ_mr->node_type = KP_NODE;

    *errcode = spatial_move_pointers(mr, targ_mr);
    if(*errcode != COUCHSTORE_SUCCESS) {
        return nullptr;
    }

    if(targ_mr->count > 1 || targ_mr->pointers != targ_mr->pointers_end) {
        ret_ptr = spatial_finish_root(mr->rq, targ_mr, errcode);
    } else {
        ret_ptr = targ_mr->values_end->pointer;
    }

    if (*errcode != COUCHSTORE_SUCCESS || ret_ptr == nullptr) {
        return nullptr;
    }

    ret_ptr = copy_node_pointer(ret_ptr);
    if (ret_ptr == nullptr) {
        *errcode = COUCHSTORE_ERROR_ALLOC_FAIL;
    }
    return ret_ptr;
}
