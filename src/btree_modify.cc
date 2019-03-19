/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#include "config.h"

#include <phosphor/phosphor.h>
#include <platform/cb_malloc.h>
#include <platform/cbassert.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include "arena.h"
#include "couch_btree.h"
#include "node_types.h"
#include "util.h"

static couchstore_error_t flush_mr_partial(couchfile_modify_result *res, size_t mr_quota);
static couchstore_error_t flush_mr(couchfile_modify_result *res);
static couchstore_error_t purge_node(couchfile_modify_request *rq,
                                      node_pointer *nptr,
                                      couchfile_modify_result *dst);

static couchstore_error_t maybe_flush(couchfile_modify_result *mr)
{
    if(mr->rq->compacting) {
        /* The compactor can (and should), just write out nodes
         * of size CHUNK_SIZE as soon as it can, so that it can
         * free memory it no longer needs. Flush at least 2 KP
         * nodes,so that we don't create one parent node for
         * each of the large KP nodes (one node size > threshold).
         */
        if (mr->modified && (((mr->node_type == KV_NODE) &&
            mr->node_len > (mr->rq->kv_chunk_threshold * 2 / 3)) ||
            ((mr->node_type == KP_NODE) &&
             mr->node_len > (mr->rq->kp_chunk_threshold * 2 / 3) &&
             mr->count > 1))) {
            return flush_mr(mr);
        }
    } else if (mr->modified &&  mr->count > 3) {
        /* Don't write out a partial node unless we've collected
         * at least three items */
        if ((mr->node_type == KV_NODE) &&
             mr->node_len > mr->rq->kv_chunk_threshold) {
            return flush_mr_partial(mr, (mr->rq->kv_chunk_threshold * 2 / 3));
        }
        if ((mr->node_type == KP_NODE) &&
             mr->node_len > mr->rq->kp_chunk_threshold) {
            return flush_mr_partial(mr, (mr->rq->kp_chunk_threshold * 2 / 3));
        }
    }

    return COUCHSTORE_SUCCESS;
}


static nodelist *make_nodelist(arena* a, size_t bufsize)
{
    nodelist *r = static_cast<nodelist*>(arena_alloc(a, sizeof(nodelist) + bufsize));
    if (!r) {
        return NULL;
    }
    memset(r, 0, sizeof(nodelist));
    r->data.size = bufsize;
    r->data.buf = ((char *) r) + (sizeof(nodelist));
    return r;
}

couchfile_modify_result *make_modres(arena* a, couchfile_modify_request *rq)
{
    couchfile_modify_result *res;
    res = static_cast<couchfile_modify_result*>(arena_alloc(a, sizeof(couchfile_modify_result)));
    if (!res) {
        return NULL;
    }
    res->arena = a;
    res->arena_transient = NULL;
    res->values = make_nodelist(a, 0);
    if (!res->values) {
        return NULL;
    }
    res->values_end = res->values;
    res->pointers = make_nodelist(a, 0);
    if (!res->pointers) {
        return NULL;
    }
    res->pointers_end = res->pointers;
    res->node_len = 0;
    res->count = 0;
    res->modified = 0;
    res->error_state = 0;
    res->rq = rq;
    return res;
}

couchfile_modify_result *new_btree_modres(arena *a, arena *transient_arena, tree_file *file,
                                          compare_info* cmp, reduce_fn reduce, reduce_fn rereduce,
                                          void *user_reduce_ctx,
                                          int kv_chunk_threshold, int kp_chunk_threshold)
{
    couchfile_modify_request* rq;
    rq = static_cast<couchfile_modify_request*>(arena_alloc(a, sizeof(couchfile_modify_request)));
    rq->cmp = *cmp;
    rq->file = file;
    rq->num_actions = 0;
    rq->fetch_callback = NULL;
    rq->reduce = reduce;
    rq->rereduce = rereduce;
    rq->user_reduce_ctx = user_reduce_ctx;
    rq->compacting = 1;
    rq->enable_purging = 0;
    rq->purge_kp = NULL;
    rq->purge_kv = NULL;
    rq->kv_chunk_threshold = kv_chunk_threshold;
    rq->kp_chunk_threshold = kp_chunk_threshold;

    couchfile_modify_result* mr = make_modres(a, rq);
    if (!mr)
        return NULL;
    mr->arena_transient = transient_arena;
    mr->modified = 1;
    mr->node_type = KV_NODE;

    return mr;
}

couchstore_error_t mr_push_item(sized_buf *k, sized_buf *v, couchfile_modify_result *dst)
{
    nodelist *itm = NULL;
    if(dst->arena_transient != NULL)
    {
        itm = make_nodelist(dst->arena_transient, 0);
    } else {
        itm = make_nodelist(dst->arena, 0);
    }
    if (!itm) {
        return COUCHSTORE_ERROR_ALLOC_FAIL;
    }
    itm->key = *k;
    itm->data = *v;
    itm->pointer = NULL;
    dst->values_end->next = itm;
    dst->values_end = itm;
    //Encoded size (see flush_mr)
    dst->node_len += k->size + v->size + sizeof(raw_kv_length);
    dst->count++;
    return maybe_flush(dst);
}

static nodelist *encode_pointer(arena* a, node_pointer *ptr)
{
    nodelist *pel = make_nodelist(a, sizeof(raw_node_pointer) + ptr->reduce_value.size);
    if (!pel) {
        return NULL;
    }
    raw_node_pointer *raw = (raw_node_pointer*)pel->data.buf;
    encode_raw48(ptr->pointer, &raw->pointer);
    encode_raw48(ptr->subtreesize, &raw->subtreesize);
    raw->reduce_value_size = encode_raw16((uint16_t)ptr->reduce_value.size);
    memcpy(raw + 1, ptr->reduce_value.buf, ptr->reduce_value.size);
    pel->pointer = ptr;
    pel->key = ptr->key;
    return pel;
}

static couchstore_error_t mr_push_pointerinfo(node_pointer *ptr,
                                              couchfile_modify_result *dst)
{
    nodelist *pel = encode_pointer(dst->arena, ptr);
    if (!pel) {
        return COUCHSTORE_ERROR_ALLOC_FAIL;
    }
    dst->values_end->next = pel;
    dst->values_end = pel;
    dst->node_len += pel->key.size + pel->data.size + sizeof(raw_kv_length);
    dst->count++;
    return maybe_flush(dst);
}

node_pointer *read_pointer(arena* a, sized_buf *key, char *buf)
{
    //Parse KP pair into a node_pointer {K, {ptr, reduce_value, subtreesize}}
    node_pointer *p = (node_pointer *) arena_alloc(a, sizeof(node_pointer));
    if (!p) {
        return NULL;
    }
    const raw_node_pointer *raw = (const raw_node_pointer*)buf;
    p->pointer = decode_raw48(raw->pointer);
    p->subtreesize = decode_raw48(raw->subtreesize);
    p->reduce_value.size = decode_raw16(raw->reduce_value_size);
    p->reduce_value.buf = buf + sizeof(*raw);
    p->key = *key;
    return p;
}

//Write the current contents of the values list to disk as a node
//and add the resulting pointer to the pointers list.
static couchstore_error_t flush_mr(couchfile_modify_result *res)
{
    return flush_mr_partial(res, res->node_len);
}

//Write a node using enough items from the values list to create a node
//with uncompressed size of at least mr_quota
static couchstore_error_t flush_mr_partial(couchfile_modify_result *res, size_t mr_quota)
{
    char *dst;
    couchstore_error_t errcode = COUCHSTORE_SUCCESS;
    int itmcount = 0;
    char *nodebuf = NULL;
    sized_buf writebuf;
    char reducebuf[MAX_REDUCTION_SIZE];
    size_t reducesize = 0;
    uint64_t subtreesize = 0;
    cs_off_t diskpos;
    size_t disk_size;
    sized_buf final_key = {NULL, 0};

    if (res->values_end == res->values || ! res->modified) {
        //Empty
        return COUCHSTORE_SUCCESS;
    }

    // nodebuf/writebuf is very short-lived and can be large, so use regular malloc heap for it:
    nodebuf = static_cast<char*>(cb_malloc(res->node_len + 1));
    if (!nodebuf) {
        return COUCHSTORE_ERROR_ALLOC_FAIL;
    }

    writebuf.buf = nodebuf;

    dst = nodebuf;
    *(dst++) = (char) res->node_type;

    nodelist *i = res->values->next;
    final_key = i->key;
    //We don't care that we've reached mr_quota if we haven't written out
    //at least two items and we're not writing a leaf node.
    while (i != NULL && (mr_quota > 0 || (itmcount < 2 && res->node_type == KP_NODE))) {
        dst = static_cast<char*>(write_kv(dst, i->key, i->data));
        if (i->pointer) {
            subtreesize += i->pointer->subtreesize;
        }
        mr_quota -= i->key.size + i->data.size + sizeof(raw_kv_length);
        final_key = i->key;
        i = i->next;
        res->count--;
        itmcount++;
    }

    writebuf.size = dst - nodebuf;

    errcode = static_cast<couchstore_error_t>(db_write_buf_compressed(res->rq->file, &writebuf, &diskpos, &disk_size));
    cb_free(nodebuf);  // here endeth the nodebuf.
    if (errcode != COUCHSTORE_SUCCESS) {
        if (res->rq->file->options.tracing_enabled) {
            TRACE_INSTANT1("couchstore_write",
                           "flush_mr_partial",
                           "errcode",
                           int(errcode));
        }
        return errcode;
    }

    if (res->node_type == KV_NODE && res->rq->reduce) {
        errcode = res->rq->reduce(reducebuf, &reducesize, res->values->next, itmcount, res->rq->user_reduce_ctx);
        if (errcode != COUCHSTORE_SUCCESS) {
            return errcode;
        }
        cb_assert(reducesize <= sizeof(reducebuf));
    }

    if (res->node_type == KP_NODE && res->rq->rereduce) {
        errcode = res->rq->rereduce(reducebuf, &reducesize, res->values->next, itmcount, res->rq->user_reduce_ctx);
        if (errcode != COUCHSTORE_SUCCESS) {
            return errcode;
        }
        cb_assert(reducesize <= sizeof(reducebuf));
    }

    node_pointer *ptr = (node_pointer *) arena_alloc(res->arena, sizeof(node_pointer) + final_key.size + reducesize);
    if (!ptr) {
        return COUCHSTORE_ERROR_ALLOC_FAIL;
    }

    ptr->key.buf = ((char *)ptr) + sizeof(node_pointer);
    ptr->reduce_value.buf = ((char *)ptr) + sizeof(node_pointer) + final_key.size;

    ptr->key.size = final_key.size;
    ptr->reduce_value.size = reducesize;

    memcpy(ptr->key.buf, final_key.buf, final_key.size);
    memcpy(ptr->reduce_value.buf, reducebuf, reducesize);

    ptr->subtreesize = subtreesize + disk_size;
    ptr->pointer = diskpos;

    nodelist *pel = encode_pointer(res->arena, ptr);
    if (!pel) {
        return COUCHSTORE_ERROR_ALLOC_FAIL;
    }

    res->pointers_end->next = pel;
    res->pointers_end = pel;

    res->node_len -= (writebuf.size - 1);

    res->values->next = i;
    if(i == NULL) {
        res->values_end = res->values;
    }

    return COUCHSTORE_SUCCESS;
}

//Move this node's pointers list to dst node's values list.
static couchstore_error_t mr_move_pointers(couchfile_modify_result *src,
                                           couchfile_modify_result *dst)
{
    couchstore_error_t errcode = COUCHSTORE_SUCCESS;
    if (src->pointers_end == src->pointers) {
        return COUCHSTORE_SUCCESS;
    }

    nodelist *ptr = src->pointers->next;
    nodelist *next = ptr;
    while (ptr != NULL && errcode == 0) {
        dst->node_len += ptr->data.size + ptr->key.size + sizeof(raw_kv_length);
        dst->count++;

        next = ptr->next;
        ptr->next = NULL;

        dst->values_end->next = ptr;
        dst->values_end = ptr;
        ptr = next;
        error_pass(maybe_flush(dst));
    }

cleanup:
    src->pointers->next = next;
    src->pointers_end = src->pointers;
    return errcode;
}

// Perform purging for a kv-node if it qualifies for purging
static couchstore_error_t maybe_purgekv(couchfile_modify_request *rq,
                                            sized_buf *key,
                                            sized_buf *val,
                                            couchfile_modify_result *result)
{
    int action;
    couchstore_error_t errcode = COUCHSTORE_SUCCESS;

    if (rq->enable_purging && rq->purge_kv) {
        action = rq->purge_kv(key, val, rq->guided_purge_ctx);
        if (action < 0) {
            return (couchstore_error_t) action;
        }
    } else {
        action = PURGE_KEEP;
    }

    switch (action) {
    case PURGE_ITEM:
        result->modified = 1;
        break;

    case PURGE_STOP:
        rq->enable_purging = 0;

    case PURGE_KEEP:
        errcode = mr_push_item(key, val, result);
        break;
    }

    return errcode;
}

// Perform purging for a kp-node if it qualifies for purging
static couchstore_error_t maybe_purgekp(couchfile_modify_request *rq, node_pointer *node,
                                        couchfile_modify_result *result)
{
    int action;
    couchstore_error_t errcode = COUCHSTORE_SUCCESS;

    if (rq->enable_purging && rq->purge_kp) {
        action = rq->purge_kp(node, rq->guided_purge_ctx);
        if (action < 0) {
            return (couchstore_error_t) action;
        }
    } else {
        action = PURGE_KEEP;
    }

    switch (action) {
    case PURGE_ITEM:
        result->modified = 1;
        break;

    case PURGE_PARTIAL:
        errcode = purge_node(rq, node, result);
        break;

    case PURGE_STOP:
        rq->enable_purging = 0;

    case PURGE_KEEP:
        errcode = mr_push_pointerinfo(node, result);
        break;
    }

    return errcode;
}

static couchstore_error_t modify_node(couchfile_modify_request *rq,
                                      node_pointer *nptr,
                                      int start, int end,
                                      couchfile_modify_result *dst)
{
    char *nodebuf = NULL;  // FYI, nodebuf is a malloced block, not in the arena
    int bufpos = 1;
    int nodebuflen = 0;
    couchstore_error_t errcode = COUCHSTORE_SUCCESS;
    couchfile_modify_result *local_result = NULL;

    if (start == end) {
        return COUCHSTORE_SUCCESS;
    }

    if (nptr) {
        if ((nodebuflen = pread_compressed(rq->file, nptr->pointer, (char **) &nodebuf)) < 0) {
            error_pass(static_cast<couchstore_error_t>(nodebuflen));
        }
    }

    local_result = make_modres(dst->arena, rq);
    error_unless(local_result, COUCHSTORE_ERROR_ALLOC_FAIL);

    if (nptr == NULL || nodebuf[0] == 1) { //KV Node
        local_result->node_type = KV_NODE;
        while (bufpos < nodebuflen) {
            sized_buf cmp_key, val_buf;
            bufpos += read_kv(nodebuf + bufpos, &cmp_key, &val_buf);
            int advance = 0;
            while (!advance && start < end) {
                advance = 1;
                int cmp_val = rq->cmp.compare(&cmp_key, rq->actions[start].key);

                if (cmp_val < 0) { //Key less than action key
                    errcode = maybe_purgekv(rq, &cmp_key, &val_buf, local_result);
                    if (errcode != COUCHSTORE_SUCCESS) {
                        goto cleanup;
                    }
                } else if (cmp_val > 0) { //Key greater than action key
                    switch (rq->actions[start].type) {
                    case ACTION_INSERT:
                        local_result->modified = 1;
                        mr_push_item(rq->actions[start].key, rq->actions[start].value.data, local_result);
                        break;

                    case ACTION_REMOVE:
                        local_result->modified = 1;
                        break;

                    case ACTION_FETCH:
                        if (rq->fetch_callback) {
                            //not found
                            (*rq->fetch_callback)(rq, rq->actions[start].key, NULL, rq->actions[start].value.arg);
                        }
                    }
                    start++;
                    //Do next action on same item in the node, as our action was
                    //not >= it.
                    advance = 0;
                } else if (cmp_val == 0) { //Node key is equal to action key
                    switch (rq->actions[start].type) {
                    case ACTION_INSERT:
                        local_result->modified = 1;
                        mr_push_item(rq->actions[start].key, rq->actions[start].value.data, local_result);
                        break;

                    case ACTION_REMOVE:
                        local_result->modified = 1;
                        break;

                    case ACTION_FETCH:
                        if (rq->fetch_callback) {
                            (*rq->fetch_callback)(rq, rq->actions[start].key, &val_buf, rq->actions[start].value.arg);
                        }
                        //Do next action on same item in the node, as our action was a fetch
                        //and there may be an equivalent insert or remove
                        //following.
                        advance = 0;
                    }
                    start++;
                }
            }
            if (start == end && !advance) {
                //If we've exhausted actions then just keep this key
                errcode = maybe_purgekv(rq, &cmp_key, &val_buf, local_result);
                if (errcode != COUCHSTORE_SUCCESS) {
                    goto cleanup;
                }
            }
        }
        while (start < end) {
            //We're at the end of a leaf node.
            switch (rq->actions[start].type) {
            case ACTION_INSERT:
                local_result->modified = 1;
                mr_push_item(rq->actions[start].key, rq->actions[start].value.data, local_result);
                break;

            case ACTION_REMOVE:
                local_result->modified = 1;
                break;

            case ACTION_FETCH:
                if (rq->fetch_callback) {
                    //not found
                    (*rq->fetch_callback)(rq, rq->actions[start].key, NULL, rq->actions[start].value.arg);
                }
                break;
            }
            start++;
        }
    } else if (nodebuf[0] == 0) { //KP Node
        local_result->node_type = KP_NODE;
        while (bufpos < nodebuflen && start < end) {
            sized_buf cmp_key, val_buf;
            bufpos += read_kv(nodebuf + bufpos, &cmp_key, &val_buf);
            int cmp_val = rq->cmp.compare(&cmp_key, rq->actions[start].key);
            if (bufpos == nodebuflen) {
                //We're at the last item in the kpnode, must apply all our
                //actions here.
                node_pointer *desc = read_pointer(dst->arena, &cmp_key, val_buf.buf);
                if (!desc) {
                    errcode = COUCHSTORE_ERROR_ALLOC_FAIL;
                    goto cleanup;
                }

                errcode = modify_node(rq, desc, start, end, local_result);
                if (errcode != COUCHSTORE_SUCCESS) {
                    goto cleanup;
                }
                break;
            }

            if (cmp_val < 0) {
                //Key in node item less than action item and not at end
                //position, so just add it and continue.
                node_pointer *add = read_pointer(dst->arena, &cmp_key, val_buf.buf);
                if (!add) {
                    errcode = COUCHSTORE_ERROR_ALLOC_FAIL;
                    goto cleanup;
                }

                errcode = maybe_purgekp(rq, add, local_result);
                if (errcode != COUCHSTORE_SUCCESS) {
                    goto cleanup;
                }
            } else if (cmp_val >= 0) {
                //Found a key in the node greater than the one in the current
                //action. Descend into the pointed node with as many actions as
                //are less than the key here.
                int range_end = start;
                while (range_end < end &&
                        rq->cmp.compare(rq->actions[range_end].key, &cmp_key) <= 0) {
                    range_end++;
                }

                node_pointer *desc = read_pointer(dst->arena, &cmp_key, val_buf.buf);
                if (!desc) {
                    errcode = COUCHSTORE_ERROR_ALLOC_FAIL;
                    goto cleanup;
                }

                errcode = modify_node(rq, desc, start, range_end, local_result);
                start = range_end;
                if (errcode != COUCHSTORE_SUCCESS) {
                    goto cleanup;
                }
            }
        }
        while (bufpos < nodebuflen) {
            sized_buf cmp_key, val_buf;
            bufpos += read_kv(nodebuf + bufpos, &cmp_key, &val_buf);
            node_pointer *add = read_pointer(dst->arena, &cmp_key, val_buf.buf);
            if (!add) {
                errcode = COUCHSTORE_ERROR_ALLOC_FAIL;
                goto cleanup;
            }

            errcode = maybe_purgekp(rq, add, local_result);
            if (errcode != COUCHSTORE_SUCCESS) {
                goto cleanup;
            }
        }
    } else {
        errcode = COUCHSTORE_ERROR_CORRUPT;
        goto cleanup;
    }
    //If we've done modifications, write out the last leaf node.
    error_pass(flush_mr(local_result));
    if (!local_result->modified && nptr != NULL) {
        //If we didn't do anything, give back the pointer to the original
        mr_push_pointerinfo(nptr, dst);
    } else {
        //Otherwise, give back the pointers to the nodes we've created.
        dst->modified = 1;
        error_pass(mr_move_pointers(local_result, dst));
    }
cleanup:
    if (nodebuf) {
        cb_free(nodebuf);
    }

    return errcode;
}

node_pointer *finish_root(couchfile_modify_request *rq,
                                 couchfile_modify_result *root_result,
                                 couchstore_error_t *errcode)
{
    node_pointer *ret_ptr = NULL;
    couchfile_modify_result *collector = make_modres(root_result->arena, rq);
    if (!collector) {
        *errcode = COUCHSTORE_ERROR_ALLOC_FAIL;
        return NULL;
    }
    collector->modified = 1;
    collector->node_type = KP_NODE;
    flush_mr(root_result);
    while (1) {
        if (root_result->pointers_end == root_result->pointers->next) {
            //The root result split into exactly one kp_node.
            //Return the pointer to it.
            ret_ptr = root_result->pointers_end->pointer;
            break;
        } else {
            //The root result split into more than one kp_node.
            //Move the pointer list to the value list and write out the new node.
            *errcode = mr_move_pointers(root_result, collector);

            if (*errcode < 0) {
                goto cleanup;
            }

            *errcode = flush_mr(collector);
            if (*errcode < 0) {
                goto cleanup;
            }
            //Swap root_result and collector mr's.
            couchfile_modify_result *tmp = root_result;
            root_result = collector;
            collector = tmp;
        }
    }
cleanup:
    return ret_ptr;
}

// Copies a node_pointer and its values to the malloc heap.
node_pointer* copy_node_pointer(node_pointer* ptr)
{
    if (!ptr) {
        return NULL;
    }
    node_pointer* ret_ptr;
    ret_ptr = static_cast<node_pointer*>(cb_malloc(sizeof(node_pointer) + ptr->key.size + ptr->reduce_value.size));
    if (!ret_ptr) {
        return NULL;
    }
    *ret_ptr = *ptr;
    ret_ptr->key.buf = (char*)ret_ptr + sizeof(node_pointer);
    memcpy(ret_ptr->key.buf, ptr->key.buf, ptr->key.size);
    ret_ptr->reduce_value.buf = (char*)ret_ptr->key.buf + ptr->key.size;
    memcpy(ret_ptr->reduce_value.buf, ptr->reduce_value.buf, ptr->reduce_value.size);
    return ret_ptr;
}

// Finished creating a new b-tree (from compaction), build pointers and get a
// root node.

node_pointer* complete_new_btree(couchfile_modify_result* mr, couchstore_error_t *errcode)
{
    *errcode = flush_mr(mr);
    if(*errcode != COUCHSTORE_SUCCESS) {
        return NULL;
    }

    couchfile_modify_result* targ_mr = make_modres(mr->arena, mr->rq);
    if (!targ_mr) {
        *errcode = COUCHSTORE_ERROR_ALLOC_FAIL;
        return NULL;
    }
    targ_mr->modified = 1;
    targ_mr->node_type = KP_NODE;

    *errcode = mr_move_pointers(mr, targ_mr);
    if(*errcode != COUCHSTORE_SUCCESS) {
        return NULL;
    }

    node_pointer* ret_ptr;
    if(targ_mr->count > 1 || targ_mr->pointers != targ_mr->pointers_end) {
        ret_ptr = finish_root(mr->rq, targ_mr, errcode);
    } else {
        ret_ptr = targ_mr->values_end->pointer;
    }

    if (*errcode != COUCHSTORE_SUCCESS || ret_ptr == NULL) {
        return NULL;
    }

    ret_ptr = copy_node_pointer(ret_ptr);
    if (ret_ptr == NULL) {
        *errcode = COUCHSTORE_ERROR_ALLOC_FAIL;
    }
    return ret_ptr;
}

node_pointer *modify_btree(couchfile_modify_request *rq,
                           node_pointer *root,
                           couchstore_error_t *errcode)
{
    arena* a = new_arena(0);
    node_pointer *ret_ptr = root;
    couchfile_modify_result *root_result = make_modres(a, rq);
    if (!root_result) {
        delete_arena(a);
        *errcode = COUCHSTORE_ERROR_ALLOC_FAIL;
        return root;
    }
    root_result->node_type = KP_NODE;
    *errcode = modify_node(rq, root, 0, rq->num_actions, root_result);
    if (*errcode < 0) {
        delete_arena(a);
        return NULL;
    }

    if (root_result->values_end->pointer == root) {
        //If we got the root pointer back, remove it from the list
        //so we don't try to free it.
        root_result->values_end->pointer = NULL;
    }

    if (root_result->modified) {
        if (root_result->count > 1 || root_result->pointers != root_result->pointers_end) {
            //The root was split
            //Write it to disk and return the pointer to it.
            ret_ptr = finish_root(rq, root_result, errcode);
            if (*errcode < 0) {
                ret_ptr = NULL;
            }
        } else {
            ret_ptr = root_result->values_end->pointer;
        }
    }
    if (ret_ptr != root) {
        ret_ptr = copy_node_pointer(ret_ptr);
    }
    delete_arena(a);
    return ret_ptr;
}

static couchstore_error_t purge_node(couchfile_modify_request *rq,
                                     node_pointer *nptr,
                                     couchfile_modify_result *dst)
{
    char *nodebuf = NULL;  // FYI, nodebuf is a malloced block, not in the arena
    int bufpos = 1;
    int nodebuflen = 0;
    couchstore_error_t errcode = COUCHSTORE_SUCCESS;
    couchfile_modify_result *local_result = NULL;

    if (nptr == NULL) {
        return errcode;
    }

    // noop: add back current node to destination
    if (!rq->enable_purging) {
        dst->modified = 1;
        return mr_push_pointerinfo(nptr, dst);
    }

    if ((nodebuflen = pread_compressed(rq->file, nptr->pointer, (char **) &nodebuf)) < 0) {
        error_pass(static_cast<couchstore_error_t>(nodebuflen));
    }

    local_result = make_modres(dst->arena, rq);
    error_unless(local_result, COUCHSTORE_ERROR_ALLOC_FAIL);

    if (nodebuf[0] == 1) { //KV Node
        local_result->node_type = KV_NODE;
        while (bufpos < nodebuflen) {
            sized_buf cmp_key, val_buf;
            bufpos += read_kv(nodebuf + bufpos, &cmp_key, &val_buf);

            errcode = maybe_purgekv(rq, &cmp_key, &val_buf, local_result);
            if (errcode != COUCHSTORE_SUCCESS) {
                goto cleanup;
            }
        }
    } else if (nodebuf[0] == 0) { //KP Node
        local_result->node_type = KP_NODE;
        while (bufpos < nodebuflen) {
            sized_buf cmp_key, val_buf;
            bufpos += read_kv(nodebuf + bufpos, &cmp_key, &val_buf);

            node_pointer *desc = read_pointer(dst->arena, &cmp_key, val_buf.buf);
            if (!desc) {
                errcode = COUCHSTORE_ERROR_ALLOC_FAIL;
                goto cleanup;
            }

            errcode = maybe_purgekp(rq, desc, local_result);
            if (errcode != COUCHSTORE_SUCCESS) {
                goto cleanup;
            }
        }
    } else {
        errcode = COUCHSTORE_ERROR_CORRUPT;
        goto cleanup;
    }

    // Write out changes and add node back to parent
    if (local_result->modified) {
        error_pass(flush_mr(local_result));
        dst->modified = 1;
        error_pass(mr_move_pointers(local_result, dst));
    }

cleanup:
    cb_free(nodebuf);
    return errcode;
}

node_pointer *guided_purge_btree(couchfile_modify_request *rq, node_pointer *root,
                                                couchstore_error_t *errcode)
{
    rq->enable_purging = 1;
    arena* a = new_arena(0);
    if (!a) {
        *errcode = COUCHSTORE_ERROR_ALLOC_FAIL;
        return NULL;
    }

    node_pointer *ret_ptr = root;
    couchfile_modify_result *root_result = make_modres(a, rq);
    if (!root_result) {
        delete_arena(a);
        *errcode = COUCHSTORE_ERROR_ALLOC_FAIL;
        return NULL;
    }

    root_result->node_type = KP_NODE;
    *errcode = purge_node(rq, root, root_result);
    if (*errcode < 0) {
        delete_arena(a);
        return NULL;
    }

    if (root_result->modified) {
        ret_ptr = root_result->values_end->pointer;
    }

    if (ret_ptr && ret_ptr != root) {
        ret_ptr = copy_node_pointer(ret_ptr);
    }

    delete_arena(a);
    return ret_ptr;
}
