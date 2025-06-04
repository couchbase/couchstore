/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#include "couchstore_config.h"
#include "couch_btree.h"
#include "node_types.h"
#include "util.h"
#include <platform/cb_malloc.h>

/* Helper function to handle lookup specific special cases */
static int lookup_compare(couchfile_lookup_request *rq,
                          const sized_buf *key1,
                          const sized_buf *key2)
{
    /* For handling the case where low key is empty for full btree iteration */
    if (!key1->size && !key2->size) {
        return 0;
    } else if (!key1->size) {
        return -1;
    } else if (!key2->size) {
        return 1;
    }

    return rq->cmp.compare(key1, key2);
}

static couchstore_error_t btree_lookup_inner(couchfile_lookup_request *rq,
                                             uint64_t diskpos,
                                             int current,
                                             int end)
{
    int bufpos = 1, nodebuflen = 0;

    if (current == end) {
        return COUCHSTORE_SUCCESS;
    }
    couchstore_error_t errcode = COUCHSTORE_SUCCESS;

    char* nodebuf = nullptr;

    {
        ScopedFileTag tag(rq->file->ops, rq->file->handle, FileTag::BTree);
        nodebuflen = pread_compressed(rq->file, diskpos, &nodebuf);
    }
    if (nodebuflen <= 0) {
        error_pass(static_cast<couchstore_error_t>(nodebuflen));
        error_unless(nodebuflen > 0, COUCHSTORE_ERROR_CORRUPT);
    }

    if (nodebuf[0] == 0) { //KP Node
        while (bufpos < nodebuflen && current < end) {
            sized_buf cmp_key, val_buf;
            bufpos += read_kv(nodebuf + bufpos, &cmp_key, &val_buf);

            if (lookup_compare(rq, &cmp_key, rq->keys[current]) >= 0) {
                if (rq->fold) {
                    rq->in_fold = 1;
                }

                uint64_t pointer = 0;
                int last_item = current;
                //Descend into the pointed to node.
                //with all keys < item key.
                do {
                    last_item++;
                } while (last_item < end && lookup_compare(rq, &cmp_key, rq->keys[last_item]) >= 0);

                const raw_node_pointer *raw = (const raw_node_pointer*)val_buf.buf;
                if(rq->node_callback) {
                    uint64_t subtreeSize = decode_raw48(raw->subtreesize);
                    sized_buf reduce_value =
                    {val_buf.buf + sizeof(raw_node_pointer), decode_raw16(raw->reduce_value_size)};
                    error_pass(rq->node_callback(rq, subtreeSize, &reduce_value));
                }

                pointer = decode_raw48(raw->pointer);

                couchstore_error_t errcode_local =
                        btree_lookup_inner(rq, pointer, current, last_item);
                if (rq->tolerate_corruption) {
                    error_tolerate(errcode_local);
                } else {
                    error_pass(errcode_local);
                }

                if (!rq->in_fold) {
                    current = last_item;
                }
                if(rq->node_callback) {
                    error_pass(rq->node_callback(rq, 0, nullptr));
                }
            }
        }
    } else if (nodebuf[0] == 1) { //KV Node
        sized_buf cmp_key, val_buf;
        bool next_key = true;

        // Try iterating whilst we have 'input' keys, i.e. keys we're looking up
        while (current < end) {
            // Only try and read the next-key if requested and we're still in
            // the node length
            if (next_key && bufpos < nodebuflen) {
                bufpos += read_kv(nodebuf + bufpos, &cmp_key, &val_buf);
            } else if (next_key) {
                // else if next_key is true and we're out of buf space, break
                break;
            }
            // else continue to evaluate cmp_key against rq->keys[current]

            int cmp_val = lookup_compare(rq, &cmp_key, rq->keys[current]);
            if (cmp_val >= 0 && rq->fold && !rq->in_fold) {
                rq->in_fold = 1;
            }

            // in_fold (>= start), requires a compare against end
            if (rq->in_fold && (current + 1) < end &&
                (lookup_compare(rq, &cmp_key, rq->keys[current + 1])) > 0) {
                //We've hit a key past the end of our range.
                rq->in_fold = 0;
                rq->fold = 0;
                current = end;
                break;
            }

            if (cmp_val >= 0) {
                couchstore_error_t errcode_local;
                if (cmp_val == 0 || rq->in_fold) { // Found
                    errcode_local = rq->fetch_callback(rq, &cmp_key, &val_buf);
                } else {
                    errcode_local =
                            rq->fetch_callback(rq, rq->keys[current], nullptr);
                }

                if (rq->tolerate_corruption) {
                    error_tolerate(errcode_local);
                } else {
                    error_pass(errcode_local);
                }

                if (!rq->in_fold) {
                    ++current;
                    next_key = cmp_val == 0;
                } else {
                    next_key = true;
                }
            } else {
                next_key = true;
            }
        }
    }

    //Any remaining items are not found.
    while (current < end && !rq->fold) {
        error_pass(rq->fetch_callback(rq, rq->keys[current], nullptr));
        current++;
    }

cleanup:
    cb_free(nodebuf);

    return errcode;
}

couchstore_error_t btree_lookup(couchfile_lookup_request *rq,
                                uint64_t root_pointer)
{
    rq->in_fold = 0;
    return btree_lookup_inner(rq, root_pointer, 0, rq->num_keys);
}
