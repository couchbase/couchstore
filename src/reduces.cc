/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#include "couchstore_config.h"
#include <stdlib.h>
#include <string.h>
#include "reduces.h"
#include "node_types.h"


couchstore_error_t by_seq_reduce(char *dst, size_t *size_r, const nodelist *leaflist, int count, void *ctx)
{
    raw_by_seq_reduce *raw = (raw_by_seq_reduce*)dst;

    (void) leaflist;
    (void) ctx;
    encode_raw40(count, &raw->count);
    *size_r = sizeof(*raw);

    return COUCHSTORE_SUCCESS;
}

couchstore_error_t by_seq_rereduce(char *dst, size_t *size_r, const nodelist *ptrlist, int count, void *ctx)
{
    uint64_t total = 0;
    const nodelist *i = ptrlist;

    (void) ctx;

    while (i != nullptr && count > 0) {
        const raw_by_seq_reduce *reduce = (const raw_by_seq_reduce*) i->pointer->reduce_value.buf;
        total += decode_raw40(reduce->count);
        
        i = i->next;
        count--;
    }
    raw_by_seq_reduce *raw = (raw_by_seq_reduce*)dst;
    encode_raw40(total, &raw->count);
    *size_r = sizeof(*raw);

    return COUCHSTORE_SUCCESS;
}


static size_t encode_by_id_reduce(char *dst, uint64_t notdeleted, uint64_t deleted, uint64_t size)
{
    raw_by_id_reduce *raw = (raw_by_id_reduce*)dst;
    encode_raw40(notdeleted, &raw->notdeleted);
    encode_raw40(deleted, &raw->deleted);
    encode_raw48(size, &raw->size);
    return sizeof(*raw);
}

couchstore_error_t by_id_reduce(char *dst, size_t *size_r, const nodelist *leaflist, int count, void *ctx)
{
    uint64_t notdeleted = 0, deleted = 0, physical_size = 0;
    const nodelist *i = leaflist;

    (void) ctx;

    while (i != nullptr && count > 0) {
        const raw_id_index_value *raw = (const raw_id_index_value*)i->data.buf;
        if (decode_raw48(raw->bp) & BP_DELETED_FLAG) {
            deleted++;
        } else {
            notdeleted++;
        }
        physical_size += decode_raw32(raw->physical_size);

        i = i->next;
        count--;
    }

    *size_r = encode_by_id_reduce(dst, notdeleted, deleted, physical_size);

    return COUCHSTORE_SUCCESS;

}

couchstore_error_t by_id_rereduce(char *dst, size_t *size_r, const nodelist *ptrlist, int count, void *ctx)
{
    uint64_t notdeleted = 0, deleted = 0, size = 0;
    const nodelist *i = ptrlist;

    (void) ctx;

    while (i != nullptr && count > 0) {
        const raw_by_id_reduce *reduce = (const raw_by_id_reduce*) i->pointer->reduce_value.buf;
        notdeleted += decode_raw40(reduce->notdeleted);
        deleted += decode_raw40(reduce->deleted);
        size += decode_raw48(reduce->size);

        i = i->next;
        count--;
    }

    *size_r = encode_by_id_reduce(dst, notdeleted, deleted, size);

    return COUCHSTORE_SUCCESS;
}
