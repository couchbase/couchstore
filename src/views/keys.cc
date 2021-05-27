/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

#include "keys.h"
#include "../bitfield.h"
#include "encoding.h"

#include <platform/cb_malloc.h>
#include <platform/cbassert.h>
#include <cstring>

#define dec_uint16(b) (decode_raw16(*((raw_16 *) b)))

couchstore_error_t decode_view_btree_json_key(const char* bytes,
                                              size_t len,
                                              sized_buf& key) {
    uint16_t sz;
    cb_assert(len >= 2);
    sz = dec_uint16(bytes);

    bytes += 2;
    len -= 2;

    key.size = sz;
    key.buf = (char*)cb_malloc(sz);

    if (key.buf == nullptr) {
        return COUCHSTORE_ERROR_ALLOC_FAIL;
    }

    cb_assert(len >= sz);
    memcpy(key.buf, bytes, sz);
    return COUCHSTORE_SUCCESS;
}

couchstore_error_t decode_view_btree_key(const char *bytes,
                                         size_t len,
                                         view_btree_key_t **key)
{
    view_btree_key_t* k = nullptr;
    uint16_t sz;

    k = (view_btree_key_t *) cb_malloc(sizeof(view_btree_key_t));
    if (k == nullptr) {
        goto alloc_error;
    }

    k->json_key.buf = nullptr;
    k->doc_id.buf = nullptr;

    cb_assert(len >= 2);
    sz = dec_uint16(bytes);

    bytes += 2;
    len -= 2;

    k->json_key.size = sz;
    k->json_key.buf = (char *) cb_malloc(sz);

    if (k->json_key.buf == nullptr) {
        goto alloc_error;
    }

    cb_assert(len >= sz);
    memcpy(k->json_key.buf, bytes, sz);
    bytes += sz;

    len -= sz;

    k->doc_id.size = len;

    k->doc_id.buf = (char *) cb_malloc(len);

    if (k->doc_id.buf == nullptr) {
        goto alloc_error;
    }

    memcpy(k->doc_id.buf, bytes, len);

    *key = k;

    return COUCHSTORE_SUCCESS;

 alloc_error:
    free_view_btree_key(k);
    return COUCHSTORE_ERROR_ALLOC_FAIL;
}


couchstore_error_t encode_view_btree_key(const view_btree_key_t *key,
                                         char **buffer,
                                         size_t *buffer_size)
{
    char *buf = nullptr, *b = nullptr;
    size_t sz = 0;

    sz += 2;             /* size_t */
    sz += key->json_key.size;
    sz += key->doc_id.size;

    b = buf = (char *) cb_malloc(sz);
    if (buf == nullptr) {
        goto alloc_error;
    }

    enc_uint16(key->json_key.size, &b);

    memcpy(b, key->json_key.buf, key->json_key.size);
    b += key->json_key.size;

    memcpy(b, key->doc_id.buf, key->doc_id.size);

    *buffer = buf;
    *buffer_size = sz;

    return COUCHSTORE_SUCCESS;

 alloc_error:
    cb_free(buf);
    *buffer = nullptr;
    *buffer_size = 0;
    return COUCHSTORE_ERROR_ALLOC_FAIL;
}


void free_view_btree_key(view_btree_key_t *key)
{
    if (key == nullptr) {
        return;
    }

    cb_free(key->json_key.buf);
    cb_free(key->doc_id.buf);
    cb_free(key);
}


couchstore_error_t decode_view_id_btree_key(const char *bytes,
                                            size_t len,
                                            view_id_btree_key_t **key)
{
    view_id_btree_key_t* k = nullptr;

    k = (view_id_btree_key_t *) cb_malloc(sizeof(view_id_btree_key_t));
    if (k == nullptr) {
        goto alloc_error;
    }

    k->doc_id.buf = nullptr;

    cb_assert(len >= 2);
    k->partition = dec_uint16(bytes);
    bytes += 2;
    len -= 2;

    k->doc_id.size = len;

    k->doc_id.buf = (char *) cb_malloc(len);

    if (k->doc_id.buf == nullptr) {
        goto alloc_error;
    }

    memcpy(k->doc_id.buf, bytes, len);

    *key = k;

    return COUCHSTORE_SUCCESS;

 alloc_error:
    free_view_id_btree_key(k);
    return COUCHSTORE_ERROR_ALLOC_FAIL;
}


couchstore_error_t encode_view_id_btree_key(const view_id_btree_key_t *key,
                                            char **buffer,
                                            size_t *buffer_size)
{
    char *buf = nullptr, *b = nullptr;
    size_t sz = 0;

    sz += 2;             /* uint16_t */
    sz += key->doc_id.size;

    b = buf = (char *) cb_malloc(sz);
    if (buf == nullptr) {
        goto alloc_error;
    }

    enc_uint16(key->partition, &b);

    memcpy(b, key->doc_id.buf, key->doc_id.size);
    b += key->doc_id.size;

    *buffer = buf;
    *buffer_size = sz;

    return COUCHSTORE_SUCCESS;

 alloc_error:
    cb_free(buf);
    *buffer = nullptr;
    *buffer_size = 0;
    return COUCHSTORE_ERROR_ALLOC_FAIL;
}


void free_view_id_btree_key(view_id_btree_key_t *key)
{
    if (key == nullptr) {
        return;
    }

    cb_free(key->doc_id.buf);
    cb_free(key);
}

