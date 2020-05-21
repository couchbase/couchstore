/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#ifndef _KEYS_H
#define _KEYS_H

#include "couchstore_config.h"
#include <stdint.h>
#include <libcouchstore/visibility.h>
#include <libcouchstore/couch_db.h>
#include <libcouchstore/couch_common.h>

#ifdef __cplusplus
extern "C" {
#endif


typedef struct {
    sized_buf               json_key;
    sized_buf               doc_id;
} view_btree_key_t;

typedef struct {
    uint16_t                partition;
    sized_buf               doc_id;
} view_id_btree_key_t;

/// Decode the json_key from bytes/len into the given sized_buf
/// caller must free key.buf
couchstore_error_t decode_view_btree_json_key(const char* bytes,
                                              size_t len,
                                              sized_buf& key);

couchstore_error_t decode_view_btree_key(const char *bytes,
                                         size_t len,
                                         view_btree_key_t **key);

couchstore_error_t encode_view_btree_key(const view_btree_key_t *key,
                                         char **buffer,
                                         size_t *buffer_size);

void free_view_btree_key(view_btree_key_t *key);

couchstore_error_t decode_view_id_btree_key(const char *bytes,
                                            size_t len,
                                            view_id_btree_key_t **key);

couchstore_error_t encode_view_id_btree_key(const view_id_btree_key_t *key,
                                            char **buffer,
                                            size_t *buffer_size);

void free_view_id_btree_key(view_id_btree_key_t *key);

#ifdef __cplusplus
}
#endif

#endif
