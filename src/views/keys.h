#pragma once

#include "couchstore_config.h"
#include <libcouchstore/couch_common.h>
#include <libcouchstore/couch_db.h>
#include <libcouchstore/visibility.h>
#include <cstdint>

struct view_btree_key_t {
    sized_buf json_key;
    sized_buf doc_id;
};

struct view_id_btree_key_t {
    uint16_t partition;
    sized_buf doc_id;
};

/// Decode the json_key from bytes/len into the given sized_buf
/// caller must free key.buf
couchstore_error_t decode_view_btree_json_key(const char* bytes,
                                              size_t len,
                                              sized_buf& key);

couchstore_error_t decode_view_btree_key(const char* bytes,
                                         size_t len,
                                         view_btree_key_t** key);

couchstore_error_t encode_view_btree_key(const view_btree_key_t* key,
                                         char** buffer,
                                         size_t* buffer_size);

void free_view_btree_key(view_btree_key_t* key);

couchstore_error_t decode_view_id_btree_key(const char* bytes,
                                            size_t len,
                                            view_id_btree_key_t** key);

couchstore_error_t encode_view_id_btree_key(const view_id_btree_key_t* key,
                                            char** buffer,
                                            size_t* buffer_size);

void free_view_id_btree_key(view_id_btree_key_t* key);
