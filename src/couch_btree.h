#ifndef COUCH_BTREE_H
#define COUCH_BTREE_H

#include "arena.h"
#include "internal.h"

// GFlags / Glog: we build it statically, but gflags / glog headers default to
// defining all public symbols as dllimport which results in linker errors - the
// compiler is expecting dll(shared) symbols and not static. Explicitly define
// GFLAGS_DLL_DEFINE_FLAG / GOOGLE_GLOG_DLL_DECL as empty to avoid this.
# define GOOGLE_GLOG_DLL_DECL

#include <folly/PackedSyncPtr.h>

#include <libcouchstore/couch_common.h>

// B+tree KV (leaf) node size limit.
#define DB_KV_CHUNK_THRESHOLD 1279
// B+tree KP (intermediate) node size limit.
#define DB_KP_CHUNK_THRESHOLD 1279
#define MAX_REDUCTION_SIZE ((1 << 16) - 1)

    typedef int (*compare_callback)(const sized_buf *k1, const sized_buf *k2);

    typedef struct compare_info {
        /* Compare function */
        compare_callback compare = nullptr;
    } compare_info;


    /* Lookup */

    struct couchfile_lookup_request {
        compare_info cmp = {};
        tree_file* file = nullptr;
        size_t num_keys = 0;
        /**
         * If nonzero, calls fetch_callback for all keys between and
         * including key 0 and key 1 in the keys array, or all keys after
         * key 0 if it contains only one key.
         * GIVE KEYS SORTED.
         */
        int fold = 0;
        //  v-- Flag used during lookup, do not set.
        int in_fold = 0;
        // If nonzero, continue to traverse tree skipping corrupted node.
        int tolerate_corruption = 0;
        sized_buf** keys = nullptr;
        void* callback_ctx = nullptr;
        couchstore_error_t (*fetch_callback)(
                struct couchfile_lookup_request* rq,
                const sized_buf* k,
                const sized_buf* v) = nullptr;
        couchstore_error_t (*node_callback)(struct couchfile_lookup_request* rq,
                                            uint64_t subtreeSize,
                                            const sized_buf* reduce_value) =
                nullptr;
    } ;

    couchstore_error_t btree_lookup(couchfile_lookup_request *rq,
                                    uint64_t root_pointer);

    /* Modify */
    typedef struct nodelist {
        sized_buf data;
        sized_buf key;
        node_pointer *pointer{nullptr};
        struct nodelist *next{nullptr};
    } nodelist;

    /* Reduce function gets items and places reduce value in dst buffer */
    typedef couchstore_error_t (*reduce_fn)(char *dst,
                                            size_t *size_r,
                                            const nodelist *itmlist,
                                            int count,
                                            void *ctx);

    typedef couchstore_error_t (*make_docinfo_callback)(DocInfo** pInfo,
                                                        const sized_buf* k,
                                                        const sized_buf* v);

#define ACTION_FETCH  0
#define ACTION_REMOVE 1
#define ACTION_INSERT 2
#define ACTION_FETCH_INSERT 3

    typedef struct couchfile_modify_action {
        uint8_t getType() const {
            return gsl::narrow_cast<uint8_t>(packedKeyPtr.extra());
        }
        sized_buf* getKey() const {
            return packedKeyPtr.get();
        }

        void setType(uint8_t t) {
            packedKeyPtr.setExtra(t);
        }

        void setKey(sized_buf* k) {
            packedKeyPtr.set(k);
        }

        // Packed ptr to allow us to reduce the size of couchfile_modify_action
        // by 8 bytes as we pack the type into the overhead of the ptr to the
        // key
        folly::PackedSyncPtr<sized_buf> packedKeyPtr;
        sized_buf* data;

        // Pointer to the user request
        void* userReq = nullptr;
    } couchfile_modify_action;

    /* Guided purge related constants */
#define PURGE_ITEM    0
#define PURGE_STOP    1
#define PURGE_KEEP    2
#define PURGE_PARTIAL 3

    /* Returns purge action or error code */
    typedef int (*purge_kp_fn)(const node_pointer *nptr, void *ctx);
    typedef int (*purge_kv_fn)(const sized_buf *key, const sized_buf *val, void *ctx);

    typedef struct couchfile_modify_request {
        compare_info cmp = {};
        tree_file* file = nullptr;
        size_t num_actions = 0;
        couchfile_modify_action* actions = nullptr;
        couchstore_error_t (*fetch_callback)(
                struct couchfile_modify_request* rq,
                sized_buf* k,
                sized_buf* v,
                void* arg) = nullptr;
        void* fetch_callback_ctx;
        reduce_fn reduce = nullptr;
        reduce_fn rereduce = nullptr;
        void* user_reduce_ctx = nullptr;
        /* For guided btree purge */
        purge_kp_fn purge_kp = nullptr;
        purge_kv_fn purge_kv = nullptr;
        int enable_purging = 0;
        void* guided_purge_ctx = nullptr;
        /*  We're in the compactor */
        int compacting = 0;
        int kv_chunk_threshold = 0;
        int kp_chunk_threshold = 0;
        save_callback_fn save_callback = nullptr;
        void* save_callback_ctx = nullptr;
        make_docinfo_callback docinfo_callback = nullptr;
    } couchfile_modify_request;

#define KP_NODE 0
#define KV_NODE 1

    /* Used to build and chunk modified nodes */
    typedef struct couchfile_modify_result {
        couchfile_modify_request *rq;
        struct arena *arena;
        /* If this is set, prefer to put items that can be thrown away after a flush in this arena */
        struct arena *arena_transient;
        nodelist *values;
        nodelist *values_end;

        long node_len;
        int count;

        nodelist *pointers;
        nodelist *pointers_end;
        /* If we run over a node and never set this, it can be left as-is on disk. */
        int modified;
        /* 1 - leaf, 0 - ptr */
        int node_type;
        int error_state;
    } couchfile_modify_result;

    node_pointer *modify_btree(couchfile_modify_request *rq,
                               node_pointer *root,
                               couchstore_error_t *errcode);

    couchstore_error_t mr_push_item(sized_buf *k, sized_buf *v, couchfile_modify_result *dst);

    couchfile_modify_result* new_btree_modres(arena* a, arena* transient_arena, tree_file *file,
                                              compare_info* cmp, reduce_fn reduce,
                                              reduce_fn rereduce, void *user_reduce_ctx,
                                              int kv_chunk_threshold,
                                              int kp_chunk_threshold);

    node_pointer* complete_new_btree(couchfile_modify_result* mr, couchstore_error_t *errcode);

    node_pointer *guided_purge_btree(couchfile_modify_request *rq,
                                                node_pointer *root,
                                                couchstore_error_t *errcode);

    node_pointer* copy_node_pointer(node_pointer* ptr);

    node_pointer *read_pointer(arena* a, sized_buf *key, char *buf);

    node_pointer *finish_root(couchfile_modify_request *rq,
                              couchfile_modify_result *root_result,
                              couchstore_error_t *errcode);

    couchfile_modify_result *make_modres(arena* a, couchfile_modify_request *rq);

#endif
