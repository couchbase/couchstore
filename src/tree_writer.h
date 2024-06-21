#pragma once

#include "couch_btree.h"
#include <libcouchstore/couch_db.h>

#include <cbcrypto/symmetric.h>

#include <array>
#include <cstdio>

/**
 * Writes key/value pairs to a tree file after external-merge-sorting them.
 *
 * Operations order:
 *
 * <pre>
 * open()
 * add()
 * add()
 * sort()
 * write()
 * close()
 *
 * open()
 * enable_encryption()
 * add()
 * sort()
 * write()
 * close()
 * </pre>
 */
class TreeWriter {
public:
    struct KeyValue {
        std::string key;
        std::string value;
    };

    /**
     * Opens a file for adding items and sorting.
     *
     * Any previously open file must be closed before calling.
     *
     * @param unsorted_file_path Path to an existing file containing a series of
     *                           unsorted key/value pairs in TreeWriter format.
     * @param key_compare Callback function that compares two keys.
     * @return Error code or COUCHSTORE_SUCCESS.
     */
    couchstore_error_t open(const char* unsorted_file_path,
                            compare_callback key_compare,
                            reduce_fn reduce,
                            reduce_fn rereduce,
                            void* user_reduce_ctx);

    /**
     * Closes the open key/value file, if any.
     */
    void close();

    /**
     * Adds a key/value pair to the file. These can be added in any order.
     */
    couchstore_error_t add(sized_buf key, sized_buf value);

    /**
     * Sorts the key/value pairs already added to the file.
     */
    couchstore_error_t sort();

    /**
     * Writes the key/value pairs to a tree file, returning a pointer to the
     * new root. The items should first have been sorted.
     */
    couchstore_error_t write(tree_file* to_file, node_pointer** out_root);

    /**
     * Enables encryption for the key/value file. A random key is used.
     */
    couchstore_error_t enable_encryption();

    ~TreeWriter();

protected:
    /**
     * Writes a key/value pair to the provided file, optionally encrypted.
     * Used by add(key, value) and the write_record callback.
     */
    couchstore_error_t add(FILE* out,
                           std::string_view key,
                           std::string_view value);

    // Callbacks for the merge-sort subroutine

    /**
     * Callback to read a key/value pair from the provided file.
     *
     * @param in File to read from
     * @param ptr Pointer to KeyValue struct
     * @param ctx Pointer to TreeWriter
     * @return 1 on success
     *         0 on file end
     *         -1 on error
     */
    static int read_record(FILE* in, void* ptr, void* ctx);

    /**
     * Callback to write a key/value pair to the provided file.
     *
     * @param out File to write to
     * @param ptr Pointer to KeyValue struct
     * @param ctx Pointer to TreeWriter
     * @return 1 on success
     *         0 on error
     */
    static int write_record(FILE* out, void* ptr, void* ctx);

    /**
     * Callback to compare two key/value pairs.
     *
     * @param r1 Pointer to first KeyValue struct
     * @param r2 Pointer to second KeyValue struct
     * @param ctx Pointer to TreeWriter
     * @return -1 if r1->key < r2->key
     *         0 if r1->key == r2->key
     *         1 if r1->key > r2->key
     */
    static int compare_records(const void* r1, const void* r2, void* ctx);

    std::unique_ptr<cb::crypto::SymmetricCipher> cipher;
    FILE* file{nullptr};
    compare_callback key_compare{nullptr};
    reduce_fn reduce{nullptr};
    reduce_fn rereduce{nullptr};
    void* user_reduce_ctx{nullptr};
    std::array<char, PATH_MAX> path;
    std::array<char, PATH_MAX> tmp_path;
};
