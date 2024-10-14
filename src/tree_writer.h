#pragma once

#include "couch_btree.h"
#include <libcouchstore/couch_db.h>

#include <cbcrypto/symmetric.h>

#include <array>
#include <filesystem>

namespace cb::couchstore {

struct StreamHolder;

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
 * enable_encryption()
 * open()
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

    TreeWriter();

    ~TreeWriter();

    /**
     * Opens a file for adding items and sorting.
     *
     * Any previously open file must be closed before calling.
     *
     * @param file_path Path to file which may containing a series of key/value
     *                  pairs in TreeWriter format.
     * @param open_existing Whether to read/ add to an existing file
     * @param key_compare Callback function that compares two keys.
     * @return Error code or COUCHSTORE_SUCCESS.
     */
    couchstore_error_t open(const char* file_path,
                            bool open_existing,
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

    /// Counter for key/value pairs added in add()
    unsigned long long num_added{0};

    /// Counter for key/value pairs written to a new tree in write()
    unsigned long long num_written{0};

protected:
    /**
     * Creates a new stream of a file with a file name generated from the
     * initial file name. When the StreamHolder is destroyed the underlying
     * file is removed.
     *
     * @param mode fopen() mode to open the file in
     */
    std::unique_ptr<StreamHolder> create_stream(const char* mode);

    /**
     * Creates a new stream of the given file. When the StreamHolder is
     * destroyed the underlying file is removed.
     *
     * @param path File path
     * @param mode fopen() mode to open the file in
     */
    std::unique_ptr<StreamHolder> create_stream(std::filesystem::path path,
                                                const char* mode);

    /**
     * Reads a key/value pair from a stream.
     *
     * @return Read KeyValue record or std::nullopt on EOF
     */
    static std::optional<KeyValue> read_record(StreamHolder& sh);

    /**
     * Writes a key/value pair to a stream.
     */
    static void write_record(StreamHolder& sh,
                             std::string_view key,
                             std::string_view value);

    /**
     * Sets the file position to the beginning of the file.
     */
    static void rewind(StreamHolder& sh);

    /// Stream where key/value pairs are stored
    std::unique_ptr<StreamHolder> stream;
    /// Cipher to be used for encrypting Streams
    std::shared_ptr<cb::crypto::SymmetricCipher> cipher;
    /// Callback for comparing keys
    compare_callback key_compare{nullptr};
    reduce_fn reduce{nullptr};
    reduce_fn rereduce{nullptr};
    void* user_reduce_ctx{nullptr};
    /// Buffer for temporary file name generation
    std::filesystem::path tmp_path;
};

} // namespace cb::couchstore
