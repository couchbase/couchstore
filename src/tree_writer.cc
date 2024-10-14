#include "tree_writer.h"
#include "couchstore_config.h" // htonl

#include "arena.h"
#include "internal.h"
#include "log_last_internal_error.h"
#include "merge_sort.h"
#include "stream.h"
#include "util.h"

#include <platform/cb_malloc.h>
#include <filesystem>

namespace cb::couchstore {

struct KeyValueHeader {
    uint32_t key_len{};
    uint32_t value_len{};
};

struct StreamHolder {
    StreamHolder(std::unique_ptr<Stream> stream, std::filesystem::path path)
        : stream(std::move(stream)), path(std::move(path)) {
    }

    ~StreamHolder() {
        try {
            if (stream && !path.empty()) {
                stream.reset();
                std::filesystem::remove(path);
            }
        } catch (const std::exception&) {
            // Don't throw in destructor
        }
    }

    std::unique_ptr<Stream> stream;
    std::filesystem::path path;
};

std::optional<TreeWriter::KeyValue> TreeWriter::read_record(StreamHolder& sh) {
    KeyValueHeader header;
    if (!sh.stream->read({reinterpret_cast<char*>(&header), sizeof(header)})) {
        return {};
    }
    TreeWriter::KeyValue elem;
    elem.key.resize(ntohl(header.key_len));
    elem.value.resize(ntohl(header.value_len));
    if (!(sh.stream->read(elem.key) && sh.stream->read(elem.value))) {
        throw std::runtime_error(
                "Couchstore: EOF while reading TreeWriter::KeyValue");
    }
    return std::move(elem);
}

void TreeWriter::write_record(StreamHolder& sh,
                              std::string_view key,
                              std::string_view value) {
    KeyValueHeader header;
    header.key_len = htonl(key.size());
    header.value_len = htonl(value.size());
    sh.stream->write({reinterpret_cast<char*>(&header), sizeof(header)});
    sh.stream->write(key);
    sh.stream->write(value);
}

void TreeWriter::rewind(StreamHolder& sh) {
    sh.stream->seek_begin();
}

template <typename Fn>
static couchstore_error_t handle_exceptions(const char* caller,
                                            couchstore_error_t io_errcode,
                                            Fn fn) {
    try {
        try {
            fn();
            return COUCHSTORE_SUCCESS;
        } catch (const std::exception& ex) {
            log_last_internal_error("%s() %s", caller, ex.what());
            throw;
        }
    } catch (const cb::crypto::MacVerificationError&) {
        return COUCHSTORE_ERROR_CORRUPT;
    } catch (const cb::crypto::OpenSslError&) {
        return COUCHSTORE_ERROR_ALLOC_FAIL;
    } catch (const cb::crypto::NotSupportedException&) {
        return COUCHSTORE_ERROR_NOT_SUPPORTED;
    } catch (const std::system_error&) {
        return io_errcode;
    } catch (const std::bad_alloc&) {
        return COUCHSTORE_ERROR_ALLOC_FAIL;
    } catch (const std::exception&) {
        return COUCHSTORE_ERROR_INVALID_ARGUMENTS;
    }
}

couchstore_error_t TreeWriter::open(const char* file_path,
                                    bool open_existing,
                                    compare_callback key_compare,
                                    reduce_fn reduce,
                                    reduce_fn rereduce,
                                    void* user_reduce_ctx) {
    if (stream) {
        return COUCHSTORE_ERROR_INVALID_ARGUMENTS;
    }
    auto errcode = handle_exceptions(
            "cb::couchstore::TreeWriter::open",
            COUCHSTORE_ERROR_OPEN_FILE,
            [this, file_path, open_existing]() {
                tmp_path = file_path;
                stream = create_stream(tmp_path, open_existing ? "r+b" : "w+b");
            });
    if (errcode) {
        return errcode;
    }
    if (!stream) {
        return COUCHSTORE_ERROR_NO_SUCH_FILE;
    }
    errcode = handle_exceptions("cb::couchstore::TreeWriter::open",
                                COUCHSTORE_ERROR_READ,
                                [this]() { stream->stream->seek_end(); });
    if (errcode) {
        return errcode;
    }
    this->key_compare = (key_compare ? key_compare : ebin_cmp);
    this->reduce = reduce;
    this->rereduce = rereduce;
    this->user_reduce_ctx = user_reduce_ctx;
    return COUCHSTORE_SUCCESS;
}

void TreeWriter::close() {
    if (stream) {
        stream.reset();
        key_compare = nullptr;
        reduce = nullptr;
        rereduce = nullptr;
        user_reduce_ctx = nullptr;
    }
}

couchstore_error_t TreeWriter::add(sized_buf key, sized_buf value) {
    return handle_exceptions("cb::couchstore::TreeWriter::add",
                             COUCHSTORE_ERROR_WRITE,
                             [this, key, value]() {
                                 write_record(*stream,
                                              {key.buf, key.size},
                                              {value.buf, value.size});
                                 ++num_added;
                             });
}

couchstore_error_t TreeWriter::sort() {
    if (!stream) {
        return COUCHSTORE_ERROR_INVALID_ARGUMENTS;
    }
    return handle_exceptions(
            "cb::couchstore::TreeWriter::sort",
            COUCHSTORE_ERROR_READ,
            [this]() {
                /// max # in memory items in sort run
                constexpr unsigned long block_size = 512 * 1024;
                stream = merge_sort<KeyValue>(
                        block_size,
                        std::move(stream),
                        [this]() { return create_stream("w+b"); },
                        [](auto& sh) { return TreeWriter::read_record(*sh); },
                        [](auto& sh, const auto& elem) {
                            TreeWriter::write_record(*sh, elem.key, elem.value);
                        },
                        [](auto& sh) { TreeWriter::rewind(*sh); },
                        [comp = key_compare](const KeyValue& left,
                                             const KeyValue& right) {
                            sized_buf lb{const_cast<char*>(left.key.data()),
                                         left.key.size()};
                            sized_buf rb{const_cast<char*>(right.key.data()),
                                         right.key.size()};
                            return comp(&lb, &rb) < 0;
                        });
            });
}

couchstore_error_t TreeWriter::write(tree_file* treefile,
                                     node_pointer** out_root) {
    if (!stream) {
        return COUCHSTORE_ERROR_INVALID_ARGUMENTS;
    }

    std::unique_ptr<arena, arena_deleter> transient_arena{new_arena(0)};
    std::unique_ptr<arena, arena_deleter> persistent_arena{new_arena(0)};
    if (!(transient_arena && persistent_arena)) {
        return COUCHSTORE_ERROR_ALLOC_FAIL;
    }

    auto errcode = handle_exceptions("cb::couchstore::TreeWriter::write",
                                     COUCHSTORE_ERROR_READ,
                                     [this]() { rewind(*stream); });
    if (errcode) {
        return errcode;
    }

    compare_info idcmp;
    // Create the structure to write the tree to the db:
    idcmp.compare = key_compare;

    auto* target_mr = new_btree_modres(persistent_arena.get(),
                                       transient_arena.get(),
                                       treefile,
                                       &idcmp,
                                       reduce,
                                       rereduce,
                                       user_reduce_ctx,
                                       treefile->options.kv_nodesize,
                                       treefile->options.kp_nodesize);
    if (target_mr == nullptr) {
        return COUCHSTORE_ERROR_ALLOC_FAIL;
    }

    // Read all the key/value pairs from the file and add them to the tree:
    for (;; ++num_written) {
        std::optional<KeyValue> kv;
        errcode =
                handle_exceptions("cb::couchstore::TreeWriter::write",
                                  COUCHSTORE_ERROR_READ,
                                  [this, &kv]() { kv = read_record(*stream); });
        if (errcode) {
            return errcode;
        }
        if (!kv) {
            break;
        }

        sized_buf k;
        k.size = kv->key.size();
        k.buf = static_cast<char*>(arena_alloc(transient_arena.get(), k.size));
        if (!k.buf) {
            return COUCHSTORE_ERROR_ALLOC_FAIL;
        }
        memcpy(k.buf, kv->key.data(), k.size);
        sized_buf v;
        v.size = kv->value.size();
        v.buf = static_cast<char*>(arena_alloc(transient_arena.get(), v.size));
        if (!v.buf) {
            return COUCHSTORE_ERROR_ALLOC_FAIL;
        }
        memcpy(v.buf, kv->value.data(), v.size);

        mr_push_item(&k, &v, target_mr);
        if (target_mr->count == 0) {
            // No items queued, we must have just flushed.
            // We can safely rewind the transient arena.
            arena_free_all(transient_arena.get());
        }
    }

    // Finish up the tree:
    if (*out_root != nullptr) {
        cb_free(*out_root);
    }
    *out_root = complete_new_btree(target_mr, &errcode);
    return errcode;
}

couchstore_error_t TreeWriter::enable_encryption() {
    return handle_exceptions(
            "cb::couchstore::TreeWriter::enable_encryption",
            COUCHSTORE_ERROR_READ,
            [this]() {
                const auto cipher_name = cb::crypto::Cipher::AES_256_GCM;
                // We use a random key to not interfere with the usage of the
                // file key (Simplifies reasoning about nonce reuse)
                auto key =
                        cb::crypto::SymmetricCipher::generateKey(cipher_name);
                cipher = cb::crypto::SymmetricCipher::create(cipher_name, key);
            });
}

static std::filesystem::path next_tmp_path(const std::filesystem::path& path) {
    auto str = path.string();
    auto pos = str.size();
    // If file name is 4.couch.2.compact.btree-tmp_356
    // pull out suffix as int in reverse i.e. 653
    // increment suffix by 1 to 654
    // append new suffix in reverse as 4.couch.2.compact.btree-tmp_456
    unsigned int suffix = 0;
    while (pos) {
        --pos;
        if (str[pos] < '0' || str[pos] > '9') {
            ++pos;
            break;
        }
        suffix = suffix * 10 + (str[pos] - '0'); // atoi
    }
    ++suffix;
    str.resize(pos);
    // do itoa in reverse
    while (suffix) {
        str.push_back((suffix % 10) + '0');
        suffix /= 10;
    }
    return {std::move(str)};
}

std::unique_ptr<StreamHolder> TreeWriter::create_stream(const char* mode) {
    tmp_path = next_tmp_path(tmp_path);
    return create_stream(tmp_path, mode);
}

std::unique_ptr<StreamHolder> TreeWriter::create_stream(
        std::filesystem::path path, const char* mode) {
    auto stream = make_file_stream(path, mode);
    if (cipher) {
        stream = make_encrypted_stream(std::move(stream), cipher);
    }
    return std::make_unique<StreamHolder>(std::move(stream), std::move(path));
}

TreeWriter::TreeWriter() = default;

TreeWriter::~TreeWriter() = default;

} // namespace cb::couchstore
