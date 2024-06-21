#include "tree_writer.h"

#include "arena.h"
#include "couch_btree.h"
#include "internal.h"
#include "mergesort.h"
#include "util.h"

#include <platform/cb_malloc.h>

struct KeyValueHeader {
    uint32_t key_len{};
    uint32_t value_len{};
};

int TreeWriter::read_record(FILE* in, void* ptr, void* ctx) {
    try {
        auto* writer = reinterpret_cast<TreeWriter*>(ctx);
        auto* rec = reinterpret_cast<KeyValue*>(ptr);
        if (writer->cipher) {
            uint32_t cipher_len;
            if (fread(&cipher_len, sizeof(cipher_len), 1, in) != 1) {
                return feof(in) ? 0 : -1;
            }
            std::string buffer;
            buffer.resize(cipher_len);
            if (fread(buffer.data(), buffer.size(), 1, in) != 1) {
                return -1;
            }
            buffer = writer->cipher->decrypt(buffer);
            uint32_t key_len;
            if (sizeof(key_len) > buffer.size()) {
                return -1;
            }
            memcpy(&key_len, buffer.data(), sizeof(key_len));
            if (key_len > buffer.size()) {
                return -1;
            }
            rec->key = buffer.substr(sizeof(key_len), key_len);
            rec->value = buffer.substr(sizeof(key_len) + key_len);
        } else {
            KeyValueHeader header;
            if (fread(&header, sizeof(header), 1, in) != 1) {
                return feof(in) ? 0 : -1;
            }
            rec->key.resize(header.key_len);
            rec->value.resize(header.value_len);
            if (fread(rec->key.data(), rec->key.size(), 1, in) != 1) {
                return -1;
            }
            if (fread(rec->value.data(), rec->value.size(), 1, in) != 1) {
                return -1;
            }
        }
        return 1;
    } catch (const std::exception&) {
        return -1;
    }
}

couchstore_error_t TreeWriter::add(FILE* out,
                                   std::string_view key,
                                   std::string_view value) {
    try {
        if (cipher) {
            uint32_t key_len = key.size();
            std::string buffer{reinterpret_cast<char*>(&key_len),
                               sizeof(key_len)};
            buffer += key;
            buffer += value;
            buffer = cipher->encrypt(buffer);
            uint32_t cipher_len = buffer.length();
            if (fwrite(&cipher_len, sizeof(cipher_len), 1, out) != 1) {
                return COUCHSTORE_ERROR_WRITE;
            }
            if (fwrite(buffer.data(), buffer.size(), 1, out) != 1) {
                return COUCHSTORE_ERROR_WRITE;
            }
        } else {
            KeyValueHeader header;
            header.key_len = key.size();
            header.value_len = value.size();
            if (fwrite(&header, sizeof(header), 1, out) != 1) {
                return COUCHSTORE_ERROR_WRITE;
            }
            if (fwrite(key.data(), key.size(), 1, out) != 1) {
                return COUCHSTORE_ERROR_WRITE;
            }
            if (fwrite(value.data(), value.size(), 1, out) != 1) {
                return COUCHSTORE_ERROR_WRITE;
            }
        }
        return COUCHSTORE_SUCCESS;
    } catch (const cb::crypto::OpenSslError&) {
        return COUCHSTORE_ERROR_ENCRYPT;
    } catch (const std::bad_alloc&) {
        return COUCHSTORE_ERROR_ALLOC_FAIL;
    } catch (const std::exception&) {
        return COUCHSTORE_ERROR_INVALID_ARGUMENTS;
    }
}

couchstore_error_t TreeWriter::add(sized_buf key, sized_buf value) {
    if (!file) {
        return COUCHSTORE_ERROR_INVALID_ARGUMENTS;
    }
    return add(file, {key.buf, key.size}, {value.buf, value.size});
}

int TreeWriter::write_record(FILE* out, void* ptr, void* ctx) {
    auto* writer = reinterpret_cast<TreeWriter*>(ctx);
    auto* rec = reinterpret_cast<KeyValue*>(ptr);
    if (writer->add(out, rec->key, rec->value) != COUCHSTORE_SUCCESS) {
        return 0;
    }
    return 1;
}

int TreeWriter::compare_records(const void* r1, const void* r2, void* ctx) {
    auto* writer = reinterpret_cast<TreeWriter*>(ctx);
    auto* kv1 = reinterpret_cast<const KeyValue*>(r1);
    auto* kv2 = reinterpret_cast<const KeyValue*>(r2);
    sized_buf buf1{const_cast<char*>(kv1->key.data()), kv1->key.size()};
    sized_buf buf2{const_cast<char*>(kv2->key.data()), kv2->key.size()};
    return writer->key_compare(&buf1, &buf2);
}

static char* alloc_record() {
    return reinterpret_cast<char*>(new (std::nothrow) TreeWriter::KeyValue());
}

static char* duplicate_record(char* rec) {
    return reinterpret_cast<char*>(new (std::nothrow) TreeWriter::KeyValue(
            *reinterpret_cast<TreeWriter::KeyValue*>(rec)));
}

static void free_record(char* rec) {
    delete reinterpret_cast<TreeWriter::KeyValue*>(rec);
}

couchstore_error_t TreeWriter::open(const char* unsorted_file_path,
                                    compare_callback key_compare,
                                    reduce_fn reduce,
                                    reduce_fn rereduce,
                                    void* user_reduce_ctx) {
    if (file) {
        return COUCHSTORE_ERROR_INVALID_ARGUMENTS;
    }
    if (strncpy_safe(path.data(), unsorted_file_path, PATH_MAX)) {
        return COUCHSTORE_ERROR_NO_SUCH_FILE;
    }
    file = openTmpFile(path.data()); // path is modified
    if (!file) {
        return COUCHSTORE_ERROR_NO_SUCH_FILE;
    }
    // copy path to tmp_path - tmp_path will be modified later
    if (strncpy_safe(tmp_path.data(), path.data(), PATH_MAX)) {
        close();
        return COUCHSTORE_ERROR_NO_SUCH_FILE;
    }
    fseek(file, 0, SEEK_END);
    this->key_compare = (key_compare ? key_compare : ebin_cmp);
    this->reduce = reduce;
    this->rereduce = rereduce;
    this->user_reduce_ctx = user_reduce_ctx;
    return COUCHSTORE_SUCCESS;
}

void TreeWriter::close() {
    if (file) {
        fclose(file);
        file = nullptr;
        key_compare = nullptr;
        reduce = nullptr;
        rereduce = nullptr;
        user_reduce_ctx = nullptr;
        remove(path.data());
    }
}

couchstore_error_t TreeWriter::sort() {
    if (!file) {
        return COUCHSTORE_ERROR_INVALID_ARGUMENTS;
    }
    /// max # in memory items in sort run
    constexpr unsigned long block_size = 512 * 1024;
    rewind(file);
    return static_cast<couchstore_error_t>(
            merge_sort(file,
                       file,
                       tmp_path.data(),
                       read_record,
                       write_record,
                       compare_records,
                       alloc_record,
                       duplicate_record,
                       free_record,
                       this /* context parameter to the above callbacks */,
                       block_size,
                       nullptr));
}

couchstore_error_t TreeWriter::write(tree_file* treefile,
                                     node_pointer** out_root) {
    if (!file) {
        return COUCHSTORE_ERROR_INVALID_ARGUMENTS;
    }
    couchstore_error_t errcode = COUCHSTORE_SUCCESS;

    std::unique_ptr<arena, arena_deleter> transient_arena{new_arena(0)};
    std::unique_ptr<arena, arena_deleter> persistent_arena{new_arena(0)};
    if (!(transient_arena && persistent_arena)) {
        return COUCHSTORE_ERROR_ALLOC_FAIL;
    }

    rewind(file);

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
    for (;;) {
        KeyValue kv;
        auto err = read_record(file, &kv, this);
        if (err == 0) {
            break;
        } else if (err != 1) {
            return COUCHSTORE_ERROR_READ;
        }

        sized_buf k;
        k.size = kv.key.size();
        k.buf = static_cast<char*>(arena_alloc(transient_arena.get(), k.size));
        if (!k.buf) {
            return COUCHSTORE_ERROR_ALLOC_FAIL;
        }
        memcpy(k.buf, kv.key.data(), k.size);
        sized_buf v;
        v.size = kv.value.size();
        v.buf = static_cast<char*>(arena_alloc(transient_arena.get(), v.size));
        if (!v.buf) {
            return COUCHSTORE_ERROR_ALLOC_FAIL;
        }
        memcpy(v.buf, kv.value.data(), v.size);

        mr_push_item(&k, &v, target_mr);
        if (target_mr->count == 0) {
            // No items queued, we must have just flushed.
            // We can safely rewind the transient arena.
            arena_free_all(transient_arena.get());
        }
    }

    // Check for file error:
    auto readerr = ferror(file);
    if (readerr != 0 && readerr != EOF) {
        return COUCHSTORE_ERROR_READ;
    }

    // Finish up the tree:
    if (*out_root != nullptr) {
        cb_free(*out_root);
    }
    *out_root = complete_new_btree(target_mr, &errcode);
    return errcode;
}

couchstore_error_t TreeWriter::enable_encryption() {
    const auto cipher_name = cb::crypto::Cipher::AES_256_GCM;
    try {
        // We use a random key to not interfere with the usage of the file key
        // (Simplifies reasoning about nonce reuse)
        auto key = cb::crypto::SymmetricCipher::generateKey(cipher_name);
        cipher = cb::crypto::SymmetricCipher::create(cipher_name, key);
        return COUCHSTORE_SUCCESS;
    } catch (const cb::crypto::OpenSslError&) {
        return COUCHSTORE_ERROR_ENCRYPT;
    } catch (const cb::crypto::NotSupportedException&) {
        return COUCHSTORE_ERROR_NOT_SUPPORTED;
    } catch (const std::bad_alloc&) {
        return COUCHSTORE_ERROR_ALLOC_FAIL;
    } catch (const std::exception&) {
        return COUCHSTORE_ERROR_INVALID_ARGUMENTS;
    }
}

TreeWriter::~TreeWriter() {
    close();
}
