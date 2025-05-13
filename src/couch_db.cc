/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2019 Couchbase, Inc.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

#include "couchstore_config.h"

#include "bitfield.h"
#include "couch_btree.h"
#include "couch_latency_internal.h"
#include "internal.h"
#include "log_last_internal_error.h"
#include "node_types.h"
#include "platform/strerror.h"
#include "reduces.h"
#include "util.h"

#include <platform/cb_malloc.h>
#include <platform/platform_socket.h>
#include <platform/string_hex.h>

#include <fcntl.h>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <fmt/core.h>

#define ROOT_BASE_SIZE 12
#define HEADER_BASE_SIZE 25

thread_local char internal_error_string[MAX_ERR_STR_LEN];

// Initializes one of the db's root node pointers from data in the file header
static couchstore_error_t read_db_root(Db *db, node_pointer **root,
                                       void *root_data, int root_size)
{
    couchstore_error_t errcode = COUCHSTORE_SUCCESS;
    if (root_size > 0) {
        error_unless(root_size >= ROOT_BASE_SIZE, COUCHSTORE_ERROR_CORRUPT);
        *root = read_root(root_data, root_size);
        error_unless(*root, COUCHSTORE_ERROR_ALLOC_FAIL);
        error_unless((*root)->pointer < db->header.position, COUCHSTORE_ERROR_CORRUPT);
    } else {
        *root = nullptr;
    }
cleanup:
    return errcode;
}

static int rawHeader2internalHeader(const raw_file_header_v12* source,
                                    db_header& header,
                                    int& seqrootsize,
                                    int& idrootsize,
                                    int& localrootsize) {
    header.disk_version = decode_raw08(source->version);
    header.update_seq = decode_raw48(source->update_seq);
    header.purge_seq = decode_raw48(source->purge_seq);
    header.purge_ptr = decode_raw48(source->purge_ptr);
    header.timestamp = 0;
    header.prev_header_pos = UNKNOWN_PREV_HEADER_POS;
    header.have_metadata_header = false;
    seqrootsize = decode_raw16(source->seqrootsize);
    idrootsize = decode_raw16(source->idrootsize);
    localrootsize = decode_raw16(source->localrootsize);
    return sizeof(raw_file_header_v12);
}

static int rawHeader2internalHeader(const raw_file_header_v13* source,
                                    db_header& header,
                                    int& seqrootsize,
                                    int& idrootsize,
                                    int& localrootsize) {
    header.disk_version = decode_raw08(source->version);
    header.update_seq = decode_raw48(source->update_seq);
    header.purge_seq = decode_raw48(source->purge_seq);
    header.purge_ptr = decode_raw48(source->purge_ptr);
    header.timestamp = decode_raw64(source->timestamp);
    header.prev_header_pos = UNKNOWN_PREV_HEADER_POS;
    header.have_metadata_header = false;
    seqrootsize = decode_raw16(source->seqrootsize);
    idrootsize = decode_raw16(source->idrootsize);
    localrootsize = decode_raw16(source->localrootsize);
    return sizeof(raw_file_header_v13);
}

static int rawHeader2internalHeader(const raw_file_header_v14* source,
                                    db_header& header,
                                    int& seqrootsize,
                                    int& idrootsize,
                                    int& localrootsize) {
    header.disk_version = decode_raw08(source->version);
    header.update_seq = decode_raw48(source->update_seq);
    header.purge_seq = decode_raw48(source->purge_seq);
    header.purge_ptr = decode_raw48(source->purge_ptr);
    header.timestamp = decode_raw64(source->timestamp);
    header.prev_header_pos = decode_raw48(source->prev_header_pos);
    header.have_metadata_header = header.prev_header_pos & 1;
    header.prev_header_pos >>= 1;
    seqrootsize = decode_raw16(source->seqrootsize);
    idrootsize = decode_raw16(source->idrootsize);
    localrootsize = decode_raw16(source->localrootsize);
    return sizeof(raw_file_header_v14);
}

// Attempts to initialize the database from a header at the given file position
static couchstore_error_t find_header_at_pos(Db *db, cs_off_t pos)
{
    int seqrootsize;
    int idrootsize;
    int localrootsize;
    char *root_data;
    int header_len;
    couchstore_error_t errcode = COUCHSTORE_SUCCESS;
    union {
        raw_file_header_v12* v12_raw;
        raw_file_header_v13* v13_raw;
        raw_file_header_v14* v14_raw;
        char *buf;
    } header_buf = {nullptr};
    int header_size = 0;

    DiskBlockType diskBlockType;
    ssize_t readsize;
    {
        // Speculative read looking for header, mark as Empty.
        ScopedFileTag tag(db->file.ops, db->file.handle, FileTag::Empty);
        readsize = db->file.ops->pread(
                &db->file.lastError, db->file.handle, &diskBlockType, 1, pos);
    }
    if (readsize < 0) {
        error_pass(static_cast<couchstore_error_t>(readsize));
    }
    error_unless(readsize == 1, COUCHSTORE_ERROR_READ);
    if (diskBlockType == DiskBlockType::Data ||
        diskBlockType == DiskBlockType::Meta) {
        return COUCHSTORE_ERROR_NO_HEADER;
    } else if (diskBlockType != DiskBlockType::Header) {
        return COUCHSTORE_ERROR_CORRUPT;
    }

    header_len = pread_header(&db->file, pos, &header_buf.buf, MAX_DB_HEADER_SIZE);
    if (header_len < 0) {
        // MB-38788:
        // Prior to the fix for MB-38788, compaction would leave the first
        // byte of the file (pos:0) with DiskBlockType::Header; which would
        // result in this function incorrectly attempting to try to parse
        // as a header; this results in pread_header() failing with
        // COUCHSTORE_ERROR_CHECKSUM_FAIL.
        // To handle this more gracefully than simply returning CHECKSUM_FAIL
        // when in fact there's no header; treat this case as-if the block
        // was Data all along.
        if (pos == 0) {
            return COUCHSTORE_ERROR_NO_HEADER;
        }
        error_pass(static_cast<couchstore_error_t>(header_len));
    }

    db->header.position = pos;
    db->header.disk_version = decode_raw08(header_buf.v12_raw->version);

    // Only 14, 13, 12 and 11 are valid
    // (Use an explicit version list to make sure people re-evaluate this list
    // when the format change)
    //
    // Version 14 adds position of previous header and support for encryption
    // Version 13 adds a timestamp
    // Version 12 use CRC32C
    // Version 11 use CRC32
    switch (db->header.disk_version) {
    case COUCH_DISK_VERSION_14:
        header_size = rawHeader2internalHeader(header_buf.v14_raw,
                                               db->header,
                                               seqrootsize,
                                               idrootsize,
                                               localrootsize);
        root_data =
                (char*)(header_buf.v14_raw + 1); // i.e. just past *header_buf
        break;
    case COUCH_DISK_VERSION_13:
        header_size = rawHeader2internalHeader(header_buf.v13_raw,
                                               db->header,
                                               seqrootsize,
                                               idrootsize,
                                               localrootsize);
        root_data =
                (char*)(header_buf.v13_raw + 1); // i.e. just past *header_buf
        break;
    case COUCH_DISK_VERSION_12:
    case COUCH_DISK_VERSION_11:
        header_size = rawHeader2internalHeader(header_buf.v12_raw,
                                               db->header,
                                               seqrootsize,
                                               idrootsize,
                                               localrootsize);
        root_data =
                (char*)(header_buf.v12_raw + 1); // i.e. just past *header_buf
        break;
    default:
        error_pass(COUCHSTORE_ERROR_HEADER_VERSION);
    }

    error_unless(db->header.purge_ptr <= db->header.position, COUCHSTORE_ERROR_CORRUPT);
    error_unless(header_len ==
                         header_size + seqrootsize + idrootsize + localrootsize,
                 COUCHSTORE_ERROR_CORRUPT);

    error_pass(read_db_root(db, &db->header.by_seq_root, root_data, seqrootsize));
    root_data += seqrootsize;
    error_pass(read_db_root(db, &db->header.by_id_root, root_data, idrootsize));
    root_data += idrootsize;
    error_pass(read_db_root(db, &db->header.local_docs_root, root_data, localrootsize));

cleanup:
    cb_free(header_buf.buf);
    return errcode;
}

/**
 * Finds the database header by scanning back from the end of the file
 * at 4k boundaries
 */
static couchstore_error_t find_header(Db* db,
                                      int64_t start_pos,
                                      bool skip_corrupt = false) {
    if (start_pos < 0) {
        return COUCHSTORE_ERROR_NO_HEADER;
    }
    couchstore_error_t last_header_errcode = COUCHSTORE_ERROR_NO_HEADER;
    int64_t pos = start_pos;
    pos -= pos % COUCH_BLOCK_SIZE;
    for (; pos >= 0; pos -= COUCH_BLOCK_SIZE) {
        couchstore_error_t errcode = find_header_at_pos(db, pos);
        switch (errcode) {
        case COUCHSTORE_SUCCESS:
            // Found it!
            return COUCHSTORE_SUCCESS;
        case COUCHSTORE_ERROR_NO_HEADER:
            // No header here, so keep going
            break;
        case COUCHSTORE_ERROR_CHECKSUM_FAIL:
        case COUCHSTORE_ERROR_CORRUPT:
        case COUCHSTORE_ERROR_READ: // Possibly corrupt length or truncated file
            if (!skip_corrupt) {
                return errcode;
            }
            // Recovery mode; continue, but remember the last error
            last_header_errcode = errcode;
            break;
        default:
            // Error; stop searching
            return errcode;
        }
    }
    return last_header_errcode;
}

/**
 * Calculates how large in bytes the current header will be
 * when written to disk.
 *
 * The seqrootsize, idrootsize and localrootsize params are
 * used to return the respective sizes in this header if
 * needed.
 */
static size_t calculate_header_size(Db* db,
                                    size_t& seqrootsize,
                                    size_t& idrootsize,
                                    size_t& localrootsize) {
    seqrootsize = idrootsize = localrootsize = 0;

    if (db->header.by_seq_root) {
        seqrootsize = ROOT_BASE_SIZE + db->header.by_seq_root->reduce_value.size;
    }
    if (db->header.by_id_root) {
        idrootsize = ROOT_BASE_SIZE + db->header.by_id_root->reduce_value.size;
    }
    if (db->header.local_docs_root) {
        localrootsize = ROOT_BASE_SIZE + db->header.local_docs_root->reduce_value.size;
    }
    const auto rootsSize = seqrootsize + idrootsize + localrootsize;
    if (db->header.disk_version >= COUCH_DISK_VERSION_14) {
        return sizeof(raw_file_header_v14) + rootsSize;
    } else if (db->header.disk_version == COUCH_DISK_VERSION_13) {
        return sizeof(raw_file_header_v13) + rootsSize;
    } else {
        return sizeof(raw_file_header_v12) + rootsSize;
    }
}

static couchstore_error_t db_write_header_impl(Db* db,
                                               DiskBlockType block_type) {
    sized_buf writebuf;
    size_t seqrootsize, idrootsize, localrootsize;
    writebuf.size = calculate_header_size(db, seqrootsize,
                                          idrootsize, localrootsize);
    writebuf.buf = (char *) cb_malloc(writebuf.size);
    if (!writebuf.buf) {
        return COUCHSTORE_ERROR_ALLOC_FAIL;
    }
    auto* header = reinterpret_cast<raw_file_header_v14*>(writebuf.buf);
    header->version = encode_raw08(db->header.disk_version);
    encode_raw48(db->header.update_seq, &header->update_seq);
    encode_raw48(db->header.purge_seq, &header->purge_seq);
    encode_raw48(db->header.purge_ptr, &header->purge_ptr);
    header->seqrootsize = encode_raw16((uint16_t)seqrootsize);
    header->idrootsize = encode_raw16((uint16_t)idrootsize);
    header->localrootsize = encode_raw16((uint16_t)localrootsize);
    char* root = writebuf.buf;
    if (db->header.disk_version >= COUCH_DISK_VERSION_14) {
        header->timestamp = encode_raw64(db->header.timestamp);
        uint64_t prev_header_pos = db->header.prev_header_pos << 1;
        if (db->header.have_metadata_header) {
            prev_header_pos |= 1;
        }
        encode_raw48(prev_header_pos, &header->prev_header_pos);
        root += sizeof(raw_file_header_v14);
    } else if (db->header.disk_version == COUCH_DISK_VERSION_13) {
        header->timestamp = encode_raw64(db->header.timestamp);
        root += sizeof(raw_file_header_v13);
    } else {
        root += sizeof(raw_file_header_v12);
    }
    encode_root(root, db->header.by_seq_root);
    root += seqrootsize;
    encode_root(root, db->header.by_id_root);
    root += idrootsize;
    encode_root(root, db->header.local_docs_root);
    cs_off_t pos;
    auto errcode = write_header(&db->file, &writebuf, &pos, block_type);
    if (errcode == COUCHSTORE_SUCCESS) {
        db->header.position = pos;
    }
    cb_free(writebuf.buf);
    return errcode;
}

couchstore_error_t db_write_header(Db* db, DiskBlockType block_type) {
    switch (db->header.disk_version) {
    case COUCH_DISK_VERSION_11:
    case COUCH_DISK_VERSION_12:
        // Clear the timestamp internally so that if someone tries
        // to query the timestamp from the instance they get what's
        // stored in the files
        db->header.timestamp = 0;
        // FALL THROUGH
    case COUCH_DISK_VERSION_13:
        db->header.prev_header_pos = UNKNOWN_PREV_HEADER_POS;
        db->header.have_metadata_header = false;
        // FALL THROUGH
    case COUCH_DISK_VERSION_14:
        return db_write_header_impl(db, block_type);
    default:
        return COUCHSTORE_ERROR_HEADER_VERSION;
    }
}

/**
 * Parse a length-prefixed string
 *
 * @param remaining remaining bytes in the buffer
 * @return the parsed string, or nullopt if buffer is too short
 */
static std::optional<std::string> parse_short_string(
        std::string_view& remaining) {
    if (remaining.empty()) {
        return {};
    }
    const size_t len = static_cast<uint8_t>(remaining[0]);
    remaining.remove_prefix(1);
    if (remaining.size() < len) {
        return {};
    }
    auto ret = std::string(remaining.substr(0, len));
    remaining.remove_prefix(len);
    return std::move(ret);
}

struct FileMetadata {
    std::string keyId;
    std::string encryptedFileKey;
};

/**
 * Reads the metadata header (if present) that may contain the master key id
 * and encrypted file key (version 0)
 */
static std::pair<couchstore_error_t, FileMetadata> read_metadata_header(
        tree_file* file) {
    DiskBlockType blockType;
    auto gotBytes =
            file->ops->pread(&file->lastError, file->handle, &blockType, 1, 0);
    if (gotBytes < 0) {
        return {static_cast<couchstore_error_t>(gotBytes), {}};
    } else if (gotBytes != 1) {
        return {COUCHSTORE_ERROR_READ, {}};
    } else if (blockType != DiskBlockType::Meta) {
        return {COUCHSTORE_ERROR_NO_HEADER, {}};
    }

    char* buf = nullptr;
    gotBytes = pread_header(file, 0, &buf, COUCH_BLOCK_SIZE);
    // buf allocated with cb_malloc, calls cb_free when exiting scope
    std::unique_ptr<char, cb_free_deleter> scopedBuf{buf};
    if (gotBytes < 0) {
        return {static_cast<couchstore_error_t>(gotBytes), {}};
    } else if (gotBytes == 0) {
        log_last_internal_error(
                "Couchstore::read_metadata_header() Read empty metadata");
        return {COUCHSTORE_ERROR_NOT_SUPPORTED, {}};
    } else if (buf[0] != 0) {
        log_last_internal_error(
                "Couchstore::read_metadata_header() "
                "Expected version 0 but got %d",
                buf[0]);
        return {COUCHSTORE_ERROR_NOT_SUPPORTED, {}};
    }

    // View of remaining bytes to be parsed
    std::string_view remaining{buf + 1, static_cast<size_t>(gotBytes - 1)};
    FileMetadata metadata;
    // Parse key ID
    auto readString = parse_short_string(remaining);
    if (!readString) {
        return {COUCHSTORE_ERROR_CORRUPT, {}};
    }
    metadata.keyId = std::move(*readString);
    // Parse encrypted file key
    readString = parse_short_string(remaining);
    if (!readString) {
        return {COUCHSTORE_ERROR_CORRUPT, {}};
    }
    metadata.encryptedFileKey = std::move(*readString);
    return {COUCHSTORE_SUCCESS, std::move(metadata)};
}

/**
 * Read the metadata header, and if encryption is enabled, fetch the master key,
 * decrypt the file key, and initialize the file cipher with the file key.
 */
static couchstore_error_t read_and_set_encryption_key(
        Db* db, const cb::couchstore::EncryptionKeyGetter& encryptionKeyCB) {
    if (db->file.cipher) {
        log_last_internal_error(
                "Couchstore::read_and_set_encryption_key() "
                "Cipher already initialized");
        return COUCHSTORE_ERROR_INVALID_ARGUMENTS;
    }
    if (db->header.disk_version < COUCH_DISK_VERSION_14) {
        log_last_internal_error(
                "Couchstore::read_and_set_encryption_key() "
                "Encryption not supported in version:%u",
                static_cast<unsigned>(db->header.disk_version));
        return COUCHSTORE_ERROR_INVALID_ARGUMENTS;
    }
    if (!db->header.have_metadata_header) {
        log_last_internal_error(
                "Couchstore::read_and_set_encryption_key() "
                "File header indicates no metadata");
        return COUCHSTORE_ERROR_INVALID_ARGUMENTS;
    }

    cb::couchstore::SharedEncryptionKey key;
    std::string encryptedFileKey;
    try {
        auto [err, metadata] = read_metadata_header(&db->file);
        if (err) {
            if (err == COUCHSTORE_ERROR_NO_HEADER) {
                log_last_internal_error(
                        "Couchstore::read_and_set_encryption_key() "
                        "Metadata header not found");
                return COUCHSTORE_ERROR_NO_ENCRYPTION_KEY;
            }
            return err;
        }
        if (metadata.keyId.empty()) {
            // Encryption disabled
            return COUCHSTORE_SUCCESS;
        }
        if (!encryptionKeyCB) {
            log_last_internal_error(
                    "Couchstore::read_and_set_encryption_key() "
                    "Encrypted file but no encryption key callback provided");
            return COUCHSTORE_ERROR_NO_ENCRYPTION_KEY;
        }

        key = encryptionKeyCB(metadata.keyId);
        if (!key) {
            log_last_internal_error(
                    "Couchstore::read_and_set_encryption_key() "
                    "Encrypted file but no encryption key returned");
            return COUCHSTORE_ERROR_NO_ENCRYPTION_KEY;
        } else if (key->id != metadata.keyId) {
            log_last_internal_error(
                    "Couchstore::read_and_set_encryption_key() "
                    "Returned encryption key ID mismatch");
            return COUCHSTORE_ERROR_NO_ENCRYPTION_KEY;
        }
        encryptedFileKey = std::move(metadata.encryptedFileKey);
    } catch (const std::bad_alloc&) {
        return COUCHSTORE_ERROR_ALLOC_FAIL;
    } catch (const std::exception& ex) {
        log_last_internal_error("Couchstore::read_and_set_encryption_key() %s",
                                ex.what());
        return COUCHSTORE_ERROR_NO_ENCRYPTION_KEY;
    }

    try {
        auto cipher =
                cb::crypto::SymmetricCipher::create(key->cipher, key->key);
        // The key used for encrypting/decrypting data chunks
        auto fileKey = cipher->decrypt(encryptedFileKey, key->id);
        cipher = cb::crypto::SymmetricCipher::create(key->cipher,
                                                     std::move(fileKey));
        db->file.cipher_keyid = key->id;
        db->file.cipher = std::move(cipher);
        return COUCHSTORE_SUCCESS;
    } catch (const std::bad_alloc&) {
        return COUCHSTORE_ERROR_ALLOC_FAIL;
    } catch (const std::exception& ex) {
        log_last_internal_error("Couchstore::read_and_set_encryption_key() %s",
                                ex.what());
        return COUCHSTORE_ERROR_DECRYPT;
    }
}

/**
 * If encryption is enabled, generate a per file key, and store it encrypted at
 * the beginning of the file, along with the master key id.
 */
static couchstore_error_t create_metadata_header(
        Db* db, const cb::couchstore::EncryptionKeyGetter& encryptionKeyCB) {
    db->header.have_metadata_header = false;
    try {
        if (!encryptionKeyCB) {
            // Encryption disabled
            return COUCHSTORE_SUCCESS;
        }
        auto key = encryptionKeyCB({}); // Empty id to request the active key
        if (!key) {
            // Encryption disabled
            return COUCHSTORE_SUCCESS;
        } else if (key->id.empty() || key->id.size() > UINT8_MAX) {
            return COUCHSTORE_ERROR_INVALID_ARGUMENTS;
        }

        // Encrypts with the master encryption key
        auto cipher =
                cb::crypto::SymmetricCipher::create(key->cipher, key->key);
        // Generate a random file key that will be used for encrypting
        // data chunks
        auto fileKey = cb::crypto::SymmetricCipher::generateKey(key->cipher);
        // We will store the file key encrypted
        auto encryptedFileKey = cipher->encrypt(fileKey, key->id);
        // Initialize a cipher with the file key
        db->file.cipher = cb::crypto::SymmetricCipher::create(
                key->cipher, std::move(fileKey));
        db->file.cipher_keyid = key->id;

        // Serialized metadata
        std::string meta;
        meta.reserve(3 + key->id.size() + encryptedFileKey.size());
        meta += '\0'; // Version
        meta += static_cast<char>(key->id.size());
        meta += key->id;
        meta += static_cast<char>(encryptedFileKey.size());
        meta += encryptedFileKey;

        sized_buf buf{meta.data(), meta.size()};
        cs_off_t pos = 0;
        db->header.have_metadata_header = true;
        return write_header(&db->file, &buf, &pos, DiskBlockType::Meta);
    } catch (const std::bad_alloc&) {
        return COUCHSTORE_ERROR_ALLOC_FAIL;
    } catch (const std::exception& ex) {
        log_last_internal_error("Couchstore::create_metadata_header() %s",
                                ex.what());
        return COUCHSTORE_ERROR_ENCRYPT;
    }
}

static couchstore_error_t create_header(Db* db, couchstore_open_flags flags) {
    // Select the version based upon selected CRC
    if (db->file.crc_mode == CRC32) {
        // user is creating down-level files
        db->header.disk_version = COUCH_DISK_VERSION_11;
    } else {
        // user is using latest
        db->header.disk_version = COUCH_DISK_VERSION_14;
    }
    db->header.update_seq = 0;
    db->header.by_id_root = nullptr;
    db->header.by_seq_root = nullptr;
    db->header.local_docs_root = nullptr;
    db->header.purge_seq = 0;
    db->header.purge_ptr = 0;
    db->header.position = 0;
    db->header.timestamp = 0;
    db->header.prev_header_pos = NO_PREV_HEADER_POS;
    // have_metadata_header was set in create_metadata_header()
    if (flags & COUCHSTORE_OPEN_FLAG_NO_COMMIT_AT_CREATE) {
        return COUCHSTORE_SUCCESS;
    }
    return db_write_header(db);
}

uint64_t couchstore_get_header_position(Db *db)
{
    return db->header.position;
}

couchstore_error_t couchstore_commit(Db* db, const SysErrorCallback& callback) {
    return couchstore_commit_ex(
            db,
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                    std::chrono::system_clock::now().time_since_epoch())
                    .count(),
            callback);
}

static couchstore_error_t write_disk_block_type(tree_file& file,
                                                cs_off_t pos,
                                                DiskBlockType block_type) {
    ssize_t written;
    do {
        written = file.ops->pwrite(
                &file.lastError, file.handle, &block_type, 1, pos);
        if (written == 1) {
            return COUCHSTORE_SUCCESS;
        }
    } while (written == 0);
    return static_cast<couchstore_error_t>(written);
}

couchstore_error_t couchstore_commit_ex(Db* db,
                                        uint64_t timestamp,
                                        const SysErrorCallback& callback) {
    COLLECT_LATENCY();

    auto res = COUCHSTORE_SUCCESS;
    auto restore_header = gsl::finally(
            [&res,
             db,
             header_position = db->header.position,
             header_timestamp = db->header.timestamp,
             header_prev_header_pos = db->header.prev_header_pos]() {
                if (res != COUCHSTORE_SUCCESS) {
                    db->header.position = header_position;
                    db->header.timestamp = header_timestamp;
                    db->header.prev_header_pos = header_prev_header_pos;
                }
            });

    const auto pre_commit_pos = db->file.pos;
    db->header.timestamp = timestamp;
    db->header.prev_header_pos = db->header.position;

    // Write the header with a data block type,
    // so that the header is not found just yet
    res = db_write_header(db, DiskBlockType::Data);
    if (res != COUCHSTORE_SUCCESS) {
        return res;
    }

    // Sync data to disk
    res = db->file.ops->sync(&db->file.lastError, db->file.handle);
    if (res != COUCHSTORE_SUCCESS) {
        return res;
    }

    const auto block_type_pos = align_to_next_block(pre_commit_pos);

    // Note: In general after a fsync failure, another call to fsync does not
    // guarantee to sync the dirty blocks from a previous pwrite. That's why
    // here we need to repeat write+sync when fsync fails.
    for (;;) {
        // Change the block type to header
        res = write_disk_block_type(
                db->file, block_type_pos, DiskBlockType::Header);
        if (res != COUCHSTORE_SUCCESS) {
            break;
        }

        // Sync header to disk
        res = db->file.ops->sync(&db->file.lastError, db->file.handle);
        if (res == COUCHSTORE_SUCCESS) {
            // Success path, all done
            break;
        }

        // Note: We need to maintain the original behaviour (just returning the
        // failure to the caller) for components that don't pass a callback or
        // components that explicitly ask couchstore to return the error code.
        if (!callback ||
            !callback(std::system_error(
                    errno,
                    std::system_category(),
                    "couchstore_commit_ex: Failed to sync header to disk"))) {
            break;
        }
    }

    // BufferedFileOps allocates read and write buffers so that we can
    // reduce syscalls. To allow us to cache Db objects in KV_Engine we need
    // to free these buffers as they can use a substantial amount of memory
    // and may not be useful for the next Db usage.
    db->file.ops->free_buffers(db->file.handle);

    return res;
}

static tree_file_options get_tree_file_options_from_flags(couchstore_open_flags flags)
{
    tree_file_options options;

    if (flags & COUCHSTORE_OPEN_FLAG_UNBUFFERED) {
        options.buf_io_enabled = false;
    } else if (flags & COUCHSTORE_OPEN_WITH_CUSTOM_BUFFER) {
        // Buffered IO with custom buffer settings.
        //  * First 4 bits [15:12]: read buffer capacity
        //  * Next  4 bits [11:08]: max read buffer count

        uint32_t unit_index = (flags >> 12) & 0xf;
        if (unit_index) {
            // unit_index    1     2     3     4     ...   15
            // unit size     1KB   2KB   4KB   8KB   ...   16MB
            options.buf_io_read_unit_size = 1024 * (1 << (unit_index -1));
        }
        uint32_t count_index = (flags >> 8) & 0xf;
        if (count_index) {
            // count_index   1     2     3     4     ...   15
            // # buffers     8     16    32    64    ...   128K
            options.buf_io_read_buffers = 8 * (1 << (count_index-1));
        }
    }

    // Set default value first.
    options.kp_nodesize = DB_KP_CHUNK_THRESHOLD;
    options.kv_nodesize = DB_KV_CHUNK_THRESHOLD;
    if (flags & COUCHSTORE_OPEN_WITH_CUSTOM_NODESIZE) {
        // B+tree custom node size settings.
        //  * First 4 bits [23:20]: KP node size
        //  * Next  4 bits [19:16]: KV node size
        uint32_t kp_flag = (flags >> 20) & 0xf;
        if (kp_flag) {
            options.kp_nodesize = kp_flag * 1024;
        }
        uint32_t kv_flag = (flags >> 16) & 0xf;
        if (kv_flag) {
            options.kv_nodesize = kv_flag * 1024;
        }
    }

    if (flags & COUCHSTORE_OPEN_WITH_PERIODIC_SYNC) {
        // Automatic sync() every N bytes written.
        //  * 5 bits [28-24]: power-of-2 * 1kB
        uint64_t sync_flag = (flags >> 24) & 0x1f;
        options.periodic_sync_bytes = uint64_t(1024) << (sync_flag - 1);
    }

    /* set the tracing and validation options */
    options.tracing_enabled = false;
    options.write_validation_enabled = false;
    options.mprotect_enabled = false;
    if (flags & COUCHSTORE_OPEN_WITH_TRACING) {
        options.tracing_enabled = true;
    }
    if (flags & COUCHSTORE_OPEN_WITH_WRITE_VALIDATION) {
        options.write_validation_enabled = true;
    }
#ifndef WIN32
    if (flags & COUCHSTORE_OPEN_WITH_MPROTECT) {
        options.mprotect_enabled = true;
    }
#endif
    return options;
}

couchstore_open_flags couchstore_encode_periodic_sync_flags(uint64_t bytes) {
    // Convert to encoding supported by couchstore_open_flags - KB power-of-2
    // value.
    // Round up to whole kilobyte units.
    const uint64_t kilobytes = (bytes + 1023) / 1024;
    // Calculate the shift amount (what is the log2 power)
    uint64_t shiftAmount = std::log2(kilobytes);
    // Saturate if the user specified more than the encodable amount.
    shiftAmount = std::min(shiftAmount, uint64_t(30));
    // Finally, encode in couchstore_open flags
    return ((shiftAmount + 1)) << 24;
}

couchstore_error_t couchstore_open_db(const char *filename,
                                      couchstore_open_flags flags,
                                      Db **pDb)
{
    return couchstore_open_db_ex(
            filename, flags, {}, couchstore_get_default_file_ops(), pDb);
}

couchstore_error_t couchstore_open_db_ex(
        const char* filename,
        couchstore_open_flags flags,
        cb::couchstore::EncryptionKeyGetter encryptionKeyCB,
        FileOpsInterface* ops,
        Db** pDb) {
    COLLECT_LATENCY();

    couchstore_error_t errcode = COUCHSTORE_SUCCESS;
    Db *db;
    int openflags;
    cs_off_t pos;

    /* Sanity check input parameters */
    if ((flags & COUCHSTORE_OPEN_FLAG_RDONLY) &&
        (flags & COUCHSTORE_OPEN_FLAG_CREATE)) {
        return COUCHSTORE_ERROR_INVALID_ARGUMENTS;
    }

    if ((db = new (std::nothrow) Db()) == nullptr) {
        return COUCHSTORE_ERROR_ALLOC_FAIL;
    }

    if (flags & COUCHSTORE_OPEN_FLAG_RDONLY) {
        db->readOnly = true;
        openflags = O_RDONLY;
    } else {
        db->readOnly = false;
        openflags = O_RDWR;
    }

    if (flags & COUCHSTORE_OPEN_FLAG_CREATE) {
        openflags |= O_CREAT;
    }

    if (flags & COUCHSTORE_OPEN_FLAG_EXCL) {
        if (!(flags & COUCHSTORE_OPEN_FLAG_CREATE)) {
            errcode = COUCHSTORE_ERROR_INVALID_ARGUMENTS;
            goto cleanup;
        }
        openflags |= O_EXCL;
    }

    // open with CRC unknown, CRC will be selected when header is read/or not found.
    error_pass(tree_file_open(&db->file, filename, openflags, CRC_UNKNOWN, ops,
                              get_tree_file_options_from_flags(flags)));

    pos = db->file.ops->goto_eof(&db->file.lastError, db->file.handle);
    db->file.pos = pos;
    if (pos == 0) {
        // This is an empty file. Create a new file header unless the user
        // wanted a read-only version of the file or to not commit yet.
        // The metadata header is written even if not committing.

        if (flags & COUCHSTORE_OPEN_FLAG_RDONLY) {
            error_pass(COUCHSTORE_ERROR_NO_HEADER);
        } else {
            // Select the CRC to use on this new file
            if (flags & COUCHSTORE_OPEN_WITH_LEGACY_CRC) {
                db->file.crc_mode = CRC32;
            } else {
                db->file.crc_mode = CRC32C;
            }

            error_pass(create_metadata_header(db, encryptionKeyCB));
            error_pass(create_header(db, flags));

            if (db->file.pos == 0) {
                // docinfo.bp == 0 signifies "not found",
                // so ensure data is written at offset 1 onward
                error_pass(write_disk_block_type(
                        db->file, 0, DiskBlockType::Data));
                db->file.pos = 1;
            }
        }
    } else if (pos > 0) {
        error_pass(find_header(
                db, db->file.pos - 2, (flags & COUCHSTORE_OPEN_RECOVERY_MODE)));

        if (db->header.disk_version <= COUCH_DISK_VERSION_11) {
            db->file.crc_mode = CRC32;
        } else {
            db->file.crc_mode = CRC32C;
        }

        // Not allowed. Can't request legacy_crc but be opening non legacy CRC files.
        if (db->file.crc_mode == CRC32C && flags & COUCHSTORE_OPEN_WITH_LEGACY_CRC) {
            errcode = COUCHSTORE_ERROR_INVALID_ARGUMENTS;
            goto cleanup;
        }
    } else {
        error_pass(static_cast<couchstore_error_t>(db->file.pos));
    }

    if (db->header.have_metadata_header && !db->file.cipher) {
        error_pass(read_and_set_encryption_key(db, encryptionKeyCB));
    }

    *pDb = db;
    db->dropped = 0;

cleanup:
    if (errcode != COUCHSTORE_SUCCESS) {
        couchstore_close_file(db);
        couchstore_free_db(db);
    }

    return errcode;
}

couchstore_error_t couchstore_close_file(Db* db)
{
    COLLECT_LATENCY();

    if(db->dropped) {
        return COUCHSTORE_SUCCESS;
    }
    auto error = db->file.close();
    db->dropped = 1;
    return error;
}

/**
 * Rewind to the previous version of the file header
 *
 * couchstore_rewind_db_header closed the file and released the
 * resources as part of cleanup of failures which made it
 * harder to use in a C++ context where you had a unique_ptr to
 * the object (to avoid doing manual cleanup in every error situation).
 * This method returns the real error code, and the caller may let
 * may clean up the object etc
 *
 * @param db the database handle to operate on
 * @return the status of the operation
 */
static couchstore_error_t couchstore_rewind_db_header_impl(Db* db) {
    COLLECT_LATENCY();

    couchstore_error_t errcode;
    error_unless(!db->dropped, COUCHSTORE_ERROR_FILE_CLOSED);
    // free current header guts
    db->header.reset();

    if (db->header.disk_version >= COUCH_DISK_VERSION_14) {
        error_unless(db->header.prev_header_pos != NO_PREV_HEADER_POS,
                     COUCHSTORE_ERROR_DB_NO_LONGER_VALID);
        if (db->header.prev_header_pos != UNKNOWN_PREV_HEADER_POS &&
            db->header.prev_header_pos < db->header.position) {
            errcode = find_header_at_pos(db, db->header.prev_header_pos);
            if (errcode == COUCHSTORE_SUCCESS ||
                errcode == COUCHSTORE_ERROR_ALLOC_FAIL) {
                return errcode;
            }
        }
    }

    error_unless(db->header.position >= COUCH_BLOCK_SIZE,
                 COUCHSTORE_ERROR_DB_NO_LONGER_VALID);
    // find older header
    error_pass(find_header(db, db->header.position - 2));

cleanup:
    return errcode;
}

couchstore_error_t couchstore_rewind_db_header(Db* db) {
    auto errcode = couchstore_rewind_db_header_impl(db);

    // if we failed, free the handle and return an error
    if (errcode != COUCHSTORE_SUCCESS) {
        couchstore_close_file(db);
        couchstore_free_db(db);
        errcode = COUCHSTORE_ERROR_DB_NO_LONGER_VALID;
    }
    return errcode;
}

static couchstore_error_t couchstore_fastforward_db_header_impl(Db* db) {
    COLLECT_LATENCY();

    auto pos = db->header.position + COUCH_BLOCK_SIZE;
    couchstore_error_t errcode = COUCHSTORE_ERROR_NO_HEADER;
    error_unless(!db->dropped, COUCHSTORE_ERROR_FILE_CLOSED);
    // free current header guts
    db->header.reset();

    while (pos < db->file.pos && (errcode = find_header_at_pos(db, pos)) ==
                                         COUCHSTORE_ERROR_NO_HEADER) {
        // No header at that location, try next:
        pos += COUCH_BLOCK_SIZE;
    }

cleanup:
    return errcode;
}

couchstore_error_t couchstore_fastforward_db_header(Db* db) {
    auto errcode = couchstore_fastforward_db_header_impl(db);

    // if we failed, free the handle and return an error
    if (errcode != COUCHSTORE_SUCCESS) {
        couchstore_close_file(db);
        couchstore_free_db(db);
        errcode = COUCHSTORE_ERROR_DB_NO_LONGER_VALID;
    }
    return errcode;
}


couchstore_error_t couchstore_free_db(Db* db)
{
    COLLECT_LATENCY();

    if(!db) {
        return COUCHSTORE_SUCCESS;
    }

    if(!db->dropped) {
        return COUCHSTORE_ERROR_INVALID_ARGUMENTS;
    }

    cb_free(db->header.by_id_root);
    cb_free(db->header.by_seq_root);
    cb_free(db->header.local_docs_root);
    delete db;

    return COUCHSTORE_SUCCESS;
}

const char* couchstore_get_db_filename(Db *db) {
    return db->file.path.c_str();
}

FileOpsInterface::FHStats* couchstore_get_db_filestats(Db* db) {
    return db->file.ops->get_stats(db->file.handle);
}

DocInfo* couchstore_alloc_docinfo(const sized_buf *id, const sized_buf *rev_meta) {
    size_t size = sizeof(DocInfo);
    if (id) {
        size += id->size;
    }
    if (rev_meta) {
        size += rev_meta->size;
    }
    DocInfo* docInfo = static_cast<DocInfo*>(cb_malloc(size));
    if (!docInfo) {
        return nullptr;
    }
    *docInfo = {};
    char *extra = (char *)docInfo + sizeof(DocInfo);
    if (id) {
        memcpy(extra, id->buf, id->size);
        docInfo->id.buf = extra;
        docInfo->id.size = id->size;
        extra += id->size;
    }
    if (rev_meta) {
        memcpy(extra, rev_meta->buf, rev_meta->size);
        docInfo->rev_meta.buf = extra;
        docInfo->rev_meta.size = rev_meta->size;
    }
    return docInfo;
}

void couchstore_free_docinfo(DocInfo *docinfo)
{
    cb_free(docinfo);
}

void couchstore_free_document(Doc *doc)
{
    if (doc) {
        size_t offset = offsetof(fatbuf, buf);
        fatbuf_free((fatbuf *) ((char *)doc - (char *)offset));
    }
}

couchstore_error_t by_seq_read_docinfo(DocInfo **pInfo,
                                       const sized_buf *k,
                                       const sized_buf *v)
{
    const raw_seq_index_value *raw = (const raw_seq_index_value*)v->buf;
    ssize_t extraSize = v->size - sizeof(*raw);
    if (extraSize < 0) {
        return COUCHSTORE_ERROR_CORRUPT;
    }

    uint32_t idsize, datasize;
    decode_kv_length(&raw->sizes, &idsize, &datasize);
    uint64_t bp = decode_raw48(raw->bp);
    int deleted = (bp & BP_DELETED_FLAG) != 0;
    bp &= ~BP_DELETED_FLAG;
    uint8_t content_meta = decode_raw08(raw->content_meta);
    uint64_t rev_seq = decode_raw48(raw->rev_seq);
    uint64_t db_seq = decode_sequence_key(k);

    sized_buf id = {v->buf + sizeof(*raw), idsize};
    sized_buf rev_meta = {id.buf + idsize, extraSize - id.size};
    DocInfo* docInfo = couchstore_alloc_docinfo(&id, &rev_meta);
    if (!docInfo) {
        return COUCHSTORE_ERROR_ALLOC_FAIL;
    }

    docInfo->db_seq = db_seq;
    docInfo->rev_seq = rev_seq;
    docInfo->deleted = deleted;
    docInfo->bp = bp;
    docInfo->physical_size = datasize;
    docInfo->content_meta = content_meta;
    *pInfo = docInfo;
    return COUCHSTORE_SUCCESS;
}

couchstore_error_t by_id_read_docinfo(DocInfo** pInfo,
                                      const sized_buf* k,
                                      const sized_buf* v) {
    const raw_id_index_value *raw = (const raw_id_index_value*)v->buf;
    ssize_t revMetaSize = v->size - sizeof(*raw);
    if (revMetaSize < 0) {
        return COUCHSTORE_ERROR_CORRUPT;
    }

    uint32_t datasize, deleted;
    uint8_t content_meta;
    uint64_t bp, seq, revnum;

    seq = decode_raw48(raw->db_seq);
    datasize = decode_raw32(raw->physical_size);
    bp = decode_raw48(raw->bp);
    deleted = (bp & BP_DELETED_FLAG) != 0;
    bp &= ~BP_DELETED_FLAG;
    content_meta = decode_raw08(raw->content_meta);
    revnum = decode_raw48(raw->rev_seq);

    sized_buf rev_meta = {v->buf + sizeof(*raw), static_cast<size_t>(revMetaSize)};
    DocInfo* docInfo = couchstore_alloc_docinfo(k, &rev_meta);
    if (!docInfo) {
        return COUCHSTORE_ERROR_ALLOC_FAIL;
    }

    docInfo->db_seq = seq;
    docInfo->rev_seq = revnum;
    docInfo->deleted = deleted;
    docInfo->bp = bp;
    docInfo->physical_size = datasize;
    docInfo->content_meta = content_meta;
    *pInfo = docInfo;
    return COUCHSTORE_SUCCESS;
}

couchstore_error_t local_read_docinfo(DocInfo** pInfo,
                                      const sized_buf* k,
                                      const sized_buf* v) {
    DocInfo* docInfo = couchstore_alloc_docinfo(k, nullptr);
    if (!docInfo) {
        return COUCHSTORE_ERROR_ALLOC_FAIL;
    }

    docInfo->physical_size = v->size;
    *pInfo = docInfo;
    return COUCHSTORE_SUCCESS;
}

//Fill in doc from reading file.
static couchstore_error_t bp_to_doc(Doc **pDoc, Db *db, cs_off_t bp, couchstore_open_options options)
{
    couchstore_error_t errcode = COUCHSTORE_SUCCESS;
    int bodylen = 0;
    char* docbody = nullptr;
    fatbuf* docbuf = nullptr;
    error_unless(!db->dropped, COUCHSTORE_ERROR_FILE_CLOSED);

    if (options & DECOMPRESS_DOC_BODIES) {
        bodylen = pread_compressed(&db->file, bp, &docbody);
    } else {
        bodylen = pread_bin(&db->file, bp, &docbody);
    }

    error_unless(bodylen >= 0, static_cast<couchstore_error_t>(bodylen));    // if bodylen is negative it's an error code
    error_unless(docbody || bodylen == 0, COUCHSTORE_ERROR_READ);

    error_unless(docbuf = fatbuf_alloc(sizeof(Doc) + bodylen), COUCHSTORE_ERROR_ALLOC_FAIL);
    *pDoc = (Doc *) fatbuf_get(docbuf, sizeof(Doc));

    if (bodylen == 0) { //Empty doc
        (*pDoc)->data.buf = nullptr;
        (*pDoc)->data.size = 0;
        cb_free(docbody);
        return COUCHSTORE_SUCCESS;
    }

    (*pDoc)->data.buf = (char *) fatbuf_get(docbuf, bodylen);
    (*pDoc)->data.size = bodylen;
    memcpy((*pDoc)->data.buf, docbody, bodylen);

cleanup:
    cb_free(docbody);
    if (errcode < 0) {
        fatbuf_free(docbuf);
    }
    return errcode;
}

static couchstore_error_t docinfo_fetch_by_id(couchfile_lookup_request *rq,
                                              const sized_buf *k,
                                              const sized_buf *v)
{
    DocInfo **pInfo = (DocInfo **) rq->callback_ctx;
    if (v == nullptr) {
        return COUCHSTORE_ERROR_DOC_NOT_FOUND;
    }
    return by_id_read_docinfo(pInfo, k, v);
}

static couchstore_error_t docinfo_fetch_by_seq(couchfile_lookup_request *rq,
                                               const sized_buf *k,
                                               const sized_buf *v)
{
    DocInfo **pInfo = (DocInfo **) rq->callback_ctx;
    if (v == nullptr) {
        return COUCHSTORE_ERROR_DOC_NOT_FOUND;
    }
    return by_seq_read_docinfo(pInfo, k, v);
}

couchstore_error_t couchstore_docinfo_by_id(Db *db,
                                            const void *id,
                                            size_t idlen,
                                            DocInfo **pInfo)
{
    COLLECT_LATENCY();

    sized_buf key;
    sized_buf *keylist = &key;
    couchfile_lookup_request rq;
    couchstore_error_t errcode;
    error_unless(!db->dropped, COUCHSTORE_ERROR_FILE_CLOSED);

    if (db->header.by_id_root == nullptr) {
        return COUCHSTORE_ERROR_DOC_NOT_FOUND;
    }

    key.buf = (char *) id;
    key.size = idlen;

    rq.cmp.compare = ebin_cmp;
    rq.file = &db->file;
    rq.num_keys = 1;
    rq.keys = &keylist;
    rq.callback_ctx = pInfo;
    rq.fetch_callback = docinfo_fetch_by_id;
    rq.node_callback = nullptr;
    rq.fold = 0;

    errcode = btree_lookup(&rq, db->header.by_id_root->pointer);
    if (errcode == COUCHSTORE_SUCCESS) {
        if (*pInfo == nullptr) {
            errcode = COUCHSTORE_ERROR_DOC_NOT_FOUND;
        }
    }
cleanup:
    return errcode;
}

couchstore_error_t couchstore_docinfo_by_sequence(Db *db,
                                                  uint64_t sequence,
                                                  DocInfo **pInfo)
{
    COLLECT_LATENCY();

    sized_buf key;
    sized_buf *keylist = &key;
    couchfile_lookup_request rq;
    couchstore_error_t errcode;
    error_unless(!db->dropped, COUCHSTORE_ERROR_FILE_CLOSED);

    if (db->header.by_id_root == nullptr) {
        return COUCHSTORE_ERROR_DOC_NOT_FOUND;
    }

    sequence = htonll(sequence);
    key.buf = (char *)&sequence + 2;
    key.size = 6;

    rq.cmp.compare = seq_cmp;
    rq.file = &db->file;
    rq.num_keys = 1;
    rq.keys = &keylist;
    rq.callback_ctx = pInfo;
    rq.fetch_callback = docinfo_fetch_by_seq;
    rq.node_callback = nullptr;
    rq.fold = 0;

    errcode = btree_lookup(&rq, db->header.by_seq_root->pointer);
    if (errcode == COUCHSTORE_SUCCESS) {
        if (*pInfo == nullptr) {
            errcode = COUCHSTORE_ERROR_DOC_NOT_FOUND;
        }
    }
cleanup:
    return errcode;
}

couchstore_error_t couchstore_open_doc_with_docinfo(Db *db,
                                                    const DocInfo *docinfo,
                                                    Doc **pDoc,
                                                    couchstore_open_options options)
{
    COLLECT_LATENCY();

    couchstore_error_t errcode;

    *pDoc = nullptr;
    if (docinfo->bp == 0) {
        return COUCHSTORE_ERROR_DOC_NOT_FOUND;
    }

    if (!(docinfo->content_meta & COUCH_DOC_IS_COMPRESSED)) {
        options &= ~DECOMPRESS_DOC_BODIES;
    }

    errcode = bp_to_doc(pDoc, db, docinfo->bp, options);
    if (errcode == COUCHSTORE_SUCCESS) {
        (*pDoc)->id.buf = docinfo->id.buf;
        (*pDoc)->id.size = docinfo->id.size;
    }

    return errcode;
}

couchstore_error_t couchstore_open_document(Db *db,
                                            const void *id,
                                            size_t idlen,
                                            Doc **pDoc,
                                            couchstore_open_options options)
{
    COLLECT_LATENCY();

    couchstore_error_t errcode;
    DocInfo *info;
    error_unless(!db->dropped, COUCHSTORE_ERROR_FILE_CLOSED);
    *pDoc = nullptr;
    errcode = couchstore_docinfo_by_id(db, id, idlen, &info);
    if (errcode == COUCHSTORE_SUCCESS) {
        errcode = couchstore_open_doc_with_docinfo(db, info, pDoc, options);
        if (errcode == COUCHSTORE_SUCCESS) {
            (*pDoc)->id.buf = (char *) id;
            (*pDoc)->id.size = idlen;
        }

        couchstore_free_docinfo(info);
    }
cleanup:
    return errcode;
}

// context info passed to lookup_callback via btree_lookup
typedef struct {
    enum class Tree { ById, BySeqno, Local};
    Db *db;
    couchstore_docinfos_options options;
    couchstore_changes_callback_fn callback;
    void* callback_context;
    Tree tree;
    int depth;
    couchstore_walk_tree_callback_fn walk_callback;
} lookup_context;

// btree_lookup callback, called while iterating keys
static couchstore_error_t lookup_callback(couchfile_lookup_request *rq,
                                          const sized_buf *k,
                                          const sized_buf *v)
{
    if (v == nullptr) {
        return COUCHSTORE_SUCCESS;
    }

    const lookup_context *context = static_cast<const lookup_context *>(rq->callback_ctx);
    DocInfo* docinfo = nullptr;
    couchstore_error_t errcode = COUCHSTORE_SUCCESS;
    switch (context->tree) {
    case lookup_context::Tree::ById:
        errcode = by_id_read_docinfo(&docinfo, k, v);
        break;
    case lookup_context::Tree::BySeqno:
        errcode = by_seq_read_docinfo(&docinfo, k, v);
        break;
    case lookup_context::Tree::Local:
        errcode = local_read_docinfo(&docinfo, k, v);
        break;
    }
    if (errcode == COUCHSTORE_ERROR_CORRUPT &&
        (context->options & COUCHSTORE_TOLERATE_CORRUPTION)) {
        // Invoke callback even if doc info is corrupted/unreadable, if magic flag is set
        docinfo = static_cast<DocInfo*>(cb_calloc(sizeof(DocInfo), 1));
        if (!docinfo) {
            return COUCHSTORE_ERROR_ALLOC_FAIL;
        }
        docinfo->id = *k;
        docinfo->rev_meta = *v;
    } else if (errcode) {
        return errcode;
    }

    if ((context->options & COUCHSTORE_DELETES_ONLY) && docinfo->deleted == 0) {
        couchstore_free_docinfo(docinfo);
        return COUCHSTORE_SUCCESS;
    }

    if ((context->options & COUCHSTORE_NO_DELETES) && docinfo->deleted == 1) {
        couchstore_free_docinfo(docinfo);
        return COUCHSTORE_SUCCESS;
    }

    if (context->walk_callback) {
        errcode = static_cast<couchstore_error_t>(
                context->walk_callback(context->db,
                                       context->depth,
                                       docinfo,
                                       0,
                                       nullptr,
                                       context->callback_context));
    } else {
        errcode = static_cast<couchstore_error_t>(context->callback(context->db,
                                                                    docinfo,
                                                                    context->callback_context));
    }
    if (errcode <= 0) {
        couchstore_free_docinfo(docinfo);
    } else {
        // User requested docinfo not be freed, don't free it, return success
        return COUCHSTORE_SUCCESS;
    }
    return errcode;
}

couchstore_error_t couchstore_changes_since(Db *db,
                                            uint64_t since,
                                            couchstore_docinfos_options options,
                                            couchstore_changes_callback_fn callback,
                                            void *ctx)
{
    COLLECT_LATENCY();

    char since_termbuf[6];
    sized_buf since_term;
    sized_buf *keylist = &since_term;
    lookup_context cbctx = {db,
                            options,
                            callback,
                            ctx,
                            lookup_context::Tree::BySeqno,
                            0,
                            nullptr};
    couchfile_lookup_request rq;
    couchstore_error_t errcode;

    error_unless(!db->dropped, COUCHSTORE_ERROR_FILE_CLOSED);
    if (db->header.by_seq_root == nullptr) {
        return COUCHSTORE_SUCCESS;
    }

    since_term.buf = since_termbuf;
    since_term.size = 6;
    encode_raw48(since, (raw_48*)since_term.buf);

    rq.cmp.compare = seq_cmp;
    rq.file = &db->file;
    rq.num_keys = 1;
    rq.keys = &keylist;
    rq.callback_ctx = &cbctx;
    rq.fetch_callback = lookup_callback;
    rq.node_callback = nullptr;
    rq.fold = 1;
    rq.tolerate_corruption = (options & COUCHSTORE_TOLERATE_CORRUPTION) != 0;

    errcode = btree_lookup(&rq, db->header.by_seq_root->pointer);
cleanup:
    return errcode;
}

couchstore_error_t couchstore_all_docs(Db *db,
                                       const sized_buf* startKeyPtr,
                                       couchstore_docinfos_options options,
                                       couchstore_changes_callback_fn callback,
                                       void *ctx)
{
    COLLECT_LATENCY();

    sized_buf startKey = {nullptr, 0};
    sized_buf *keylist = &startKey;
    lookup_context cbctx = {
            db, options, callback, ctx, lookup_context::Tree::ById, 0, nullptr};
    couchfile_lookup_request rq;
    couchstore_error_t errcode;

    error_unless(!db->dropped, COUCHSTORE_ERROR_FILE_CLOSED);
    if (db->header.by_id_root == nullptr) {
        return COUCHSTORE_SUCCESS;
    }

    if (startKeyPtr) {
        startKey = *startKeyPtr;
    }

    rq.cmp.compare = ebin_cmp;
    rq.file = &db->file;
    rq.num_keys = 1;
    rq.keys = &keylist;
    rq.callback_ctx = &cbctx;
    rq.fetch_callback = lookup_callback;
    rq.node_callback = nullptr;
    rq.fold = 1;
    rq.tolerate_corruption = (options & COUCHSTORE_TOLERATE_CORRUPTION) != 0;

    errcode = btree_lookup(&rq, db->header.by_id_root->pointer);
cleanup:
    return errcode;
}

static couchstore_error_t walk_node_callback(struct couchfile_lookup_request *rq,
                                                 uint64_t subtreeSize,
                                                 const sized_buf *reduceValue)
{
    lookup_context* context = static_cast<lookup_context*>(rq->callback_ctx);
    if (reduceValue) {
        int result = context->walk_callback(context->db,
                                            context->depth,
                                            nullptr,
                                            subtreeSize,
                                            reduceValue,
                                            context->callback_context);
        context->depth++;
        if (result < 0)
            return static_cast<couchstore_error_t>(result);
    } else {
        context->depth--;
    }
    return COUCHSTORE_SUCCESS;
}

static
couchstore_error_t couchstore_walk_tree(Db *db,
                                        lookup_context::Tree tree,
                                        const node_pointer* root,
                                        const sized_buf* startKeyPtr,
                                        couchstore_docinfos_options options,
                                        int (*compare)(const sized_buf *k1, const sized_buf *k2),
                                        couchstore_walk_tree_callback_fn callback,
                                        void *ctx)
{
    couchstore_error_t errcode;
    sized_buf startKey = {nullptr, 0};
    sized_buf *keylist;
    couchfile_lookup_request rq;

    error_unless(!db->dropped, COUCHSTORE_ERROR_FILE_CLOSED);
    if (root == nullptr) {
        return COUCHSTORE_SUCCESS;
    }

    // Invoke the callback on the root node:
    errcode = static_cast<couchstore_error_t>(callback(
            db, 0, nullptr, root->subtreesize, &root->reduce_value, ctx));
    if (errcode < 0) {
        return errcode;
    }

    if (startKeyPtr) {
        startKey = *startKeyPtr;
    }
    keylist = &startKey;

    {
        // Create a new scope here just to mute the warning from the
        // compiler that the goto in the macro error_unless
        // skips the initialization of lookup_ctx..
        lookup_context lookup_ctx = {
                db, options, nullptr, ctx, tree, 1, callback};

        rq.cmp.compare = compare;
        rq.file = &db->file;
        rq.num_keys = 1;
        rq.keys = &keylist;
        rq.callback_ctx = &lookup_ctx;
        rq.fetch_callback = lookup_callback;
        rq.node_callback = walk_node_callback;
        rq.fold = 1;
        rq.tolerate_corruption = (options & COUCHSTORE_TOLERATE_CORRUPTION) != 0;

        error_pass(btree_lookup(&rq, root->pointer));
    }
cleanup:
    return errcode;
}

couchstore_error_t couchstore_walk_id_tree(Db *db,
                                           const sized_buf* startDocID,
                                           couchstore_docinfos_options options,
                                           couchstore_walk_tree_callback_fn callback,
                                           void *ctx)
{
    COLLECT_LATENCY();

    return couchstore_walk_tree(db, lookup_context::Tree::ById, db->header.by_id_root, startDocID,
                                options, ebin_cmp, callback, ctx);
}

couchstore_error_t couchstore_walk_seq_tree(Db *db,
                                           uint64_t startSequence,
                                           couchstore_docinfos_options options,
                                           couchstore_walk_tree_callback_fn callback,
                                           void *ctx)
{
    COLLECT_LATENCY();

    raw_48 start_termbuf;
    encode_raw48(startSequence, &start_termbuf);
    sized_buf start_term = {(char*)&start_termbuf, 6};

    return couchstore_walk_tree(db, lookup_context::Tree::BySeqno, db->header.by_seq_root, &start_term,
                                options, seq_cmp, callback, ctx);
}

couchstore_error_t couchstore_walk_local_tree(
        Db* db,
        const sized_buf* startLocalID,
        couchstore_walk_tree_callback_fn callback,
        void* ctx) {
    COLLECT_LATENCY();

    return couchstore_walk_tree(db,
                                lookup_context::Tree::Local,
                                db->header.local_docs_root,
                                startLocalID,
                                {},
                                ebin_cmp,
                                callback,
                                ctx);
}

static int id_ptr_cmp(const void *a, const void *b)
{
    sized_buf **buf1 = (sized_buf**) a;
    sized_buf **buf2 = (sized_buf**) b;
    return ebin_cmp(*buf1, *buf2);
}

static int seq_ptr_cmp(const void *a, const void *b)
{
    sized_buf **buf1 = (sized_buf**) a;
    sized_buf **buf2 = (sized_buf**) b;
    return seq_cmp(*buf1, *buf2);
}

// Common subroutine of couchstore_docinfos_by_{ids, sequence}
static couchstore_error_t iterate_docinfos(Db *db,
                                           const sized_buf keys[],
                                           unsigned numDocs,
                                           node_pointer *tree,
                                           int (*key_ptr_compare)(const void *, const void *),
                                           int (*key_compare)(const sized_buf *k1, const sized_buf *k2),
                                           couchstore_changes_callback_fn callback,
                                           int fold,
                                           int tolerate_corruption,
                                           void *ctx)
{
    couchstore_error_t errcode = COUCHSTORE_SUCCESS;
    const sized_buf** keyptrs = nullptr;
    error_unless(!db->dropped, COUCHSTORE_ERROR_FILE_CLOSED);
    // Nothing to do if the tree is empty
    if (tree == nullptr) {
        return COUCHSTORE_SUCCESS;
    }

    if(numDocs <= 0) {
        return COUCHSTORE_ERROR_INVALID_ARGUMENTS;
    }

    // Create an array of *pointers to* sized_bufs, which is what btree_lookup wants:
    keyptrs = static_cast<const sized_buf**>(cb_malloc(numDocs * sizeof(sized_buf*)));
    error_unless(keyptrs, COUCHSTORE_ERROR_ALLOC_FAIL);

    {
        unsigned i;
        for (i = 0; i< numDocs; ++i) {
            keyptrs[i] = &keys[i];
        }
        if (!fold) {
            // Sort the key pointers:
            qsort(keyptrs, numDocs, sizeof(keyptrs[0]), key_ptr_compare);
        }

        // Construct the lookup request:
        const auto treeType = (tree == db->header.by_id_root)
                                      ? lookup_context::Tree::ById
                                      : lookup_context::Tree::BySeqno;
        lookup_context cbctx = {db, 0, callback, ctx, treeType, 0, nullptr};
        couchfile_lookup_request rq;
        rq.cmp.compare = key_compare;
        rq.file = &db->file;
        rq.num_keys = numDocs;
        rq.keys = (sized_buf**) keyptrs;
        rq.callback_ctx = &cbctx;
        rq.fetch_callback = lookup_callback;
        rq.node_callback = nullptr;
        rq.fold = fold;
        rq.tolerate_corruption = tolerate_corruption;

        // Go!
        error_pass(btree_lookup(&rq, tree->pointer));
    }
cleanup:
    cb_free(keyptrs);
    return errcode;
}

couchstore_error_t couchstore_docinfos_by_id(Db *db,
                                             const sized_buf ids[],
                                             unsigned numDocs,
                                             couchstore_docinfos_options options,
                                             couchstore_changes_callback_fn callback,
                                             void *ctx)
{
    COLLECT_LATENCY();

    return iterate_docinfos(db, ids, numDocs,
                            db->header.by_id_root, id_ptr_cmp, ebin_cmp,
                            callback,
                            (options & RANGES) != 0,
                            (options & COUCHSTORE_TOLERATE_CORRUPTION) != 0,
                            ctx);
}

couchstore_error_t couchstore_docinfos_by_sequence(Db *db,
                                                   const uint64_t sequence[],
                                                   unsigned numDocs,
                                                   couchstore_docinfos_options options,
                                                   couchstore_changes_callback_fn callback,
                                                   void *ctx)
{
    COLLECT_LATENCY();

    // Create the array of keys:
    sized_buf *keylist = static_cast<sized_buf*>(cb_malloc(numDocs * sizeof(sized_buf)));
    raw_by_seq_key *keyvalues = static_cast<raw_by_seq_key*>(cb_malloc(numDocs * sizeof(raw_by_seq_key)));
    couchstore_error_t errcode;
    error_unless(!db->dropped, COUCHSTORE_ERROR_FILE_CLOSED);
    error_unless(keylist && keyvalues, COUCHSTORE_ERROR_ALLOC_FAIL);
    unsigned i;
    for (i = 0; i< numDocs; ++i) {
        encode_raw48(sequence[i], &keyvalues[i].sequence);
        keylist[i].buf = static_cast<char*>((void*) &keyvalues[i]);
        keylist[i].size = sizeof(keyvalues[i]);
    }

    error_pass(iterate_docinfos(db, keylist, numDocs,
                                db->header.by_seq_root, seq_ptr_cmp, seq_cmp,
                                callback,
                                (options & RANGES) != 0,
                                (options & COUCHSTORE_TOLERATE_CORRUPTION) != 0,
                                ctx));
cleanup:
    cb_free(keylist);
    cb_free(keyvalues);
    return errcode;
}

couchstore_error_t couchstore_db_info(Db *db, DbInfo* dbinfo) {
    if (db == nullptr || dbinfo == nullptr) {
        return COUCHSTORE_ERROR_INVALID_ARGUMENTS;
    }
    const node_pointer *id_root = db->header.by_id_root;
    const node_pointer *seq_root = db->header.by_seq_root;
    const node_pointer *local_root = db->header.local_docs_root;
    dbinfo->filename = db->file.path.c_str();
    dbinfo->header_position = db->header.position;
    dbinfo->last_sequence = db->header.update_seq;
    dbinfo->purge_seq = db->header.purge_seq;
    dbinfo->deleted_count = dbinfo->doc_count = dbinfo->space_used = 0;
    dbinfo->file_size = db->file.pos;
    if (id_root) {
        raw_by_id_reduce* id_reduce = (raw_by_id_reduce*) id_root->reduce_value.buf;
        dbinfo->doc_count = decode_raw40(id_reduce->notdeleted);
        dbinfo->deleted_count = decode_raw40(id_reduce->deleted);
        dbinfo->space_used = decode_raw48(id_reduce->size);
        dbinfo->space_used += id_root->subtreesize;
    }
    if(seq_root) {
        dbinfo->space_used += seq_root->subtreesize;
    }
    if(local_root) {
        dbinfo->space_used += local_root->subtreesize;
    }
    return COUCHSTORE_SUCCESS;
}

static couchstore_error_t local_doc_fetch(couchfile_lookup_request *rq,
                                          const sized_buf *k,
                                          const sized_buf *v)
{
    LocalDoc **lDoc = (LocalDoc **) rq->callback_ctx;
    LocalDoc *dp;

    if (!v) {
        *lDoc = nullptr;
        return COUCHSTORE_SUCCESS;
    }
    fatbuf *ldbuf = fatbuf_alloc(sizeof(LocalDoc) + k->size + v->size);
    if (ldbuf == nullptr) {
        return COUCHSTORE_ERROR_ALLOC_FAIL;
    }

    dp = *lDoc = (LocalDoc *) fatbuf_get(ldbuf, sizeof(LocalDoc));
    dp->id.buf = (char *) fatbuf_get(ldbuf, k->size);
    dp->id.size = k->size;

    dp->json.buf = (char *) fatbuf_get(ldbuf, v->size);
    dp->json.size = v->size;

    dp->deleted = 0;

    memcpy(dp->id.buf, k->buf, k->size);
    memcpy(dp->json.buf, v->buf, v->size);

    return COUCHSTORE_SUCCESS;
}

couchstore_error_t couchstore_open_local_document(Db *db,
                                                  const void *id,
                                                  size_t idlen,
                                                  LocalDoc **pDoc)
{
    sized_buf key;
    sized_buf *keylist = &key;
    couchfile_lookup_request rq;
    couchstore_error_t errcode;
    error_unless(!db->dropped, COUCHSTORE_ERROR_FILE_CLOSED);
    if (db->header.local_docs_root == nullptr) {
        return COUCHSTORE_ERROR_DOC_NOT_FOUND;
    }

    key.buf = (char *) id;
    key.size = idlen;

    rq.cmp.compare = ebin_cmp;
    rq.file = &db->file;
    rq.num_keys = 1;
    rq.keys = &keylist;
    rq.callback_ctx = pDoc;
    rq.fetch_callback = local_doc_fetch;
    rq.node_callback = nullptr;
    rq.fold = 0;

    errcode = btree_lookup(&rq, db->header.local_docs_root->pointer);
    if (errcode == COUCHSTORE_SUCCESS) {
        if (*pDoc == nullptr) {
            errcode = COUCHSTORE_ERROR_DOC_NOT_FOUND;
        }
    }
cleanup:
    return errcode;
}

couchstore_error_t couchstore_save_local_document(Db *db, LocalDoc *lDoc)
{
    couchstore_error_t errcode;
    couchfile_modify_action ldupdate;
    couchfile_modify_request rq;
    node_pointer* nroot = nullptr;
    error_unless(!db->dropped, COUCHSTORE_ERROR_FILE_CLOSED);

    if (lDoc->deleted) {
        ldupdate.setType(ACTION_REMOVE);
    } else {
        ldupdate.setType(ACTION_INSERT);
    }

    ldupdate.setKey(&lDoc->id);
    ldupdate.data = &lDoc->json;

    rq.cmp.compare = ebin_cmp;
    rq.num_actions = 1;
    rq.actions = &ldupdate;
    rq.fetch_callback = nullptr;
    rq.reduce = nullptr;
    rq.rereduce = nullptr;
    rq.file = &db->file;
    rq.enable_purging = false;
    rq.purge_kp = nullptr;
    rq.purge_kv = nullptr;
    rq.compacting = 0;
    rq.kv_chunk_threshold = db->file.options.kv_nodesize;
    rq.kp_chunk_threshold = db->file.options.kp_nodesize;

    nroot = modify_btree(&rq, db->header.local_docs_root, &errcode);
    if (errcode == COUCHSTORE_SUCCESS && nroot != db->header.local_docs_root) {
        cb_free(db->header.local_docs_root);
        db->header.local_docs_root = nroot;
    }

cleanup:
    return errcode;
}

couchstore_error_t cb::couchstore::saveLocalDocuments(
        Db& db, std::vector<std::reference_wrapper<LocalDoc>>& documents) {
    if (db.dropped) {
        return COUCHSTORE_ERROR_FILE_CLOSED;
    }

    // Must sort the input keys before writing
    std::sort(documents.begin(),
              documents.end(),
              [](LocalDoc& ld1, LocalDoc& ld2) {
                  return ebin_cmp(&ld1.id, &ld2.id) < 0;
              });

    int ii = 0;
    std::vector<couchfile_modify_action> actions(documents.size());
    for (const auto& doc : documents) {
        if (doc.get().deleted) {
            actions[ii].setType(ACTION_REMOVE);
        } else {
            actions[ii].setType(ACTION_INSERT);
        }

        actions[ii].setKey(const_cast<sized_buf*>(&doc.get().id));
        actions[ii].data = const_cast<sized_buf*>(&doc.get().json);
        ii++;
    }

    couchfile_modify_request rq{};
    rq.cmp.compare = ebin_cmp;
    rq.num_actions = actions.size();
    rq.actions = actions.data();
    rq.file = &db.file;
    rq.kv_chunk_threshold = db.file.options.kv_nodesize;
    rq.kp_chunk_threshold = db.file.options.kp_nodesize;

    couchstore_error_t errcode = COUCHSTORE_SUCCESS;
    auto* nroot = modify_btree(&rq, db.header.local_docs_root, &errcode);
    if (errcode == COUCHSTORE_SUCCESS && nroot != db.header.local_docs_root) {
        cb_free(db.header.local_docs_root);
        db.header.local_docs_root = nroot;
    }

    return errcode;
}

void couchstore_free_local_document(LocalDoc *lDoc)
{
    if (lDoc) {
        size_t offset = offsetof(fatbuf, buf);
        fatbuf_free((fatbuf *) ((char *)lDoc - (char *)offset));
    }
}

std::string cb::couchstore::getLastOsError(const Db& db) {
    const auto err = db.file.lastError.error;
    return fmt::format("errno = {}: '{}'", err, cb_strerror(err));
}

std::string cb::couchstore::getLastInternalError() {
    return fmt::format("'{}'", internal_error_string);
}

static couchstore_error_t btree_eval_seq_reduce(Db *db,
                                                uint64_t *accum,
                                                sized_buf *left,
                                                sized_buf *right,
                                                bool past_left_edge,
                                                uint64_t diskpos) {
    couchstore_error_t errcode = COUCHSTORE_SUCCESS;
    int bufpos = 1, nodebuflen = 0;
    int node_type;
    char* nodebuf = nullptr;
    nodebuflen = pread_compressed(&db->file, diskpos, &nodebuf);
    error_unless(nodebuflen >= 0, (static_cast<couchstore_error_t>(nodebuflen)));  // if negative, it's an error code

    node_type = nodebuf[0];
    while(bufpos < nodebuflen) {
        sized_buf k, v;
        bufpos += read_kv(nodebuf + bufpos, &k, &v);
        int left_cmp = seq_cmp(&k, left);
        int right_cmp = seq_cmp(&k, right);
        if(left_cmp < 0) {
            continue;
        }
        if(node_type == KP_NODE) {
            // In-range Item in a KP Node
            const raw_node_pointer *raw = (const raw_node_pointer*)v.buf;
            const raw_by_seq_reduce *rawreduce = (const raw_by_seq_reduce*) (v.buf + sizeof(raw_node_pointer));
            uint64_t subcount = decode_raw40(rawreduce->count);
            uint64_t pointer = decode_raw48(raw->pointer);
            if((left_cmp >= 0 && !past_left_edge) || right_cmp >= 0) {
                error_pass(btree_eval_seq_reduce(db, accum, left, right, past_left_edge, pointer));
                if(right_cmp >= 0) {
                    break;
                } else {
                    past_left_edge = true;
                }
            } else {
                *accum += subcount;
            }
        } else {
            if(right_cmp > 0) {
                break;
            }
            // In-range Item in a KV Node
            *accum += 1;
        }
    }
cleanup:
    if (nodebuf) {
        cb_free(nodebuf);
    }
    return errcode;
}

couchstore_error_t couchstore_changes_count(Db* db,
                                            uint64_t min_seq,
                                            uint64_t max_seq,
                                            uint64_t *count) {
    COLLECT_LATENCY();

    couchstore_error_t errcode = COUCHSTORE_SUCCESS;
    raw_48 leftkr, rightkr;
    sized_buf leftk, rightk;
    leftk.buf = (char*) &leftkr;
    rightk.buf = (char*) &rightkr;
    leftk.size = 6;
    rightk.size = 6;
    encode_raw48(min_seq, &leftkr);
    encode_raw48(max_seq, &rightkr);

    *count = 0;
    if(db->header.by_seq_root) {
        error_pass(btree_eval_seq_reduce(db, count, &leftk, &rightk, false,
                                         db->header.by_seq_root->pointer));
    }
cleanup:
    return errcode;
}

namespace cb {
namespace couchstore {

couchstore_error_t seek(Db& db, cs_off_t offset) {
    COLLECT_LATENCY();
    if (db.dropped) {
        return COUCHSTORE_ERROR_FILE_CLOSED;
    }

    // All header blocks are located at the beginning of a block
    if (offset % COUCH_BLOCK_SIZE) {
        return COUCHSTORE_ERROR_INVALID_ARGUMENTS;
    }

    if (uint64_t(offset) >= db.file.pos) {
        // Requested offset is beyond the file size
        return COUCHSTORE_ERROR_NO_HEADER;
    }

    const auto current = db.header.position;

    couchstore_error_t errcode;
    error_unless(!db.dropped, COUCHSTORE_ERROR_FILE_CLOSED);
    // free current header guts
    db.header.reset();
    error_pass(find_header_at_pos(&db, offset));

cleanup:
    // if we failed, free the handle and return an error
    if (errcode == COUCHSTORE_SUCCESS) {
        return COUCHSTORE_SUCCESS;
    }

    // Try to reopen the previous database!!
    if (find_header_at_pos(&db, current) != COUCHSTORE_SUCCESS) {
        // failed to open the database we had open... Drop the file
        // but don't release the handle (as couchstore_close_file may
        // be called multiple times)
        couchstore_close_file(&db);
        return COUCHSTORE_ERROR_DB_NO_LONGER_VALID;
    }

    return errcode;
}

couchstore_error_t seek(Db& db, Direction direction) {
    if (db.dropped) {
        return COUCHSTORE_ERROR_FILE_CLOSED;
    }

    couchstore_error_t errorcode = COUCHSTORE_ERROR_INVALID_ARGUMENTS;
    const auto current = db.header.position;
    const auto old_file_pos = db.file.pos;
    cs_off_t offset;

    switch (direction) {
    case Direction::End:
        // Get the new file size
        offset = db.file.ops->goto_eof(&db.file.lastError, db.file.handle);
        if (offset < 0) {
            // A negative value is the couchstore_error_t for the operation
            errorcode = couchstore_error_t(offset);
        } else {
            db.file.pos = uint64_t(offset);
            db.header.position = db.file.pos - 2;
            // Don't use the previous header pointer
            db.header.prev_header_pos = UNKNOWN_PREV_HEADER_POS;
            errorcode = couchstore_rewind_db_header_impl(&db);
        }
        break;

    case Direction::Forward:
        errorcode = couchstore_fastforward_db_header_impl(&db);
        break;

    case Direction::Backward:
        // "optimization": if we're at the beginning of the file we don't
        // need to drop the internal data and reload them..
        if (db.header.position == 0) {
            return COUCHSTORE_ERROR_NO_HEADER;
        }
        errorcode = couchstore_rewind_db_header_impl(&db);
        break;
    }

    if (errorcode == COUCHSTORE_SUCCESS) {
        return COUCHSTORE_SUCCESS;
    }

    // Restore the old file position (if we changed it)
    db.file.pos = old_file_pos;
    if (errorcode == COUCHSTORE_ERROR_INVALID_ARGUMENTS) {
        return errorcode;
    }

    // Try to reopen the previous database!!
    if (find_header_at_pos(&db, current) != COUCHSTORE_SUCCESS) {
        // failed to open the database we had open... Drop the file
        // but don't release the handle (as couchstore_close_file may
        // be called multiple times)
        couchstore_close_file(&db);
        return COUCHSTORE_ERROR_DB_NO_LONGER_VALID;
    }

    return errorcode;
}

couchstore_error_t seekFirstHeaderContaining(Db& db,
                                             uint64_t seqno,
                                             uint64_t granularity) {
    if (granularity == 0) {
        throw std::invalid_argument(
                "seekFirstHeaderContaining: granularity can't be 0");
    }

    // We can have readers and writers in the same file, and given the
    // append-only format it is safe for readers to seek within the portion up
    // to where they opened the file.
    const auto tipOffset = getHeader(db).headerPosition;

    // The following implements a binary-search on the datafile for finding the
    // first header that contains the given seqno.
    //
    // [left, right] are offsets of file headers, and they represent the search
    // range at each iteration.
    // The procedure starts from [0, last-header-offset] and narrows down the
    // range to a point where there's no further possibility to shrink the range
    // down.
    // Note that, compared to a vanilla binary-search on a domain that contains
    // the search element, here we are in a case where the element might or
    // might be not in the domain - ie, in most cases we will be looking for a
    // seqno for which we don't have an exact header.updateSeqNum. Thus the
    // extra complexity in the break-conditions of the procedure, see below for
    // details.

    const auto blockSize = getDiskBlockSize(db);
    uint64_t left = 0;
    uint64_t right = getHeader(db).headerPosition;
    while (true) {
        if (left > right) {
            throw std::logic_error("seekFirstHeaderContaining: l (" +
                                   std::to_string(left) + ") > r (" +
                                   std::to_string(right) + ")");
        }

        // Find the offset in the middle of the range
        uint64_t middle = (left + right) / 2;
        // Align it to the block boundary
        middle = middle - (middle % blockSize);

        // middle here is at block boundary but it could point to header or
        // data, so we need to find the first header.
        couchstore_error_t ret;
        while ((ret = seek(db, middle)) != COUCHSTORE_SUCCESS) {
            if (ret != COUCHSTORE_ERROR_NO_HEADER) {
                throw std::logic_error(
                        "seekFirstHeaderContaining: looking for the "
                        "middle-header, unexpected ret:" +
                        std::to_string(ret));
            }
            middle += blockSize;
        }

        // Finding middle has required some adjustments. Those ensure the
        // following invariants, but let's be paranoid on correctness.
        if (middle < left || middle > right) {
            throw std::logic_error(
                    "seekFirstHeaderContaining: l < m < r invariant broken: "
                    "l(" +
                    std::to_string(left) + "), m(" + std::to_string(middle) +
                    "), r(" + std::to_string(right) + ")");
        }

        const auto headerSeqno = getHeader(db).updateSeqNum;
        if (seqno < headerSeqno) {
            // H  H  H  H  H  H  H  H  H
            // l     s     m           r
            if (right == middle) {
                // H  H  H  H  H  H  H  H  H
                // l        s m/r
                // We have already set r (ie the upper bound of the range) to m.
                // That means that the search-seqno is lower then the current
                // header, but the current header is the closer that contains
                // the search-seqno.
                break;
            }
            right = middle;
        } else if (seqno > headerSeqno) {
            // H  H  H  H  H  H  H  H  H
            // l           m     s     r
            if (left == middle) {
                // H  H  H  H  H  H  H  H  H
                //         l/m s           r
                // We have already set l (ie the lower bound of the range) to m.
                // That means that the search-seqno is higher then the current
                // header, but the header next to the current one is the closer
                // that contains the search-seqno.
                const auto ret = seek(db, Direction::Forward);
                if (ret != COUCHSTORE_SUCCESS) {
                    throw std::logic_error(
                            "seekFirstHeaderContaining: header located, "
                            "seeking forward, unexpected ret:" +
                            std::to_string(ret));
                }
                break;
            }
            left = middle;
        } else {
            // Unlikely/lucky case, we have an header that is exactly at
            // search-seqno, all done.
            break;
        }
    }

    // We may have a finer granularity "on disk" than the user requested
    // Try to "fast forward" to the requested boundary
    auto header = getHeader(db);

    if (header.headerPosition == tipOffset || granularity == 1) {
        // This is the newest header so we can't fast forward
        return COUCHSTORE_SUCCESS;
    }

    const auto next =
            header.timestamp - (header.timestamp % granularity) + granularity;
    if (header.timestamp < next) {
        // Inspect all blocks up to the tip of the file
        while (header.headerPosition < tipOffset) {
            const auto prev = header.headerPosition;
            auto status = seek(db, Direction::Forward);
            if (status != COUCHSTORE_SUCCESS) {
                // TODO: Remove this PiTR code?
                (void)seek(db, tipOffset);
                return status;
            }
            header = getHeader(db);
            if (header.timestamp >= next) {
                // this one is too new... jump back
                status = seek(db, prev);
                if (status != COUCHSTORE_SUCCESS) {
                    // TODO: Remove this PiTR code?
                    (void)seek(db, tipOffset);
                }
                return status;
            }
        }
    }

    return COUCHSTORE_SUCCESS;
}

} // namespace couchstore
} // namespace cb
