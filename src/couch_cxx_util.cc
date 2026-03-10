/*
 *     Copyright 2020 Couchbase, Inc.
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

#include "couch_btree.h"
#include "util.h"
#include <nlohmann/json.hpp>
#include <platform/string_hex.h>
#include <libcouchstore/json_utils.h>

namespace cb {
namespace couchstore {

void DbDeleter::operator()(Db* db) {
    couchstore_close_file(db);
    couchstore_free_db(db);
}

void DocInfoDeleter::operator()(DocInfo* info) {
    couchstore_free_docinfo(info);
}

void DocDeleter::operator()(Doc* doc) {
    couchstore_free_document(doc);
}

void LocalDocDeleter::operator()(LocalDoc* doc) {
    couchstore_free_local_document(doc);
}

std::pair<couchstore_error_t, UniqueLocalDocPtr> openLocalDocument(
        Db& db, std::string_view id) {
    LocalDoc* localDoc = nullptr;
    auto error = couchstore_open_local_document(
            &db,
            reinterpret_cast<const void*>(id.data()),
            id.size(),
            &localDoc);
    if (error == COUCHSTORE_SUCCESS) {
        return {error, UniqueLocalDocPtr{localDoc}};
    }
    return {error, UniqueLocalDocPtr{}};
}

std::pair<couchstore_error_t, UniqueLocalDocPtr> openLocalDocument(
        Db& db, const DocInfo& docInfo) {
    return openLocalDocument(db,
                             std::string_view{docInfo.id.buf, docInfo.id.size});
}

std::pair<couchstore_error_t, UniqueDocPtr> openDocument(
        Db& db, const DocInfo& docInfo) {
    Doc* doc = nullptr;
    auto error = couchstore_open_doc_with_docinfo(&db, &docInfo, &doc, 0);
    if (error == COUCHSTORE_SUCCESS) {
        return {error, UniqueDocPtr{doc}};
    }
    return {error, UniqueDocPtr{}};
}

std::pair<couchstore_error_t, UniqueDocPtr> openDocument(Db& db,
                                                         std::string_view key) {
    Doc* doc = nullptr;
    auto error = couchstore_open_document(&db, key.data(), key.size(), &doc, 0);
    if (error == COUCHSTORE_SUCCESS) {
        return {error, UniqueDocPtr{doc}};
    }
    return {error, UniqueDocPtr{}};
}

LIBCOUCHSTORE_API
std::pair<couchstore_error_t, UniqueDocInfoPtr> openDocInfo(
        Db& db, std::string_view key) {
    DocInfo* docInfo = nullptr;
    auto error =
            couchstore_docinfo_by_id(&db, key.data(), key.size(), &docInfo);
    if (error == COUCHSTORE_SUCCESS) {
        return {error, UniqueDocInfoPtr{docInfo}};
    }
    return {error, UniqueDocInfoPtr{}};
}

static couchstore_error_t scanLocalDocsCallback(couchfile_lookup_request* rq,
                                                const sized_buf* key,
                                                const sized_buf* value) {
    auto buf = fatbuf_alloc(sizeof(LocalDoc) + key->size + value->size);
    if (buf == nullptr) {
        return COUCHSTORE_ERROR_ALLOC_FAIL;
    }

    auto doc = reinterpret_cast<LocalDoc*>(fatbuf_get(buf, sizeof(LocalDoc)));
    doc->id.buf = reinterpret_cast<char*>(fatbuf_get(buf, key->size));
    doc->id.size = key->size;

    doc->json.buf = reinterpret_cast<char*>(fatbuf_get(buf, value->size));
    doc->json.size = value->size;

    doc->deleted = 0;

    memcpy(doc->id.buf, key->buf, key->size);
    memcpy(doc->json.buf, value->buf, value->size);

    try {
        auto& callback = *reinterpret_cast<
                const std::function<couchstore_error_t(UniqueLocalDocPtr)>*>(
                rq->callback_ctx);
        return callback(UniqueLocalDocPtr{doc});
    } catch (const std::bad_alloc&) {
        return COUCHSTORE_ERROR_ALLOC_FAIL;
    } catch (const std::exception& ex) {
        log_last_internal_error(
                "cb::couchstore::scanLocalDocs() Callback failed: %s",
                ex.what());
        return COUCHSTORE_ERROR_INVALID_ARGUMENTS;
    }
}

LIBCOUCHSTORE_API
couchstore_error_t scanLocalDocs(
        Db& db,
        std::string_view from,
        const std::function<couchstore_error_t(UniqueLocalDocPtr)>& callback) {
    if (db.dropped) {
        return COUCHSTORE_ERROR_FILE_CLOSED;
    }
    if (db.header.local_docs_root == nullptr) {
        return COUCHSTORE_SUCCESS;
    }

    sized_buf first{const_cast<char*>(from.data()), from.size()};
    if (first.buf == nullptr) {
        first.buf = const_cast<char*>("");
    }
    auto keys = &first;

    couchfile_lookup_request rq{};
    rq.cmp.compare = ebin_cmp;
    rq.file = &db.file;
    rq.num_keys = 1;
    rq.keys = &keys;
    rq.callback_ctx = (void*)&callback;
    rq.fetch_callback = scanLocalDocsCallback;
    rq.fold = 1;

    return btree_lookup(&rq, db.header.local_docs_root->pointer);
}

std::pair<couchstore_error_t, UniqueDbPtr> openDatabase(
        const std::string& filename,
        couchstore_open_flags flags,
        cb::couchstore::EncryptionKeyGetter encryptionKeyCB,
        FileOpsInterface* fileops,
        std::optional<cs_off_t> offset) {
    Db* db = nullptr;
    if (!fileops) {
        fileops = couchstore_get_default_file_ops();
    }
    auto error = couchstore_open_db_ex(
            filename.c_str(), flags, std::move(encryptionKeyCB), fileops, &db);
    if (error == COUCHSTORE_SUCCESS) {
        if (offset) {
            UniqueDbPtr uniqueDbPtr{db};
            auto status = seek(*uniqueDbPtr, *offset);
            return {status, std::move(uniqueDbPtr)};
        }
        return {COUCHSTORE_SUCCESS, UniqueDbPtr{db}};
    }

    return {error, UniqueDbPtr{}};
}

size_t getDiskBlockSize(Db&) {
    return COUCH_BLOCK_SIZE;
}

nlohmann::json to_json(const Header& header) {
    nlohmann::json ret;
    ret["version"] = uint64_t(header.version);
    ret["update_seq"] = header.updateSeqNum;
    ret["purge_seq"] = header.purgeSeqNum;
    ret["header_position"] = cb::to_hex(header.headerPosition);
    ret["timestamp"] = header.timestamp;
    ret["filename"] = header.filename;
    ret["doc_count"] = header.docCount;
    ret["deleted_count"] = header.deletedCount;
    ret["space_used"] = header.spaceUsed;
    ret["file_size"] = header.fileSize;
    return ret;
}

Header getHeader(Db& db) {
    Header ret;
    ret.version = Header::Version(db.header.disk_version);
    ret.updateSeqNum = db.header.update_seq;
    ret.purgeSeqNum = db.header.purge_seq;
    ret.timestamp = db.header.timestamp;
    ret.headerPosition = db.header.position;
    DbInfo info;
    couchstore_db_info(&db, &info);
    ret.filename = info.filename;
    ret.docCount = info.doc_count;
    ret.deletedCount = info.deleted_count;
    ret.spaceUsed = info.space_used;
    ret.fileSize = info.file_size;
    return ret;
}

bool isEncrypted(const Db& db) {
    return db.file.cipher != nullptr;
}

std::string_view getEncryptionKeyId(const Db& db) {
    return db.file.cipher_keyid;
}

} // namespace couchstore
} // namespace cb
