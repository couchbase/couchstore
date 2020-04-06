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

#include "internal.h"
#include <nlohmann/json.hpp>
#include <platform/string_hex.h>

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

std::pair<couchstore_error_t, UniqueDbPtr> openDatabase(
        const std::string& filename,
        couchstore_open_flags flags,
        FileOpsInterface* fileops,
        std::optional<cs_off_t> offset) {
    Db* db = nullptr;
    if (!fileops) {
        fileops = couchstore_get_default_file_ops();
    }
    auto error = couchstore_open_db_ex(filename.c_str(), flags, fileops, &db);
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

nlohmann::json Header::to_json() const {
    nlohmann::json ret;
    ret["version"] = uint64_t(version);
    ret["update_seq"] = updateSeqNum;
    ret["purge_seq"] = purgeSeqNum;
    ret["header_position"] = cb::to_hex(headerPosition);
    ret["timestamp"] = timestamp;
    return ret;
}

Header getHeader(Db& db) {
    Header ret;
    ret.version = Header::Version(db.header.disk_version);
    ret.updateSeqNum = db.header.update_seq;
    ret.purgeSeqNum = db.header.purge_seq;
    ret.timestamp = db.header.timestamp;
    ret.headerPosition = db.header.position;
    return ret;
}

} // namespace couchstore
} // namespace cb
