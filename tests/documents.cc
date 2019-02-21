/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2015 Couchbase, Inc
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

#include "documents.h"

#include <folly/portability/GTest.h>
#include <libcouchstore/couch_db.h>
#include <algorithm>
#include <cstring>
#include <random>

static std::string to_string(sized_buf buf) {
    return std::string(buf.buf, buf.size);
}

Documents::Documents(int n_docs)
  : docs(n_docs),
    docInfos(n_docs),
    documents(n_docs),
    deleted(0),
    callbacks(0),
    position(0) {
}

void Documents::setDoc(int index, const std::string& id, const std::string& data) {
    documents[index].init(id, data);
    docs[index] = documents[index].getDocPointer();
    docInfos[index] = documents[index].getDocInfoPointer();
}

// shuffle the doc*/docinfo*
void Documents::shuffle() {
    // shuffle both arrays using same psudeo-rand input
    std::mt19937 twister1(10), twister2(10);
    std::shuffle(docs.begin(), docs.end(), twister1);
    std::shuffle(docInfos.begin(), docInfos.end(), twister2);
}

void Documents::generateDocs(std::string keyPrefix) {
    for (size_t ii = 0; ii < documents.size(); ii++) {
        std::string key = keyPrefix + std::to_string(ii);
        std::string data = key + "-data";
        setDoc(ii, key, data);
    }
}

void Documents::generateRandomDocs(int seed,
                                   std::string keyPrefix,
                                   std::string keySuffix) {
    std::mt19937 twister1(seed);
    const std::string characters =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    std::uniform_int_distribution<int> distribution(0, characters.size() - 1);
    for (size_t ii = 0; ii < documents.size(); ii++) {
        std::string randKey;
        std::generate_n(std::back_inserter(randKey), 10, [&]() {
            return characters[distribution(twister1)];
        });
        std::string key = keyPrefix + randKey + std::to_string(ii) + keySuffix;
        std::string data = key + "-data";
        setDoc(ii, key, data);
    }
}

void Documents::setContentMeta(int index, int flag) {
    documents[index].setContentMeta(flag);
}

Doc** Documents::getDocs() {
    return docs.data();
}

DocInfo** Documents::getDocInfos() {
    return docInfos.data();
}

Doc* Documents::getDoc(int index) {
    return docs[index];
}

DocInfo* Documents::getDocInfo(int index) {
    return docInfos[index];
}

int Documents::getDocsCount() const {
    return docs.size();
}

int Documents::getDocInfosCount() const {
    return docInfos.size();
}

void Documents::incrementDeleted() {
    deleted++;
}

int Documents::getDeleted() const {
    return deleted;
}

void Documents::incrementCallbacks() {
    callbacks++;
}

int Documents::getCallbacks() const {
    return callbacks;
}

void Documents::incrementPosition() {
    position++;
}

int Documents::getPosition() const {
    return position;
}

void Documents::resetCounters() {
    deleted = 0;
    callbacks = 0;
    position = 0;
}

void Documents::updateDocumentMap(const std::string& key) {
    EXPECT_EQ(0ul, documentMap.count(key));
    documentMap.insert(key);
}

void Documents::clearDocumentMap() {
    documentMap.clear();
}

/**
    Couchstore callback method that checks the document against
    the orginal Documents data.
**/
int Documents::checkCallback(Db* db, DocInfo* info, void* ctx) {
    Documents* ds = reinterpret_cast<Documents*>(ctx);

    ds->incrementCallbacks();

    if (info->deleted) {
        ds->incrementDeleted();
    }

    Doc* doc = ds->getDoc(ds->getPosition());
    DocInfo* docInfo = ds->getDocInfo(ds->getPosition());

    EXPECT_EQ(to_string(docInfo->id), to_string(info->id));
    EXPECT_EQ(to_string(docInfo->rev_meta), to_string(info->rev_meta));

    Doc* openDoc = nullptr;
    couchstore_open_doc_with_docinfo(db,
                                     info,
                                     &openDoc,
                                     DECOMPRESS_DOC_BODIES);
    EXPECT_TRUE(openDoc != nullptr);

    if (openDoc && doc->data.size > 0) {
        EXPECT_EQ(to_string(openDoc->id), to_string(doc->id));
        EXPECT_EQ(to_string(openDoc->data), to_string(openDoc->data));
    }

    ds->incrementPosition();
    if (openDoc) {
        couchstore_free_document(openDoc);
    }
    return 0;
}

/**
    Couchstore callback method that just counts the number of callbacks.
**/
int Documents::countCallback(Db* db, DocInfo* info, void* ctx) {
    reinterpret_cast<Documents*>(ctx)->incrementCallbacks();
    return 0;
}

/**
    Couchstore callback method that checks the document can be opened.
        - Also counts callbacks and deleted documents.
**/
int Documents::docIterCheckCallback(Db *db, DocInfo *info, void *ctx) {
    Documents* ds = reinterpret_cast<Documents*>(ctx);

    ds->incrementCallbacks();
    if (info->deleted) {
        ds->incrementDeleted();
    }

    Doc* doc = nullptr;
    EXPECT_EQ(COUCHSTORE_SUCCESS, couchstore_open_doc_with_docinfo(db,
                                                                   info,
                                                                   &doc,
                                                                   DECOMPRESS_DOC_BODIES));

    EXPECT_TRUE(doc != nullptr);

    if (doc) {
        couchstore_free_document(doc);
    }
    return 0;
}

/**
    Couchstore callback that updates a set of document keys.
        - The update call expects the document to not exist in the set.
**/
int Documents::docMapUpdateCallback(Db *db, DocInfo *info, void *ctx) {
    Documents* ds = reinterpret_cast<Documents*>(ctx);
    std::string key(info->id.buf, info->id.size);
    ds->updateDocumentMap(key);
    return 0;
}

Documents::Document::Document() {
    std::memset(&doc, 0, sizeof(Doc));
    std::memset(&docInfo, 0, sizeof(DocInfo));
}

Documents::Document::~Document() {
    documentId.clear();
    documentData.clear();
    documentMeta.clear();
}

/* Init a document */
void Documents::Document::init(const std::string& id, const std::string& data, const std::vector<char>& meta) {
    // Copy-in id and data as Doc/DocInfo use raw char* (non const)
    // This is probably overkill (const cast could work) but this is the safe and more
    // correct style.
    documentId.resize(id.length());
    std::memcpy(documentId.data(), id.c_str(), id.length());

    documentData.resize(data.length());
    std::copy(data.begin(), data.end(), documentData.begin());

    doc.id.buf = documentId.data();
    doc.id.size = documentId.size();

    doc.data.buf = documentData.data();
    doc.data.size = documentData.size();

    documentMeta = meta;
    docInfo.id.buf = documentId.data();
    docInfo.id.size = documentId.size();
    docInfo.rev_meta.buf = documentMeta.data();
    docInfo.rev_meta.size = documentMeta.size();
}

/* Init a document with default 'zero' meta */
void Documents::Document::init(const std::string& id, const std::string& data) {
    init(id, data, zeroMeta);
}

void Documents::Document::setContentMeta(int flag) {
    docInfo.content_meta = flag;
}

Doc* Documents::Document::getDocPointer() {
    return &doc;
}

DocInfo* Documents::Document::getDocInfoPointer() {
    return &docInfo;
}

std::vector<char> Documents::Document::zeroMeta = {0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3};
