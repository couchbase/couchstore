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

/**
    Class to assist testing of couchstore.

    Documents represents a set of Doc/DocInfo objects allowing convenient management
    of the underlying objects.

**/

#pragma once

#include "couchstore_config.h"

#include <libcouchstore/couch_db.h>
#include <set>
#include <string>
#include <vector>

class Documents {

public:
    Documents(size_t n_docs);

    /**
        Set document at index with id and data.
        Note: null terminator of both id/data strings is not stored.
    **/
    void setDoc(size_t index, const std::string& id, const std::string& data);

    void delDoc(size_t index);

    /**
        shuffle the documents so they're no longer in the order setDoc indicated.
    **/
    void shuffle();

    /**
        Just generate documents.
        Key is doc<index>
        Document is doc<index>-data
        @param keyPrefix optional prefix
    **/
    void generateDocs(std::string keyPrefix = "doc");

    /**
     * Generate documents with a fixed length (8) and are 1 greater (memcmp)
     * than the previous. E.g.
     * "00000000"
     * "10000000"
     * "20000000"
     * ...
     * "a0000000"
     */
    void generateLexicographicalSequence();
    /**
     * Generate docs with random keys
     */
    void generateRandomDocs(int seed,
                            std::string keyPrefix = "doc",
                            std::string keySuffix = "doc");

    void setContentMeta(size_t index, uint8_t flag);

    Doc** getDocs();

    DocInfo** getDocInfos();

    void** getUserReqs();

    Doc* getDoc(size_t index);

    std::string_view getKey(size_t index) const;

    DocInfo* getDocInfo(size_t index);

    size_t getDocsCount() const;

    size_t getDocInfosCount() const;

    int getDeleted() const;

    int getCallbacks() const;

    size_t getPosition() const;

    void resetCounters();

    /**
        Update the document map with the key.
        Expects the key to not exist (uses gtest EXPECT macro)
    **/
    void updateDocumentMap(const std::string& key);

    void clearDocumentMap();

    void setRange(std::string_view start, std::string_view end) {
        this->start = start;
        this->end = end;
    }

    /**
        Couchstore callback method that checks the document against
        the orginal Documents data.
    **/
    static int checkCallback(Db* db, DocInfo* info, void* ctx);

    /**
        Couchstore callback method that just counts the number of callbacks.
    **/
    static int countCallback(Db* db, DocInfo* info, void* ctx);

    /**
        Couchstore callback method that checks the document can be opened.
            - Also counts callbacks and deleted documents.
    **/
    static int docIterCheckCallback(Db *db, DocInfo *info, void *ctx);

    /**
        Couchstore callback that updates a set of document keys.
            - The update call expects the document to not exist in the set.
    **/
    static int docMapUpdateCallback(Db *db, DocInfo *info, void *ctx);

    static int inRangeAndCountCallback(Db* db, DocInfo* info, void* ctx);

private:

    void incrementCallbacks();

    void incrementDeleted();

    void incrementPosition();

    std::string_view getRangeStart() const {
        return start;
    }
    std::string_view getRangeEnd() const {
        return end;
    }

    /**
        Inner class storing the data for one document.
    **/
    class Document {
    public:

        Document();

        ~Document();

        /* Init a document */
        void init(const std::string& id, const std::string& data, const std::vector<char>& meta);

        /* Init a document with default 'zero' meta */
        void init(const std::string& id, const std::string& data);

        void setContentMeta(uint8_t flag);

    private:
        friend Documents;

        Doc* getDocPointer();

        DocInfo* getDocInfoPointer();

        Doc doc;
        DocInfo docInfo;
        std::vector<char> documentId;
        std::vector<char> documentData;
        std::vector<char> documentMeta;
        static std::vector<char> zeroMeta;
    };

    // Documents private data.
    std::vector<Doc*> docs;
    std::vector<DocInfo*> docInfos;
    std::vector<void*> userReqs;
    std::vector<Document> documents;
    std::set<std::string> documentMap;

    // Counters for the callbacks
    int deleted;
    int callbacks;
    size_t position;

    // data for inRangeAndCountCallback
    std::string start;
    std::string end;
};

/// Convenience function to convert a size_buf to std::string.
std::string to_string(sized_buf buf);
