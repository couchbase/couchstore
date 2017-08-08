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

#include "config.h"

#include <libcouchstore/couch_db.h>
#include <set>
#include <string>
#include <vector>

class Documents {

public:
    Documents(int n_docs);

    /**
        Set document at index with id and data.
        Note: null terminator of both id/data strings is not stored.
    **/
    void setDoc(int index, const std::string& id, const std::string& data);

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
     * Generate docs with random keys
     */
    void generateRandomDocs(int seed,
                            std::string keyPrefix = "doc",
                            std::string keySuffix = "doc");

    void setContentMeta(int index, int flag);

    Doc** getDocs();

    DocInfo** getDocInfos();

    Doc* getDoc(int index);

    DocInfo* getDocInfo(int index);

    int getDocsCount() const;

    int getDocInfosCount() const;

    int getDeleted() const;

    int getCallbacks() const;

    int getPosition() const;

    void resetCounters();

    /**
        Update the document map with the key.
        Expects the key to not exist (uses gtest EXPECT macro)
    **/
    void updateDocumentMap(const std::string& key);

    void clearDocumentMap();

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

private:

    void incrementCallbacks();

    void incrementDeleted();

    void incrementPosition();
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

        void setContentMeta(int flag);

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
    std::vector<Document> documents;
    std::set<std::string> documentMap;

    // Counters for the callbacks
    int deleted;
    int callbacks;
    int position;
};