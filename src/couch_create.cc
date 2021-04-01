/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2015 Couchbase, Inc.
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

//
// couch_create, a program for 'offline' generation of Couchbase compatible
// couchstore files.
//

#include "crc32.h"
#include <getopt.h>
#include <inttypes.h>
#include <mcbp/protocol/unsigned_leb128.h>
#include <nlohmann/json.hpp>
#include <platform/socket.h>
#include <stddef.h>
#include <stdint.h>
#include <array>
#include <atomic>
#include <chrono>
#include <climits>
#include <condition_variable>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <exception>
#include <iostream>
#include <memory>
#include <mutex>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "libcouchstore/couch_db.h"

enum VBucketState { VB_ACTIVE, VB_REPLICA, VB_UNMANAGED };

enum DocType {
    BINARY_DOC,
    BINARY_DOC_COMPRESSED,
    JSON_DOC,
    JSON_DOC_COMPRESSED
};

//
// ProgramParameters:
// An object to process argv/argc and carry around the parameters to operate
// with.
//
class ProgramParameters {
public:
    // Define all program defaults as static
    static const bool reuse_couch_files_default = false;
    static const int vbc_default = 1024;
    static const uint64_t key_count_default = 0;
    static const int keys_per_flush_default = 512;
    static const int doc_len_default = 256;
    static const int keys_per_vbucket_default = false;
    static const uint64_t start_key_default = 0;
    static const bool low_compression_default = false;
    static const DocType doc_type_default = BINARY_DOC_COMPRESSED;
    static const int flusher_count_default = 8;
    static const uint32_t collection_id_default = 0;

    //
    // Construct a program parameters, all parameters assigned default settings
    //
    ProgramParameters()
        : reuse_couch_files(reuse_couch_files_default),
          vbc(vbc_default),
          key_count(key_count_default),
          keys_per_vbucket(keys_per_vbucket_default),
          keys_per_flush(keys_per_flush_default),
          doc_len(doc_len_default),
          doc_type(doc_type_default),
          vbuckets(vbc_default),
          vbuckets_managed(0),
          start_key(start_key_default),
          low_compression(low_compression_default),
          flusher_count(flusher_count_default) {
        fill(vbuckets.begin(), vbuckets.end(), VB_UNMANAGED);
    }

    void load(int argc, char** argv) {
        const int KEYS_PER_VBUCKET = 1000;
        while (1) {
            static struct option long_options[] = {
                    {"reuse", no_argument, 0, 'r'},
                    {"vbc", required_argument, 0, 'v'},
                    {"keys", required_argument, 0, 'k'},
                    {"keys-per-vbucket", no_argument, 0, KEYS_PER_VBUCKET},
                    {"keys-per-flush", required_argument, 0, 'f'},
                    {"doc-len", required_argument, 0, 'd'},
                    {"doc-type", required_argument, 0, 't'},
                    {"start-key", required_argument, 0, 's'},
                    {"low-compression", no_argument, 0, 'l'},
                    {"no-namespace", no_argument, 0, 'n'},
                    {"namespace-id", required_argument, 0, 'i'},
                    {0, 0, 0, 0}};
            /* getopt_long stores the option index here. */
            int option_index = 0;

            int c = getopt_long(
                    argc, argv, "s:v:k:f:d:t:rl", long_options, &option_index);

            /* Detect the end of the options. */
            if (c == -1) {
                break;
            }

            switch (c) {
            case 'v': {
                vbc = static_cast<int16_t>(atoi(optarg));
                vbuckets.resize(vbc);
                break;
            }

            case 'k': {
                key_count = strtoull(optarg, 0, 10);
                break;
            }

            case 'f': {
                keys_per_flush = atoi(optarg);
                break;
            }

            case 'd': {
                doc_len = atoi(optarg);
                break;
            }

            case 'r': {
                reuse_couch_files = true;
                break;
            }

            case 'l': {
                low_compression = true;
                break;
            }

            case 's': {
                start_key = strtoull(optarg, 0, 10);
                break;
            }

            case 't': {
                if (strcmp(optarg, "binary") == 0) {
                    doc_type = BINARY_DOC;
                } else if (strcmp(optarg, "binarycompressed") == 0) {
                    doc_type = BINARY_DOC_COMPRESSED;
                }
                break;
            }

            case KEYS_PER_VBUCKET: {
                keys_per_vbucket = true;
                break;
            }
            case 'n': {
                namespaced = false;
                break;
            }
            case 'i': {
                collection_id = atoi(optarg);
                break;
            }

            default: { usage(1); }
            }
        } // end of option parsing

        // Now are we managing all vbuckets, or a list?
        if (optind < argc) {
            while (optind < argc) {
                int i = atoi(argv[optind]);
                if (i < vbc) {
                    // a or r present?
                    VBucketState s = VB_ACTIVE;
                    for (size_t i = 0; i < strlen(argv[optind]); i++) {
                        if (argv[optind][i] == 'a') {
                            s = VB_ACTIVE;
                        } else if (argv[optind][i] == 'r') {
                            s = VB_REPLICA;
                        }
                    }
                    vbuckets[i] = s;
                    vbuckets_managed++; // keep track of how many we are
                    // managing
                    std::cout << "Managing VB " << i;
                    if (s == VB_ACTIVE) {
                        std::cout << " active" << std::endl;
                    } else {
                        std::cout << " replica" << std::endl;
                    }

                    optind++;
                }
            }
        } else {
            for (int i = 0; i < vbc; i++) {
                vbuckets[i] = VB_ACTIVE;
                vbuckets_managed++;
            }
        }
    }

    //
    // return true if the current parameters are good, else print an error and
    // return false.
    //
    bool validate() const {
        if (vbc <= 0) {
            std::cerr << "Error: vbc less than or equal to 0 - " << vbc
                      << std::endl;
            return false;
        }

        // this ensures that the program doesn't run away with no args...
        if (key_count == 0) {
            std::cerr << "Key count 0 or not specified, use -k to set key "
                         "count to "
                         "greater than 0"
                      << std::endl;
            return false;
        }
        return true;
    }

    int16_t get_vbc() const {
        return vbc;
    }

    uint64_t get_key_count() const {
        return key_count;
    }

    int get_keys_per_flush() const {
        return keys_per_flush;
    }

    int get_doc_len() const {
        return doc_len;
    }

    bool get_reuse_couch_files() const {
        return reuse_couch_files;
    }

    std::string get_doc_type_string() const {
        switch (doc_type) {
        case BINARY_DOC: {
            return std::string("binary");
            break;
        }
        case BINARY_DOC_COMPRESSED: {
            return std::string("binary compressed");
            break;
        }
        case JSON_DOC: {
            return std::string("JSON");
            break;
        }
        case JSON_DOC_COMPRESSED: {
            return std::string("JSON compressed");
            break;
        }
        }
        return std::string("getDocTypeString failure");
    }

    DocType get_doc_type() const {
        return doc_type;
    }

    bool is_keys_per_vbucket() const {
        return keys_per_vbucket;
    }

    bool is_vbucket_managed(int vb) const {
        if (vb > vbc) {
            return false;
        }
        return vbuckets[vb] != VB_UNMANAGED;
    }

    int get_vbuckets_managed() {
        return vbuckets_managed;
    }

    uint64_t get_start_key() {
        return start_key;
    }

    VBucketState get_vbucket_state(int vb) const {
        return vbuckets[vb];
    }

    void disable_vbucket(int vb) {
        static std::mutex lock;
        std::unique_lock<std::mutex> lck(lock);
        vbuckets[vb] = VB_UNMANAGED;
        vbuckets_managed--;
    }

    bool is_low_compression() {
        return low_compression;
    }

    int get_flusher_count() {
        return flusher_count;
    }

    bool is_namespaced() const {
        return namespaced;
    }

    uint32_t get_collection_id() const {
        return collection_id;
    }

    static void usage(int exit_code) {
        std::cerr << std::endl;
        std::cerr << "couch_create <options> <vbucket list>" << std::endl;
        std::cerr << "options:" << std::endl;
        std::cerr << "    --reuse,-r: Reuse couch-files (any re-used file must "
                     "have "
                     "a vbstate document) (default "
                  << reuse_couch_files_default << ")." << std::endl;
        std::cerr << "    --vbc, -v <integer>:  Number of vbuckets (default "
                  << vbc_default << ")." << std::endl;
        std::cerr << "    --keys, -k <integer>:  Number of keys to create "
                     "(default "
                  << key_count_default << ")." << std::endl;
        std::cerr << "    --keys-per-vbucket:  The keys value is how many keys "
                     "for "
                     "each vbucket default "
                  << keys_per_vbucket_default << ")." << std::endl;
        std::cerr << "    --keys-per-flush, -f <integer>:  Number of keys per "
                     "vbucket before committing to disk (default "
                  << keys_per_flush_default << ")." << std::endl;
        std::cerr << "    --doc-len,-d <integer>:  Number of bytes for the "
                     "document "
                     "body (default "
                  << doc_len_default << ")." << std::endl;
        std::cerr << "    --doc-type,-t <binary|binarycompressed>:  Document "
                     "type."
                  << std::endl;
        std::cerr << "    --start-key,-s <integer>:  Specify the first key "
                     "number "
                     "(default "
                  << start_key_default << ")." << std::endl;
        std::cerr << "    --low-compression,-l: Generate documents that don't "
                     "compress well (default "
                  << low_compression_default << ")." << std::endl;
        std::cerr << "    --no-namespace: Don't namespace the file"
                  << std::endl;
        std::cerr << "    --namespace-id: Set the ID to use for namespace. "
                     "(default "
                  << collection_id_default << ")" << std::endl;

        std::cerr << std::endl
                  << "vbucket list (optional space separated values):"
                  << std::endl;
        std::cerr
                << "    Specify a list of vbuckets to manage and optionally "
                   "the "
                   "state. "
                << std::endl
                << "E.g. VB 1 can be specified as '1' (defaults to active when "
                   "creating vbuckets) or '1a' (for active) or '1r' (for "
                   "replica)."
                << std::endl
                << "Omiting the vbucket list means all vbuckets will be "
                   "created."
                << std::endl;

        std::cerr
                << "Two modes of operation:" << std::endl
                << "    1) Re-use vbuckets (--reuse or -r) \"Automatic mode\":"
                << std::endl
                << "    In this mode of operation the program will only write "
                   "key/values into vbucket files it finds in the current "
                   "directory."
                << std::endl
                << "    Ideally the vbucket files are empty of documents, but "
                   "must have a vbstate local doc."
                << std::endl
                << "    The intent of this mode is for a cluster and bucket to "
                   "be "
                   "pre-created, but empty and then to simply "
                << std::endl
                << "    populate the files found on each node without having "
                   "to "
                   "consider which are active/replica."
                << std::endl
                << std::endl;
        ;

        std::cerr
                << "    2) Create vbuckets:" << std::endl
                << "    In this mode of operation the program will create new "
                   "vbucket files. The user must make the decision about what "
                   "is "
                   "active/replica"
                << std::endl
                << std::endl;

        std::cerr << "Examples: " << std::endl;
        std::cerr
                << "  Create 1024 active vbuckets containing 10,000, 256 byte "
                   "binary documents."
                << std::endl;
        std::cerr << "    > ./couch_create -k 10000" << std::endl << std::endl;
        std::cerr << "  Iterate over 10,000 keys, but only generate vbuckets "
                     "0, 1, "
                     "2 and 3 with a mix of active/replica"
                  << std::endl;
        std::cerr << "    > ./couch_create -k 10000 0a 1r 2a 3r" << std::endl
                  << std::endl;
        std::cerr
                << "  Iterate over 10,000 keys and re-use existing couch-files"
                << std::endl;
        std::cerr << "    > ./couch_create -k 10000 -r" << std::endl
                  << std::endl;
        std::cerr << "  Create 10000 keys for each vbucket and re-use existing "
                     "couch-files"
                  << std::endl;
        std::cerr << "    > ./couch_create -k 10000 --keys-per-vbucket -r"
                  << std::endl
                  << std::endl;

        exit(exit_code);
    }

private:
    bool reuse_couch_files;
    int16_t vbc;
    uint64_t key_count;
    bool keys_per_vbucket;
    int keys_per_flush;
    int doc_len;
    DocType doc_type;
    std::vector<VBucketState> vbuckets;
    int vbuckets_managed;
    uint64_t start_key;
    bool low_compression;
    int flusher_count;
    bool namespaced{true};
    uint32_t collection_id{collection_id_default};
};

//
// Class representing a single couchstore document
//
class Document {
    class Meta {
    public:
        /// @param e expiry time
        /// @param f flags
        Meta(uint32_t e, uint32_t f)
            : cas(htonll(std::chrono::duration_cast<std::chrono::nanoseconds>(
                                 std::chrono::system_clock::now()
                                         .time_since_epoch())
                                 .count())),
              exptime(htonl(e)),
              flags(f),
              flex_meta_code(0x01),
              flex_value(0x0) {
        }

        void set_exptime(uint32_t exptime) {
            this->exptime = exptime;
        }

        void set_flags(uint32_t flags) {
            this->flags = flags;
        }

        size_t get_size() const {
            // Not safe to use sizeof(Meta) due to trailing padding
            return sizeof(cas) + sizeof(exptime) + sizeof(flags) +
                   sizeof(flex_meta_code) + sizeof(flex_value);
        }

    public:
        uint64_t cas;
        uint32_t exptime;
        uint32_t flags;
        uint8_t flex_meta_code;
        uint8_t flex_value;
    };

public:
    Document(const char* k, int klen, ProgramParameters& params, int dlen)
        : meta(0, 0),
          key_len(klen),
          key(nullptr),
          data_len(dlen),
          data(nullptr),
          parameters(params),
          doc_created(0) {
        key = new char[klen];
        data = new char[dlen];
        set_doc(k, klen, dlen);
        doc.id.buf = key;
        doc.id.size = klen;
        doc.data.buf = data;
        doc.data.size = dlen;
        doc_info.id = doc.id;
        doc_info.physical_size = doc.data.size;
        doc_info.db_seq = 0; // db_seq;
        doc_info.rev_seq = 1; // ++db_seq;

        if (params.get_doc_type() == BINARY_DOC_COMPRESSED) {
            doc_info.content_meta =
                    COUCH_DOC_NON_JSON_MODE | COUCH_DOC_IS_COMPRESSED;
        } else if (params.get_doc_type() == BINARY_DOC) {
            doc_info.content_meta = COUCH_DOC_NON_JSON_MODE;
        } else if (params.get_doc_type() == JSON_DOC_COMPRESSED) {
            doc_info.content_meta = COUCH_DOC_IS_JSON | COUCH_DOC_IS_COMPRESSED;
        } else if (params.get_doc_type() == JSON_DOC) {
            doc_info.content_meta = COUCH_DOC_IS_JSON;
        } else {
            doc_info.content_meta = COUCH_DOC_NON_JSON_MODE;
        }

        doc_info.rev_meta.buf = reinterpret_cast<char*>(&meta);
        doc_info.rev_meta.size = meta.get_size();
        doc_info.deleted = 0;
    }

    ~Document() {
        delete[] key;
        delete[] data;
    }

    void set_doc(const char* k, int klen, int dlen) {
        if (klen > key_len) {
            delete key;
            key = new char[klen];
            doc.id.buf = key;
            doc.id.size = klen;
            doc_info.id = doc.id;
        }
        if (dlen > data_len) {
            delete data;
            data = new char[dlen];
            doc.data.buf = data;
            doc.data.size = dlen;
        }

        memcpy(key, k, klen);
        // generate doc body only if size has changed.
        if (doc_created != dlen) {
            if (parameters.is_low_compression()) {
                srand(0);
                for (int data_index = 0; data_index < dlen; data_index++) {
                    char data_value = (rand() % 255) % ('Z' - '0');
                    data[data_index] = data_value + '0';
                }
            } else {
                char data_value = 0;
                for (int data_index = 0; data_index < dlen; data_index++) {
                    data[data_index] = data_value + '0';
                    data_value = (data_value + 1) % ('Z' - '0');
                }
            }
            doc_created = dlen;
        }
    }

    Doc* get_doc() {
        return &doc;
    }

    DocInfo* get_doc_info() {
        return &doc_info;
    }

private:
    Doc doc;
    DocInfo doc_info;
    Meta meta;

    int key_len;
    char* key;
    int data_len;
    char* data;
    ProgramParameters& parameters;
    int doc_created;
    static uint64_t db_seq;
};

uint64_t Document::db_seq = 0;

//
// A class representing a VBucket.
// This object holds a queue of key/values (documents) and manages their writing
// to the couch-file.
//
class VBucket {
public:
    class Exception1 : public std::exception {
        virtual const char* what() const throw() {
            return "Found an existing couch-file with vbstate and --reuse/-r "
                   "is not set.";
        }
    } exception1;

    class Exception2 : public std::exception {
        virtual const char* what() const throw() {
            return "Didn't find valid couch-file (or found file with no "
                   "vbstate) and --reuse/-r is set.";
        }
    } exception2;

    class Exception3 : public std::exception {
        virtual const char* what() const throw() {
            return "Error opening couch_file (check ulimit -n).";
        }
    } exception3;

    //
    // Constructor opens file and validates the state.
    // throws exceptions if not safe to continue
    //
    VBucket(char* filename,
            int vb,
            uint64_t& saved_counter,
            ProgramParameters& params_ref)
        : handle(nullptr),
          next_free_doc(0),
          flush_threshold(params_ref.get_keys_per_flush()),
          docs(params_ref.get_keys_per_flush()),
          pending_documents(0),
          documents_saved(saved_counter),
          params(params_ref),
          vbid(vb),
          doc_count(0),
          got_vbstate(false),
          vb_seq(0),
          ok_to_set_vbstate(true) {
        int flags = params.get_reuse_couch_files()
                            ? COUCHSTORE_OPEN_FLAG_RDONLY
                            : COUCHSTORE_OPEN_FLAG_CREATE;

        couchstore_error_t err = couchstore_open_db(filename, flags, &handle);
        if (err != COUCHSTORE_SUCCESS) {
            throw exception3;
        }

        if (read_vbstate()) {
            // A vbstate document exists.
            // Can only proceed if we're in reuse mode
            if (!params.get_reuse_couch_files()) {
                destroy();
                throw exception1;
            } else {
                // VB exists and is valid, close and open in write mode.
                destroy();
                couchstore_error_t err = couchstore_open_db(
                        filename, COUCHSTORE_OPEN_FLAG_CREATE, &handle);
                if (err != COUCHSTORE_SUCCESS) {
                    throw exception3;
                }
            }
        } else {
            if (params.get_reuse_couch_files()) {
                destroy();
                throw exception2;
            }
        }
        ok_to_set_vbstate = true;
    }

    ~VBucket() {
        save_docs();
        if (ok_to_set_vbstate) {
            set_vbstate(); // set/update local vbstate
        }
        docs.clear();
        destroy();
    }

    //
    // Return true if the special vbstate document is present.
    //
    bool read_vbstate() {
        LocalDoc* local_doc = nullptr;
        couchstore_error_t errCode =
                couchstore_open_local_document(handle,
                                               "_local/vbstate",
                                               sizeof("_local/vbstate") - 1,
                                               &local_doc);
        if (local_doc) {
            got_vbstate = true;
            vbstate_data.assign(local_doc->json.buf, local_doc->json.size);
            couchstore_free_local_document(local_doc);
        }
        return errCode == COUCHSTORE_SUCCESS;
    }

    //
    // Set the special vbstate document
    //
    void set_vbstate() {
        std::string state_string;
        if (got_vbstate) {
            if (vbstate_data.find("replica") != std::string::npos) {
                state_string = "replica";
            } else {
                state_string = "active";
            }
        } else {
            state_string = params.get_vbucket_state(vbid) == VB_ACTIVE
                                   ? "active"
                                   : "replica";
        }

        // Set max_cas to a timestamp
        auto now = std::chrono::system_clock::now();
        auto max_cas = std::chrono::duration_cast<std::chrono::nanoseconds>(
                               now.time_since_epoch())
                               .count();

        // looks like an upgrade from '6.0' to 6.5
        auto json = nlohmann::json{
                {"state", state_string},
                {"max_deleted_seqno", "0"},
                {"high_seqno", std::to_string(vb_seq)},
                {"purge_seqno", "0"},
                {"snap_start", std::to_string(vb_seq)},
                {"snap_end", std::to_string(vb_seq)},
                {"max_cas", std::to_string(max_cas)},
                {"hlc_epoch", "0"},
                {"might_contain_xattrs", false},
                {"namespaces_supported", params.is_namespaced()}};
        auto jsonState = json.dump();
        LocalDoc vbstate;
        vbstate.id.buf = (char*)"_local/vbstate";
        vbstate.id.size = sizeof("_local/vbstate") - 1;
        vbstate.json.buf = (char*)jsonState.c_str();
        vbstate.json.size = jsonState.size();
        vbstate.deleted = 0;

        couchstore_error_t errCode =
                couchstore_save_local_document(handle, &vbstate);
        if (errCode != COUCHSTORE_SUCCESS) {
            std::cerr << "Warning: couchstore_save_local_document failed error="
                      << couchstore_strerror(errCode) << std::endl;
        }
        couchstore_commit(handle);
    }

    //
    // Add a new key/value to the queue
    // Flushes the queue if has reached the flush_threshold.
    //
    void add_doc(char* k, int klen, int dlen) {
        if (docs[next_free_doc] == nullptr) {
            docs[next_free_doc] =
                    std::make_unique<Document>(k, klen, params, dlen);
        }

        docs[next_free_doc]->set_doc(k, klen, dlen);
        pending_documents++;
        doc_count++;
        vb_seq++;

        if (pending_documents == flush_threshold) {
            save_docs();
        } else {
            next_free_doc++;
        }
    }

    //
    // Save any pending documents to the couch file
    //
    void save_docs() {
        if (pending_documents) {
            std::vector<Doc*> doc_array(pending_documents);
            std::vector<DocInfo*> doc_info_array(pending_documents);

            for (int i = 0; i < pending_documents; i++) {
                doc_array[i] = docs[i]->get_doc();
                doc_info_array[i] = docs[i]->get_doc_info();
            }

            int flags = 0;

            if (params.get_doc_type() == JSON_DOC_COMPRESSED ||
                params.get_doc_type() == BINARY_DOC_COMPRESSED) {
                flags = COMPRESS_DOC_BODIES;
            }

            couchstore_save_documents(handle,
                                      doc_array.data(),
                                      doc_info_array.data(),
                                      pending_documents,
                                      flags);
            couchstore_commit(handle);
            documents_saved += pending_documents;
            next_free_doc = 0;
            pending_documents = 0;
        }
    }

    uint64_t get_doc_count() {
        return doc_count;
    }

private:
    void destroy() {
        couchstore_close_file(handle);
        couchstore_free_db(handle);
    }

    Db* handle;
    int next_free_doc;
    int flush_threshold;
    std::vector<std::unique_ptr<Document>> docs;
    int pending_documents;
    uint64_t& documents_saved;
    ProgramParameters& params;
    int vbid;
    uint64_t doc_count;
    std::string vbstate_data;
    bool got_vbstate;
    uint64_t vb_seq;
    bool ok_to_set_vbstate;
};

class VBucketFlusher {
public:
    VBucketFlusher(ProgramParameters& params)
        : started(false),
          documents_saved(0),
          parameters(params),
          task_thread(&VBucketFlusher::run, this) {
    }

    ~VBucketFlusher() {
    }

    void add_vbucket(uint16_t vbid) {
        my_vbuckets.insert(vbid);
    }

    void start() {
        while (!started) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        cvar.notify_one();
    }

    void join() {
        task_thread.join();
    }

    uint64_t get_documents_saved() {
        return documents_saved;
    }

private:
    void run() {
        std::unique_lock<std::mutex> lck(lock);
        started = true;
        cvar.wait(lck);

        std::vector<std::unique_ptr<VBucket>> vb_handles(parameters.get_vbc());
        uint64_t key_value = 0;

        bool start_counting_vbuckets = false;

        cb::mcbp::unsigned_leb128<uint32_t> collectionId(
                parameters.get_collection_id());
        uint64_t key_max = parameters.is_keys_per_vbucket()
                                   ? ULLONG_MAX
                                   : parameters.get_key_count();

        // Loop through the key space and create keys, test each key to see if
        // we are managing the vbucket it maps to.
        for (uint64_t ii = parameters.get_start_key();
             ii < (key_max + parameters.get_start_key());
             ii++) {
            std::string documentKey;
            documentKey.reserve(64);
            if (parameters.is_namespaced()) {
                std::copy(collectionId.begin(),
                          collectionId.end(),
                          back_inserter(documentKey));
            }

            char logicalKey[64];
            int logicalKeyLen =
                    snprintf(logicalKey, 64, "K%020" PRId64, key_value);
            int vbid = client_hash_crc32(
                               reinterpret_cast<const uint8_t*>(logicalKey),
                               logicalKeyLen) %
                       (parameters.get_vbc());

            documentKey.append(logicalKey);

            // Only if the vbucket is managed generate the doc
            if (my_vbuckets.count(vbid) > 0 &&
                parameters.is_vbucket_managed(vbid)) {
                if (vb_handles[vbid] == nullptr) {
                    char filename[32];
                    snprintf(filename, 32, "%d.couch.1", vbid);
                    start_counting_vbuckets = true;
                    try {
                        vb_handles[vbid] = std::make_unique<VBucket>(
                                filename, vbid, documents_saved, parameters);
                    } catch (std::exception& e) {
                        std::unique_lock<std::mutex> print_lck(print_lock);
                        std::cerr << "Not creating a VB handler for "
                                  << filename << " \"" << e.what() << "\""
                                  << std::endl;
                        parameters.disable_vbucket(vbid);
                        vb_handles[vbid].reset();
                    }
                }

                // if there's now a handle, go for it
                if (vb_handles[vbid] != nullptr) {
                    vb_handles[vbid]->add_doc(documentKey.data(),
                                              documentKey.size(),
                                              parameters.get_doc_len());

                    // If we're generating keys per vbucket, stop managing this
                    // vbucket when we've it the limit
                    if (parameters.is_keys_per_vbucket() &&
                        (vb_handles[vbid]->get_doc_count() ==
                         parameters.get_key_count())) {
                        vb_handles[vbid].reset(); // done with this VB
                        parameters.disable_vbucket(vbid);
                    }
                }
            }
            key_value++;

            // Stop when there's no more vbuckets managed, yet we're past
            // starting
            if (start_counting_vbuckets &&
                parameters.get_vbuckets_managed() == 0) {
                break;
            }
        }

        vb_handles.clear();
    }

    std::atomic<bool> started;
    uint64_t documents_saved;
    ProgramParameters& parameters;
    std::set<uint16_t> my_vbuckets;
    std::deque<VBucket*> work_queue;
    std::mutex lock;
    static std::mutex print_lock;
    std::condition_variable cvar;
    std::thread task_thread;
};

std::mutex VBucketFlusher::print_lock;

int main(int argc, char** argv) {
    ProgramParameters parameters;
    parameters.load(argc, argv);
    if (!parameters.validate()) {
        return 1;
    }

    char key[64];
    uint64_t key_max = parameters.is_keys_per_vbucket()
                               ? ULLONG_MAX
                               : parameters.get_key_count();
    std::cout << "Generating " << parameters.get_key_count() << " keys ";
    if (parameters.is_keys_per_vbucket()) {
        std::cout << "per VB";
    }
    std::cout << std::endl;
    if (parameters.get_key_count() > 1) {
        std::cout << "Key pattern is ";
        snprintf(key,
                 64,
                 "K%020" PRId64,
                 (uint64_t)0 + parameters.get_start_key());
        std::cout << key << " to ";
        snprintf(key,
                 64,
                 "K%020" PRId64,
                 (uint64_t)((key_max + parameters.get_start_key()) - 1));
        std::cout << key << std::endl;
    } else {
        std::cout << "Key pattern is K00000000000000000000" << std::endl;
    }

    std::cout << "vbucket count set to " << parameters.get_vbc() << std::endl;
    std::cout << "keys per flush set to " << parameters.get_keys_per_flush()
              << std::endl;
    std::cout << "Document type is " << parameters.get_doc_len() << " bytes "
              << parameters.get_doc_type_string() << std::endl;

    if (parameters.get_reuse_couch_files()) {
        std::cout << "Re-using any existing couch-files" << std::endl;
    } else {
        std::cout << "Creating new couch-files" << std::endl;
    }

    std::vector<std::unique_ptr<VBucketFlusher>> vb_flushers(
            parameters.get_flusher_count());
    uint64_t documents_saved = 0;

    // loop through VBs and distribute to flushers.
    for (int vbid = 0; vbid < parameters.get_vbc(); vbid++) {
        if (parameters.is_vbucket_managed(vbid)) {
            if (vb_flushers[vbid % parameters.get_flusher_count()] == nullptr) {
                vb_flushers[vbid % parameters.get_flusher_count()] =
                        std::make_unique<VBucketFlusher>(parameters);
            }
            vb_flushers[vbid % parameters.get_flusher_count()]->add_vbucket(
                    vbid);
        }
    }

    for (auto& flusher : vb_flushers) {
        if (flusher.get()) {
            flusher->start();
        }
    }

    for (auto& flusher : vb_flushers) {
        if (flusher.get()) {
            flusher->join();
            documents_saved += flusher->get_documents_saved();
        }
    }

    std::cout << "Saved " << documents_saved << " documents " << std::endl;

    vb_flushers.clear();
    return 0;
}
