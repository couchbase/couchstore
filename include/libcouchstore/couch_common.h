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
#pragma once

#include <fcntl.h>
#include <sys/types.h>
#include <cstdint>

#include <libcouchstore/visibility.h>


    /**
     * Using off_t turned out to be a real challenge. On "unix-like" systems
     * its size is set by a combination of #defines like: _LARGE_FILE,
     * _FILE_OFFSET_BITS and/or _LARGEFILE_SOURCE etc. The interesting
     * part is however Windows.
     *
     * Windows follows the LLP64 data model:
     * http://en.wikipedia.org/wiki/LLP64#64-bit_data_models
     *
     * This means both the int and long int types have a size of 32 bits
     * regardless if it's a 32 or 64 bits Windows system.
     *
     * And Windows defines the type off_t as being a signed long integer:
     * http://msdn.microsoft.com/en-us/library/323b6b3k.aspx
     *
     * This means we can't use off_t on Windows if we deal with files
     * that can have a size of 2Gb or more.
     */
    using cs_off_t = int64_t;

    /** Document content metadata flags */
    using couchstore_content_meta_flags = uint8_t;
    enum {
        COUCH_DOC_IS_COMPRESSED = 128,  /**< Document contents compressed via Snappy */
        /* Content Type Reasons (content_meta & 0x0F): */
        COUCH_DOC_IS_JSON = 0,      /**< Document is valid JSON data */
        COUCH_DOC_INVALID_JSON = 1, /**< Document was checked, and was not valid JSON */
        COUCH_DOC_INVALID_JSON_KEY = 2, /**< Document was checked, and contained reserved keys,
                                             was not inserted as JSON. */
        COUCH_DOC_NON_JSON_MODE = 3 /**< Document was not checked (DB running in non-JSON mode) */
    };

    enum couchstore_file_advice_t {
#ifdef POSIX_FADV_NORMAL
        /* Evict this range from FS caches if possible */
        COUCHSTORE_FILE_ADVICE_EVICT = POSIX_FADV_DONTNEED
#else
        /* Assign these whatever values, we'll be ignoring them.. */
        COUCHSTORE_FILE_ADVICE_EVICT
#endif
    };

    /// Different types of data contained in a couchstore file.
    enum class FileTag : uint8_t {
        Empty, // Ignore this access; speculative (e.g. searching for header).
        FileHeader, // File header.
        BTree, // Generic B-Tree
        Document, // User document data.
        Unknown, // Valid access, but unknown what for.
    };

    /** A generic data blob. Nothing is implied about ownership of the block pointed to. */
    struct sized_buf {
        char* buf{nullptr};
        size_t size{0};
    };

    /** A CouchStore document, consisting of an ID (key) and data, each of which is a blob. */
    struct Doc {
        sized_buf id;
        sized_buf data;
    };

    /** Metadata of a CouchStore document. */
    struct DocInfo {
        /// @return the total size, that is value+key+metadata
        size_t getTotalSize() const {
            return physical_size + id.size + rev_meta.size;
        }

        /**< Document ID (key) */
        sized_buf id;
        /**< Sequence number in database */
        uint64_t db_seq{0};
        /**< Revision number of document */
        uint64_t rev_seq{0};
        /**< Revision metadata; uninterpreted by CouchStore.
           Needs to be kept small enough to fit in a B-tree index.*/
        sized_buf rev_meta;
        /**< Is this a deleted revision? */
        int deleted{0};
        /**< Content metadata flags */
        couchstore_content_meta_flags content_meta{0};
        /**< Byte offset of document data in file */
        uint64_t bp{0};
        /**< Physical space occupied by data (*not* its length) */
        size_t physical_size{0};
    };

#define DOC_INITIALIZER { {0, 0}, {0, 0} }
#define DOC_INFO_INITIALIZER { {0, 0}, 0, 0, {0, 0}, 0, 0, 0, 0 }

    /** Contents of a 'local' (unreplicated) document. */
    struct LocalDoc {
        sized_buf id;
        sized_buf json;
        int deleted;
    };

    /** Information about the database as a whole. */
    struct DbInfo {
        const char* filename;       /**< Filesystem path */
        uint64_t last_sequence;     /**< Last sequence number allocated */
        uint64_t doc_count;         /**< Total number of (non-deleted) documents */
        uint64_t deleted_count;     /**< Total number of deleted documents */
        uint64_t space_used;        /**< Disk space actively used by docs */
        uint64_t file_size;         /**< Total disk space used by database */
        cs_off_t header_position;   /**< File offset of current header */
        uint64_t purge_seq;         /**< Last Purge sequence number */
    };

    /** Opaque reference to an open database. */
    struct Db;
