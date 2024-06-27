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
#define COUCHSTORE_COUCH_DB_H

#include "couch_common.h"
#include <libcouchstore/error.h>
#include <libcouchstore/file_ops.h>

#include <cbcrypto/common.h>

#include <functional>
#include <memory>
#include <optional>
#include <system_error>

namespace cb::couchstore {

using SharedEncryptionKey =
        std::shared_ptr<const cb::crypto::DataEncryptionKey>;

/**
 * Callback that returns the encryption key that decrypts the per file key,
 * or null if encryption should not be used or the requested key was not found.
 *
 * @param keyId Requested key id or empty when creating a file
 */
using EncryptionKeyGetter =
        std::function<SharedEncryptionKey(std::string_view keyId)>;

} // namespace cb::couchstore

extern "C" {

    /*///////////////////  OPENING/CLOSING DATABASES: */

    /**
     * Flags to pass as the flags parameter to couchstore_open_db
     */
    using couchstore_open_flags = uint64_t;

    /**
     * Create a new empty .couch file if file doesn't exist.
     */
    constexpr couchstore_open_flags COUCHSTORE_OPEN_FLAG_CREATE = 1;

    /**
     * Open the database in read only mode
     */
    constexpr couchstore_open_flags COUCHSTORE_OPEN_FLAG_RDONLY = 2;

    /**
     * Require the database to use the legacy CRC.
     * This forces the disk_version flag to be 11 and is only valid for new
     * files and existing version 11 files. When excluded the correct CRC is
     * automatically chosen for existing files. When excluded the latest
     * file version is always used for new files.
     */
    constexpr couchstore_open_flags COUCHSTORE_OPEN_WITH_LEGACY_CRC = 4;

    /**
     * Open the database file without using an IO buffer
     *
     * This prevents the FileOps that are used in from being
     * wrapped by the buffered file operations. This will
     * *usually* result in performance degradation and is
     * primarily intended for testing purposes.
     */
    constexpr couchstore_open_flags COUCHSTORE_OPEN_FLAG_UNBUFFERED = 8;

    /**
     * Ensures that the call to open() creates the file.
     * If the file already exists then open() fails with the error EEXIST.
     *
     * !! Note: Must be used in conjunction with O_CREAT, the behaviour of
     * open() is undefined otherwise.
     */
    constexpr couchstore_open_flags COUCHSTORE_OPEN_FLAG_EXCL = 16;

    /**
     * Don't write the header when creating the database file.
     *
     * Allows to write items before writing the header.
     */
    constexpr couchstore_open_flags COUCHSTORE_OPEN_FLAG_NO_COMMIT_AT_CREATE =
            32;

    /**
     * Customize IO buffer configurations.
     *
     * This specifies the capacity of a read buffer and its count.
     * The first 4 bits are for the capacity; that will be calculated as:
     *     1KB * 1 << (N-1)
     * And the next 4 bits are for the count:
     *     8 * 1 << (N-1)
     * Note that all zeros represent the default setting.
     */
    constexpr couchstore_open_flags COUCHSTORE_OPEN_WITH_CUSTOM_BUFFER = 0xff00;

    /**
     * Customize B+tree node size.
     *
     * This specifies the size of B+tree node.
     * The first 4 bits represents the size of key-pointer
     * (i.e., intermediate) nodes in KB, and the next 4 bits denotes
     * the size of key-value (i.e., leaf) nodes in KB.
     * Note that all zeros represent the default setting,
     * 1279 (0x4ff) bytes.
     */
    constexpr couchstore_open_flags COUCHSTORE_OPEN_WITH_CUSTOM_NODESIZE =
            0xff0000;

    /**
     * Enable periodic sync().
     *
     * Automatically perform a sync() call after every N bytes written.
     *
     * When writing large amounts of data (e.g during compaction), read
     * latency can be adversely affected if a single sync() is made at the
     * end of writing all the data, as the IO subsystem has a large amount
     * of outstanding writes to flush to disk. By issuing periodic syncs
     * the affect on read latency can be signifcantly reduced.
     *
     * Encoded as a power-of-2 KB value, ranging from 1KB .. 1TB (5 bits):
     *     1KB * << (N-1)
     *
     * A value of N=0 specifies that automatic fsync is disabled.
     */
    constexpr couchstore_open_flags COUCHSTORE_OPEN_WITH_PERIODIC_SYNC =
            0x1f000000;

    /**
     * Enable tracing and verification.
     *
     * Flags to turn on tracing and perform other validations to
     * help detect corruption.
     *
     * The operations performed on a couchstore file can be traced using
     * the phoshpor tracing library.
     * Checks to validate data that was written was passed on correctly to
     * OS. If needed, the internal iobuffer can be used in a protected mode
     * and trigger a fault if accessed by other threads.
     *
     * TRACING          - 0x20000000 Enable tracing
     * WRITE_VALIDATION - 0x40000000 validation of data writes
     * MPROTECT         - 0x60000000 mprotect of internal iobuffer
     */
    constexpr couchstore_open_flags COUCHSTORE_OPEN_WITH_TRACING = 0x20000000;
    constexpr couchstore_open_flags COUCHSTORE_OPEN_WITH_WRITE_VALIDATION =
            0x40000000;
    constexpr couchstore_open_flags COUCHSTORE_OPEN_WITH_MPROTECT = 0x800000000;

    /**
     * Encode a periodic sync specified in bytes to the correct
     * couchstore_open_flags encoding.
     * @param fsync period in bytes
     * @return encoded open_flags value, ranging from 1KB to 1TB. Rounded down
     *         to nearest power-of-2.
     */
    LIBCOUCHSTORE_API
    couchstore_open_flags couchstore_encode_periodic_sync_flags(uint64_t bytes);

    /**
     * Open a database.
     *
     * The database should be closed with couchstore_close_db().
     *
     * @param filename The name of the file containing the database
     * @param flags Additional flags for how the database should
     *              be opened. See couchstore_open_flags_* for the
     *              available flags.
     * @param db Pointer to where you want the handle to the database to be
     *           stored.
     * @return COUCHSTORE_SUCCESS for success
     */
    LIBCOUCHSTORE_API
    couchstore_error_t couchstore_open_db(const char *filename,
                                          couchstore_open_flags flags,
                                          Db **db);

    /**
     * Open a database, with custom I/O callbacks.
     *
     * The database should be closed with couchstore_close_db().
     *
     * @param filename The name of the file containing the database
     * @param flags Additional flags for how the database should
     *              be opened. See couchstore_open_flags_* for the
     *              available flags.
     * @param encryptionKeyCB Callback that returns the encryption key that
     *                        decrypts the per file key
     * @param ops Pointer to the implementation of FileOpsInterface
     *            you want the library to use.
     * @param db Pointer to where you want the handle to the database to be
     *           stored.
     * @return COUCHSTORE_SUCCESS for success
     */
    LIBCOUCHSTORE_API
    couchstore_error_t couchstore_open_db_ex(
            const char* filename,
            couchstore_open_flags flags,
            cb::couchstore::EncryptionKeyGetter encryptionKeyCB,
            FileOpsInterface* ops,
            Db** db);

    /**
     * Release all resources held by the database handle after the file
     * has been closed.
     *
     * This should be called *after* couchstore_close_file(db).
     *
     * @param db Pointer to the database handle to free.
     * @return COUCHSTORE_SUCCESS upon success
     */
    LIBCOUCHSTORE_API
    couchstore_error_t couchstore_free_db(Db* db);


    /**
     * Close the file handle associated with this database handle.
     *
     * This does not free the resources held by the database handle. These
     * resources should be released by subsequently calling
     * couchstore_free_db(db).
     *
     * @param db Pointer to the database handle to drop the file from.
     * @return COUCHSTORE_SUCCESS upon success
     */
    LIBCOUCHSTORE_API
    couchstore_error_t couchstore_close_file(Db* db);

    /**
     * Rewind a db handle to the next-oldest header still present in the file.
     * If there is no next-oldest header, the db handle will be *closed*, and
     * COUCHSTORE_DB_NO_LONGER_VALID will be returned.
     *
     * @param db The database handle to rewind
     * @return COUCHSTORE_SUCCESS upon success, COUCHSTORE_DB_NO_LONGER_VALID if
     * no next-oldest header was found.
     */
    LIBCOUCHSTORE_API
    couchstore_error_t couchstore_rewind_db_header(Db *db);

    /**
     * Fast forward a db handle to the next header present in the file.
     * If there is no next header, the db handle will be *closed*, and
     * COUCHSTORE_DB_NO_LONGER_VALID will be returned.
     *
     * @param db The database handle to fast forward
     * @return COUCHSTORE_SUCCESS upon success, COUCHSTORE_DB_NO_LONGER_VALID if
     *         no header was found.
     */
    LIBCOUCHSTORE_API
    couchstore_error_t couchstore_fastforward_db_header(Db* db);

    /**
     * Get the default FileOpsInterface object
     */
    LIBCOUCHSTORE_API
    FileOpsInterface* couchstore_get_default_file_ops(void);

    /**
     * Get information about the database.
     *
     * @param db Pointer to the database handle.
     * @param info Pointer to where you want the info to be stored.
     * @return COUCHSTORE_SUCCESS upon success
     */
    LIBCOUCHSTORE_API
    couchstore_error_t couchstore_db_info(Db *db, DbInfo* info);


    /**
     * Returns the filename of the database, as given when it was opened.
     *
     * @param db Pointer to the database handle.
     * @return Pointer to filename (path). This is an exact copy of the filename given to
     *         couchstore_open_db.
     */
    LIBCOUCHSTORE_API
    const char* couchstore_get_db_filename(Db *db);

    /**
     * Return file handle statistics of the database's underlying file handle.
     *
     * @return A non-null pointer to a FileStats instance if the
     *         database's file ops support file statistics, otherwise
     *         returns nullptr.
     */
    LIBCOUCHSTORE_API
    FileOpsInterface::FHStats* couchstore_get_db_filestats(Db* db);

    /**
     * Get the position in the file of the mostly recently written
     * database header.
     */
    LIBCOUCHSTORE_API
    uint64_t couchstore_get_header_position(Db *db);


    /*////////////////////  WRITING DOCUMENTS: */

    /*
     * Options used by couchstore_save_document() and
     * couchstore_save_documents():
     */
    typedef uint64_t couchstore_save_options;
    enum {
        /**
         * Snappy compress document data if the high bit of the
         * content_meta field of the DocInfo is set. This is NOT the
         * default, and if this is not set the data field of the Doc will
         * be written to disk as-is, regardless of the content_meta flags.
         */
        COMPRESS_DOC_BODIES = 1,
        /**
         * Store the DocInfo's passed in db_seq as is.
         *
         * Couchstore will *not* assign it a new sequence number, but store the
         * sequence number as given. The update_seq for the DB will be set to
         * at least this sequence.
         * */
        COUCHSTORE_SEQUENCE_AS_IS = 2
    };

    /**
     * Save document pointed to by doc and docinfo to db.
     *
     * When saving documents you should only set the id, rev_meta,
     * rev_seq, deleted, and content_meta fields on the DocInfo.
     *
     * To delete a docuemnt, set doc to NULL.
     *
     * On return, the db_seq field of the DocInfo will be filled in with the
     * document's (or deletion's) sequence number.
     *
     * @param db database to save the document in
     * @param doc the document to save
     * @param info document info
     * @param options see descrtiption of COMPRESS_DOC_BODIES below
     * @return COUCHSTORE_SUCCESS upon success
     */
    LIBCOUCHSTORE_API
    couchstore_error_t couchstore_save_document(Db *db,
                                                const Doc *doc,
                                                DocInfo *info,
                                                couchstore_save_options options);

    /**
     * Save array of docs to db
     *
     * To delete documents, set docs to NULL: the docs referenced by
     * the docinfos will be deleted. To intermix deletes and inserts
     * in a bulk update, pass docinfos with the deleted flag set.
     *
     * On return, the db_seq fields of the DocInfos will be filled in with the
     * documents' (or deletions') sequence numbers.
     *
     * @param db the database to save documents in
     * @param docs an array of document pointers
     * @param infos an array of docinfo pointers
     * @param numDocs the number documents to save
     * @param options see descrtiption of COMPRESS_DOC_BODIES below
     * @return COUCHSTORE_SUCCESS upon success
     */
    LIBCOUCHSTORE_API
    couchstore_error_t couchstore_save_documents(Db *db,
                                                 Doc* const docs[],
                                                 DocInfo *infos[],
                                                 unsigned numDocs,
                                                 couchstore_save_options options);

    /**
     * Callback type for couchstore_save_documents_and_callback.
     * For each input key into couchstore_save_documents_and_callback the
     * callback is invoked with DocInfo for the new and maybe old.
     *
     * @param oldInfo Old doc, expected to be nullptr if callback for an insert
     * @param newInfo New doc
     * @param ctx
     * @param userReq Pointer to the user request
     */
    typedef void (*save_callback_fn)(const DocInfo* oldInfo,
                                     const DocInfo* newInfo,
                                     void* ctx,
                                     void* userReq);

    /**
     * Save array of docs to db and optionally get called back about how the key
     * enters the database.
     *
     * To delete documents, set docs to NULL: the docs referenced by
     * the docinfos will be deleted. To intermix deletes and inserts
     * in a bulk update, pass docinfos with the deleted flag set.
     *
     * On return, the db_seq fields of the DocInfos will be filled in with the
     * documents' (or deletions') sequence numbers.
     *
     * @param db the database to save documents in
     * @param docs an array of document pointers
     * @param infos an array of docinfo pointers
     * @param numDocs the number documents to save
     * @param options see description of COMPRESS_DOC_BODIES below
     * @param save_cb an optional callback, every key processed will trigger a
     *        callback containing the key its updated_how value and the
     *        save_cb_ctx.
     * @param save_cb_ctx optional void* context for the save_cb
     * @param userReqs Array of pointers to the user requests
     * @return COUCHSTORE_SUCCESS upon success
     */
    LIBCOUCHSTORE_API
    couchstore_error_t couchstore_save_documents_and_callback(
            Db* db,
            const Doc* const docs[],
            DocInfo* const infos[],
            void* const userReqs[],
            unsigned numDocs,
            couchstore_save_options options,
            save_callback_fn save_cb,
            void* save_cb_ctx);

    /**
     * User-defined callback that will be executed when couchstore_commit fails.
     * Allows the user to decide whether they want couchstore to re-try the
     * operation or just return to the caller.
     *
     * @return false if the user just wants couchstore to return the error code;
     *         true if the user wants couchstore to re-try the operation
     */
    using SysErrorCallback = std::function<bool(const std::system_error&)>;

    /**
     * Commit all pending changes and flush buffers to persistent storage
     * (and set the "timestamp" to the number of nanoseconds since epoch
     * reported by the steady clock)
     *
     * @param db database to perform the commit on
     * @param callback Called if the sync-header phase fails
     * @return COUCHSTORE_SUCCESS on success
     */
    LIBCOUCHSTORE_API
    couchstore_error_t couchstore_commit(Db* db,
                                         const SysErrorCallback& callback = {});

    /**
     * Commit all pending changes and flush buffers to persistent storage.
     *
     * @param db database to perform the commit on
     * @param timestamp a "number" the application may use to represent
     *                  its logical "timestamp" of when the data was written.
     * @param callback Called if the sync-header phase fails
     * @return COUCHSTORE_SUCCESS on success
     */
    LIBCOUCHSTORE_API
    couchstore_error_t couchstore_commit_ex(
            Db* db, uint64_t timestamp, const SysErrorCallback& callback = {});

    /*////////////////////  RETRIEVING DOCUMENTS: */

    /**
     * Retrieve the document info for a given key.
     *
     * The info should be freed with couchstore_free_docinfo().
     *
     * @param id the document identifier
     * @param idlen the number of bytes in the identifier
     * @param pInfo where to store the result
     * @return COUCHSTORE_SUCCESS on success.
     */
    LIBCOUCHSTORE_API
    couchstore_error_t couchstore_docinfo_by_id(Db *db,
                                                const void *id,
                                                size_t idlen,
                                                DocInfo **pInfo);

    /**
     * Retrieve the document info for a given sequence number.
     *
     * To look up multiple sequences, it's more efficient to call couchstore_docinfos_by_sequence.
     *
     * @param sequence the document sequence number
     * @param pInfo where to store the result. Must be freed with couchstore_free_docinfo().
     * @return COUCHSTORE_SUCCESS on success.
     */
    LIBCOUCHSTORE_API
    couchstore_error_t couchstore_docinfo_by_sequence(Db *db,
                                                      uint64_t sequence,
                                                      DocInfo **pInfo);

    /** Options flags for open_doc and open_doc_with_docinfo */
    typedef uint64_t couchstore_open_options;
    enum {
        /* Snappy decompress document data if the high bit of the content_meta field
         * of the DocInfo is set.
         * This is NOT the default, and if this is not set the data field of the Doc
         * will be read from disk as-is, regardless of the content_meta flags. */
        DECOMPRESS_DOC_BODIES = 1
    };

    /**
     * Retrieve a doc from the db.
     *
     * The document should be freed with couchstore_free_document()
     *
     * On a successful return, doc.id.buf will point to the id you passed in,
     * so don't free or overwrite the id buffer before freeing the document!
     *
     * @param db database to load document from
     * @param id the identifier to load
     * @param idlen the number of bytes in the id
     * @param pDoc Where to store the result
     * @param options See DECOMPRESS_DOC_BODIES
     * @return COUCHSTORE_SUCCESS if found
     */
    LIBCOUCHSTORE_API
    couchstore_error_t couchstore_open_document(Db *db,
                                                const void *id,
                                                size_t idlen,
                                                Doc **pDoc,
                                                couchstore_open_options options);

    /**
     * Retrieve a doc from the db, using a DocInfo.
     * The DocInfo must have been filled in with valid values by an API call such
     * as couchstore_docinfo_by_id().
     *
     * Do not free the docinfo before freeing the doc, with couchstore_free_document().
     *
     * @param db database to load document from
     * @param docinfo a valid DocInfo, as filled in by couchstore_docinfo_by_id()
     * @param pDoc Where to store the result
     * @param options See DECOMPRESS_DOC_BODIES
     * @return COUCHSTORE_SUCCESS if found
     */
    LIBCOUCHSTORE_API
    couchstore_error_t couchstore_open_doc_with_docinfo(Db *db,
                                                        const DocInfo *docinfo,
                                                        Doc **pDoc,
                                                        couchstore_open_options options);

    /**
     * Free all allocated resources from a document returned from
     * couchstore_open_document().
     *
     * @param doc the document to free. May be NULL.
     */
    LIBCOUCHSTORE_API
    void couchstore_free_document(Doc *doc);


    /**
     * Allocates a new DocInfo structure on the heap, plus optionally its id and rev_meta.
     * If the id or rev_meta are given, their values will be copied into the allocated memory
     * and the corresponding fields in the returned DocInfo will point there. Otherwise the
     * DocInfo's id and/or rev_meta fields will be empty/null.
     * @param id the document ID to copy into the DocInfo, or NULL to leave its ID NULL.
     * @param rev_meta the revision metadata to copy into the DocInfo, or NULL to leave its
     *          rev_meta NULL.
     * @return the allocated DocInfo, or NULL on an allocation failure. Must be freed by
     *          calling couchstore_free_docinfo.
     */
    LIBCOUCHSTORE_API
    DocInfo* couchstore_alloc_docinfo(const sized_buf *id,
                                      const sized_buf *rev_meta);


    /**
     * Free all allocated resources from a docinfo structure returned by
     * couchstore_docinfo_by_id() or passed to a couchstore_changes_callback_fn.
     *
     * @param docinfo the document info to free. May be NULL.
     */
    LIBCOUCHSTORE_API
    void couchstore_free_docinfo(DocInfo *docinfo);


    /*////////////////////  ITERATING DOCUMENTS: */

    /**
     * The callback function used by couchstore_changes_since(), couchstore_docinfos_by_id()
     * and couchstore_docinfos_by_sequence() to iterate through the documents.
     *
     * The docinfo structure is automatically freed if the callback
     * returns 0. A positive return value will preserve the DocInfo
     * for future use (should be freed with free_docinfo by the
     * caller). A negative return value will cancel the iteration and
     * pass the error value back to the caller.
     *
     * @param db the database being traversed
     * @param docinfo the current document
     * @param ctx user context
     * @return 1 to preserve the DocInfo, 0 or negative error value to free it (see above).
     */
    typedef int (*couchstore_changes_callback_fn)(Db *db,
                                                  DocInfo *docinfo,
                                                  void *ctx);

    /** Options flags for document iteration */
    typedef uint64_t couchstore_docinfos_options;
    enum {
        /* If set, the sequences/ids lists are interpreted as pairs of range endpoints,
         * and all documents within those ranges will be iterated over.
         */
        RANGES = 1,
        /**
         * Send only deleted items.
         */
        COUCHSTORE_DELETES_ONLY = 2,
        /**
         * Send only non-deleted items.
         */
        COUCHSTORE_NO_DELETES = 4,
        /**
         * If set, corrupted B+tree nodes or documents will be tolerated
         * to collect as much data as possible.
         */
        COUCHSTORE_TOLERATE_CORRUPTION = 8
    };

    /**
     * Iterate through the changes since sequence number `since`.
     *
     * @param db the database to iterate through
     * @param since the sequence number to start iterating from
     * @param options COUCHSTORE_DELETES_ONLY and COUCHSTORE_NO_DELETES are supported
     * @param callback the callback function used to iterate over all changes
     * @param ctx client context (passed to the callback)
     * @return COUCHSTORE_SUCCESS upon success
     */
    LIBCOUCHSTORE_API
    couchstore_error_t couchstore_changes_since(Db *db,
                                                uint64_t since,
                                                couchstore_docinfos_options options,
                                                couchstore_changes_callback_fn callback,
                                                void *ctx);

    /**
     * Iterate through all documents in order by key.
     *
     * @param db the database to iterate through
     * @param startKeyPtr  The key to start at, or NULL to start from the beginning
     * @param options COUCHSTORE_DELETES_ONLY and COUCHSTORE_NO_DELETES are supported
     * @param callback the callback function used to iterate over all documents
     * @param ctx client context (passed to the callback)
     * @return COUCHSTORE_SUCCESS upon success
     */
    LIBCOUCHSTORE_API
    couchstore_error_t couchstore_all_docs(Db *db,
                                           const sized_buf* startKeyPtr,
                                           couchstore_docinfos_options options,
                                           couchstore_changes_callback_fn callback,
                                           void *ctx);

    /**
     * Iterate over the document infos of a set of sequence numbers.
     *
     * The DocInfos will be presented to the callback in order of ascending sequence
     * number, *not* in the order in which they appear in the sequence[] array.
     *
     * If the RANGES option flag is set, the sequences array is interpreted as
     * alternating begin/end points of ranges, and all DocInfos within those ranges
     * are iterated over. (If there is an odd number of sequences, the iteration will
     * stop at the last sequence.)
     *
     * The callback will not be invoked for nonexistent sequence numbers.
     *
     * @param sequence array of document sequence numbers. Need not be sorted but must not contain
     *          duplicates.
     * @param numDocs number of documents to look up (size of sequence[] array)
     * @param options Set the RANGES bit for range mode (see above)
     * @param callback the callback function used to iterate over document infos
     * @param ctx client context (passed to the callback)
     * @return COUCHSTORE_SUCCESS on success.
     */
    LIBCOUCHSTORE_API
    couchstore_error_t couchstore_docinfos_by_sequence(Db *db,
                                                       const uint64_t sequence[],
                                                       unsigned numDocs,
                                                       couchstore_docinfos_options options,
                                                       couchstore_changes_callback_fn callback,
                                                       void *ctx);

    /**
     * Iterate over the document infos of a set of ids.
     *
     * The DocInfos will be presented to the callback in order of ascending
     * document id, *not* in the order in which they appear in the ids[] array.
     *
     * If the RANGES option flag is set, the ids array is expected to store
     * begin/end keys describing inclusive ranges of documents. All DocInfos
     * with IDs within those ranges are iterated over. (If there is an odd
     * number of IDs, the iteration will stop at the last ID.)
     *
     * The callback will not be invoked for nonexistent ids.
     *
     * @param ids array of document ids. Need not be sorted but must not contain
     *          duplicates.
     * @param numDocs number of documents to look up (size of ids[] array)
     * @param options Set the RANGES bit for range mode (see above)
     * @param callback the callback function used to iterate over document infos
     * @param ctx client context (passed to the callback)
     * @return COUCHSTORE_SUCCESS on success.
     */
    LIBCOUCHSTORE_API
    couchstore_error_t couchstore_docinfos_by_id(Db *db,
                                                 const sized_buf ids[],
                                                 unsigned numDocs,
                                                 couchstore_docinfos_options options,
                                                 couchstore_changes_callback_fn callback,
                                                 void *ctx);

    /*////////////////////  ITERATING TREES: */

    /**
     * The callback function used by couchstore_walk_id_tree() and couchstore_walk_seq_tree()
     * to iterate through the B-tree.
     *
     * This function is called both for documents and tree nodes. reduce_value will be non-NULL
     * for a node; doc_info will be non-NULL for a document.
     *
     * The docinfo structure is automatically freed if the callback
     * returns 0. A positive return value will preserve the DocInfo
     * for future use (should be freed with free_docinfo by the
     * caller). A negative return value will cancel the iteration and
     * pass the error value back to the caller.
     *
     * @param db the database being traversed
     * @param depth the current depth in the tree (the root node is 0, and documents are one level
     *          deeper than their leaf nodes)
     * @param doc_info the current document, or NULL if this is a tree node
     * @param subtree_size the on-disk size of this tree node and its children, or 0 for a document
     * @param reduce_value the reduce data of this node, or NULL for a document
     * @param ctx user context
     * @return 1 to preserve the DocInfo, 0 to free it, or a negative error code to abort iteration.
     */
    typedef int (*couchstore_walk_tree_callback_fn)(Db *db,
                                                    int depth,
                                                    const DocInfo* doc_info,
                                                    uint64_t subtree_size,
                                                    const sized_buf* reduce_value,
                                                    void *ctx);

    /**
     * Iterate through the by-ID B-tree, including interior and leaf nodes as well as documents.
     *
     * The iteration is depth-first, in order by document ID. The callback is invoked on a tree
     * node before its children. The first call is for the root node.
     *
     * This is only useful for tools that want to examine the B-tree structure or reduced values,
     * such as couch_dbdump. It's unlikely that applications will need to use it.
     *
     * @param db the database to iterate through
     * @param startDocID  The key to start at, or NULL to start from the beginning
     * @param options COUCHSTORE_DELETES_ONLY and COUCHSTORE_NO_DELETES are supported
     * @param callback the callback function used to iterate over all documents
     * @param ctx client context (passed to the callback)
     * @return COUCHSTORE_SUCCESS upon success
     */
    LIBCOUCHSTORE_API
    couchstore_error_t couchstore_walk_id_tree(Db *db,
                                               const sized_buf* startDocID,
                                               couchstore_docinfos_options options,
                                               couchstore_walk_tree_callback_fn callback,
                                               void *ctx);

    /**
     * Iterate through the by-sequence B-tree, including interior and leaf nodes as well as documents.
     *
     * The iteration is depth-first, in order by sequence. The callback is invoked on a tree
     * node before its children. The first call is for the root node.
     *
     * This is only useful for tools that want to examine the B-tree structure or reduced values,
     * such as couch_dbdump. It's unlikely that applications will need to use it.
     *
     * @param db the database to iterate through
     * @param startSequence the sequence number to start from
     * @param options COUCHSTORE_DELETES_ONLY and COUCHSTORE_NO_DELETES are supported
     * @param callback the callback function used to iterate over all documents
     * @param ctx client context (passed to the callback)
     * @return COUCHSTORE_SUCCESS upon success
     */
    LIBCOUCHSTORE_API
    couchstore_error_t couchstore_walk_seq_tree(Db *db,
                                                uint64_t startSequence,
                                                couchstore_docinfos_options options,
                                                couchstore_walk_tree_callback_fn callback,
                                                void *ctx);

    /**
     * Iterate through the local B-tree, including interior and leaf nodes as
     * well as documents.
     *
     * The iteration is depth-first, in order by local document ID. The
     * callback is invoked on a tree node before its children. The first call
     * is for the root node.
     *
     * This is only useful for tools that want to examine the B-tree structure
     * or reduced values, such as couch_dbdump. It's unlikely that
     * applications will need to use it.
     *
     * @param db the database to iterate through
     * @param startLocalID  The key to start at, or NULL to start from the beginning
     * @param callback the callback function used to iterate over all documents
     * @param ctx client context (passed to the callback)
     * @return COUCHSTORE_SUCCESS upon success
     */
    LIBCOUCHSTORE_API
    couchstore_error_t couchstore_walk_local_tree(
            Db* db,
            const sized_buf* startLocalID,
            couchstore_walk_tree_callback_fn callback,
            void* ctx);

    /*////////////////////  LOCAL DOCUMENTS: */

    /**
     * Get a local doc from the db.
     *
     * The document should be freed with couchstore_free_local_document().
     *
     * @param db database to load document from
     * @param id the identifier to load (must begin with "_local/")
     * @param idlen the number of bytes in the id
     * @param lDoc Where to store the result
     * @return COUCHSTORE_SUCCESS if found
     */
    LIBCOUCHSTORE_API
    couchstore_error_t couchstore_open_local_document(Db *db,
                                                      const void *id,
                                                      size_t idlen,
                                                      LocalDoc **lDoc);

    /**
     * Save a local doc to the db. Its identifier must begin with "_local/".
     * To delete an existing doc, set the deleted flag on the LocalDoc
     * struct. The json buffer will be ignored for a deletion.
     *
     * @param db the database to store the document in
     * @param lDoc the document to store
     * @return COUCHSTORE_SUCCESS on success
     */
    LIBCOUCHSTORE_API
    couchstore_error_t couchstore_save_local_document(Db *db, LocalDoc *lDoc);

    /*
     * Free all allocated resources from a LocalDoc obtained from
     * couchstore_open_local_document().
     *
     * @param lDoc document to free
     */
    LIBCOUCHSTORE_API
    void couchstore_free_local_document(LocalDoc *lDoc);


    /*////////////////////  UTILITIES: */

    /**
     * Compact a database. This creates a new DB file with the same data as the
     * source db, omitting data that is no longer needed.
     * Will use default couch_file_ops to create and write the target db.
     *
     * @param source the source database
     * @param target_filename the filename of the new database to create.
     * @return COUCHSTORE_SUCCESS on success
     */
    LIBCOUCHSTORE_API
    couchstore_error_t couchstore_compact_db(Db* source, const char* target_filename);


    /*
     * Flags to pass as the flags parameter to couchstore_compact_db_ex
     */
    typedef uint64_t couchstore_compact_flags;
    enum {
        /**
         * Do not copy the tombstones of deleted items into compacted file.
         */
        COUCHSTORE_COMPACT_FLAG_DROP_DELETES = 1,

        /**
         * Upgrade the database whilst compacting.
         * The only supported upgrade is from version 11 to 12 which
         * changes the CRC function used.
         */
        COUCHSTORE_COMPACT_FLAG_UPGRADE_DB = 2,

        /**
         * Open the target database file without using an IO buffer
         *
         * This prevents the FileOps that are used in from being
         * wrapped by the buffered file operations. This will
         * *usually* result in performance degradation and is
         * primarily intended for testing purposes.
         */
        COUCHSTORE_COMPACT_FLAG_UNBUFFERED = 4,

        /**
         * This flag internally turns on 'error toleration' mode,
         * so as to migrate as many KV pairs as possible to the new
         * file, without aborting the task in the middle of compaction.
         */
        COUCHSTORE_COMPACT_RECOVERY_MODE = 8,

        /**
         * Currently unused flag bits.
         */
        COUCHSTORE_COMPACT_UNUSED = 0xfffff0,

        /**
         * Enable periodic sync().
         *
         * Automatically perform a sync() call after every N bytes written.
         * Same encoding as COUCHSTORE_OPEN_WITH_PERIODIC_SYNC - see
         * couchstore_open_flags for details.
         */
        COUCHSTORE_COMPACT_WITH_PERIODIC_SYNC = 0x1f000000,
    };

    /**
     * A compactor hook will be given each DocInfo, and can either keep or drop
     * the item based on its contents.
     *
     * It can also return a couchstore error code, which will abort the
     * compaction.
     *
     * If a compactor hook is set, COUCHSTORE_COMPACT_FLAG_DROP_DELETES will
     * *not* drop deletes, but will bump the purge counter. The hook is
     * responsible for dropping deletes.
     *
     * The couchstore_docinfo_hook is for editing the docinfo of the item if the
     * rev_meta section in docinfo is not found to already contain extended
     * metadata.
     */
    enum {
        COUCHSTORE_COMPACT_KEEP_ITEM = 0,
        COUCHSTORE_COMPACT_DROP_ITEM = 1,
        // The compact hook might need to see the full body to determine
        // if it should keep or drop the body. By default the body is
        // _not_ being read (as we expect that "keep" would be the common
        // path).
        COUCHSTORE_COMPACT_NEED_BODY = 2
    };

    using couchstore_compact_hook = int (*)(Db*, DocInfo*, sized_buf, void*);

    /**
     * Callback to rewrite the DocInfo as part of compaction
     * @param docinfo [IN/OUT] The DocInfo to persist
     * @param value The documents value
     * @return 0 no modifications happened to the data
     *         1 the data was changed
     */
    using couchstore_docinfo_hook = int (*)(DocInfo**, const sized_buf*);

    /**
     * Set purge sequence number.
     *
     * This allows the compactor hook to set the highest purged sequence number
     * into the header once compaction is complete (must happen before
     * commit in order to be persisted)
     *
     * @param target any database whose's purge_seq needs to be set
     * @param purge_seq the sequence number to set into the header's purge_seq.
     * @return COUCHSTORE_SUCCESS on success
     */
    LIBCOUCHSTORE_API
    couchstore_error_t couchstore_set_purge_seq(Db* target, uint64_t purge_seq);

    using PrecommitHook =
            std::function<couchstore_error_t(Db& source, Db& target)>;

    /**
     * Compact a database.
     *
     * This creates a new DB file with the same data as the source db,
     * omitting data that is no longer needed.
     *
     * Will use specified couch_file_ops to create and write the target db.
     *
     * @param source the source database
     * @param target_filename the filename of the new database to create.
     * @param flags flags that change compaction behavior
     * @param hook time_purge_hook callback
     * @param dhook callback which allows the user to rewrite the document info
     *              as part of compaction
     * @param hook_ctx compaction_ctx struct passed to time_purge_hook as the
     *                 ctx parameter
     * @param ops Pointer to the FileOpsInterface implementation
     *            you want the library to use.
     * @param precommitHook Before calling commit on the compacted file the
     *                      precommot hook is called to allow the caller to
     *                      do modifications to the database before commit
     * @return COUCHSTORE_SUCCESS on success
     */
    LIBCOUCHSTORE_API
    couchstore_error_t couchstore_compact_db_ex(
            Db* source,
            const char* target_filename,
            couchstore_compact_flags flags,
            couchstore_compact_hook hook,
            couchstore_docinfo_hook dhook,
            void* hook_ctx,
            FileOpsInterface* ops,
            PrecommitHook precommitHook = {});

    /*////////////////////  MISC: */

    /**
     * Convert an error code from couchstore to a textual description. The
     * text is a constant within the library so you should not try to modify
     * or free the pointer.
     *
     * @param errcode The error code to look up
     * @return a textual description of the error
     */
    LIBCOUCHSTORE_API
    const char *couchstore_strerror(couchstore_error_t errcode);

     /**
      * Counts the number of changes between two sequence numbers, inclusive.
      *
      * @param db The db to count changes in
      * @param min_seq The minimum sequence to count
      * @param max_seq The maximum sequence to count
      * @param count Pointer to uint64_t to store count in
      * @return COUCHSTORE_SUCCESS on success
      */
     LIBCOUCHSTORE_API
     couchstore_error_t couchstore_changes_count(Db* db,
                                                 uint64_t min_seq,
                                                 uint64_t max_seq,
                                                 uint64_t *count);
}

namespace cb {
namespace couchstore {

struct LIBCOUCHSTORE_API DbDeleter {
    void operator()(Db* db);
};
using UniqueDbPtr = std::unique_ptr<Db, DbDeleter>;

struct LIBCOUCHSTORE_API DocInfoDeleter {
    void operator()(DocInfo* info);
};
using UniqueDocInfoPtr = std::unique_ptr<DocInfo, DocInfoDeleter>;

struct LIBCOUCHSTORE_API DocDeleter {
    void operator()(Doc* doc);
};
using UniqueDocPtr = std::unique_ptr<Doc, DocDeleter>;

struct LIBCOUCHSTORE_API LocalDocDeleter {
    void operator()(LocalDoc* doc);
};
using UniqueLocalDocPtr = std::unique_ptr<LocalDoc, LocalDocDeleter>;

/**
 * Seek and load the database at the header at the given offset
 *
 * @param db The database instance to use
 * @param offset The location in the file of the new header to use
 * @return The status of the operation
 */
LIBCOUCHSTORE_API
couchstore_error_t seek(Db& db, cs_off_t offset);

enum class Direction : uint8_t {
    /// The next header in the file (newer revisions)
    Forward,
    /// The previous (older) header in the file
    Backward,
    /// The newest (last) header in the file
    End
};

/**
 * Find the next (forward, backward or last) header in a database file and
 * open that.
 *
 * Forward and backward will only seek within the file as it was opened
 * (not detect additional data being written by others who might have
 * the file open). They'll return COUCHSTORE_NO_HEADER if they fail to find
 * another header (and leave the "current" position at where it was).
 * Direction::End will "reset" its file size and find the last header in
 * the file (just like reopening the file would do).
 *
 * @param db The database instance to use
 * @param direction The direction in the database
 * @return The status of the operation
 */
LIBCOUCHSTORE_API
couchstore_error_t seek(Db& db, Direction direction);

/**
 * Find the first header containing the requested sequence number (aligned
 * to the provided granularity).
 *
 * The method rewinds the database instance to locate the first occurrence
 * of the provided sequence number, then it'll move forward until it meets
 * the boundary for timestamps with the provided granularity). This allows
 * for "deduplication" when trying to locate all changes as part of Point
 * in Time Recovery. If you want the first header the change was introduced
 * in, supply 1 as the granularity.
 *
 * @param db The database instance to use
 * @param seqno The sequence number to search for
 * @param granularity The granularity used for deduplication (cannot be 0)
 * @return The status of the operation
 */
LIBCOUCHSTORE_API
couchstore_error_t seekFirstHeaderContaining(Db& db,
                                             uint64_t seqno,
                                             uint64_t granularity);

/**
 * Helper method to wrap the C api to open a local document
 *
 * @param db the database to use
 * @param id the key to open
 * @return a pair containing the status of the operation and the document
 *           (if status == COUCHSTORE_SUCCESS)
 */
LIBCOUCHSTORE_API
std::pair<couchstore_error_t, UniqueLocalDocPtr> openLocalDocument(
        Db& db, std::string_view id);

/**
 * Helper method to wrap the C api to open a local document
 *
 * @param db the database to use
 * @param docinfo the doc info structure containing the document to open
 * @return a pair containing the status of the operation and the document
 *           (if status == COUCHSTORE_SUCCESS)
 */
LIBCOUCHSTORE_API
std::pair<couchstore_error_t, UniqueLocalDocPtr> openLocalDocument(
        Db& db, const DocInfo& docInfo);

/**
 * Helper method to wrap the C api to open a document
 *
 * @param db the database to use
 * @param docinfo the doc info structure containing the document to open
 * @return a pair containing the status of the operation and the document
 *           (if status == COUCHSTORE_SUCCESS)
 */
LIBCOUCHSTORE_API
std::pair<couchstore_error_t, UniqueDocPtr> openDocument(
        Db& db, const DocInfo& docInfo);

/**
 * Helper method to wrap the C api to open a document
 *
 * @param db the database to use
 * @param key the document to open
 * @return a pair containing the status of the operation and the document
 *           (if status == COUCHSTORE_SUCCESS)
 */
LIBCOUCHSTORE_API
std::pair<couchstore_error_t, UniqueDocPtr> openDocument(Db& db,
                                                         std::string_view key);

/**
 * Helper method to wrap the C api to open a DocInfo structure
 *
 * @param db the database to use
 * @param key the document to open
 * @return a pair containing the status of the operation and the DocInfo
 *           (if status == COUCHSTORE_SUCCESS)
 */
LIBCOUCHSTORE_API
std::pair<couchstore_error_t, UniqueDocInfoPtr> openDocInfo(
        Db& db, std::string_view key);

/**
 * Helper method to wrap the C api to open a database
 *
 * @param filename The file name to open the file
 * @param flags Open flags
 * @param encryptionKeyCB Callback that returns the encryption key that
 *                        decrypts the per file key
 * @param fileops optional file ops interface to use
 * @param offset optional offset in the file for the header to use
 * @return a pair containing the status of the operation and the database
 *           handle (if status == COUCHSTORE_SUCCESS)
 */
LIBCOUCHSTORE_API
std::pair<couchstore_error_t, UniqueDbPtr> openDatabase(
        const std::string& filename,
        couchstore_open_flags flags,
        cb::couchstore::EncryptionKeyGetter encryptionKeyCB,
        FileOpsInterface* fileops = {},
        std::optional<cs_off_t> offset = {});

/**
 * Get the physical block size used by this database instance
 *
 * @param db the database instance in use
 * @return the number of bytes for the block size
 */
LIBCOUCHSTORE_API
size_t getDiskBlockSize(Db& db);

struct LIBCOUCHSTORE_API Header {
    enum class Version {
        /// Version 11 use the old legacy CRC32 (may still be created by
        /// specifying COUCHSTORE_OPEN_WITH_LEGACY_CRC to open)
        V11 = 11,
        /// Version 12 changed the hash to CRC32C
        V12 = 12,
        /// Version 13 adds a timestamp to the header
        V13 = 13
    };

    /// The version number for the header
    Version version;
    /// The timestamp for the commit (only valid for V13)
    uint64_t timestamp;
    /// The sequence number used for updates in the header
    uint64_t updateSeqNum;
    /// The purge sequence number in the header
    uint64_t purgeSeqNum;
    /// The offset in the database file for the location of the header
    uint64_t headerPosition;
    /// Filesystem path (the file name is only valid as long as the
    /// database instance is valid!).
    const char* filename;
    /// Total number of (non-deleted) documents
    uint64_t docCount;
    /// Total number of deleted documents
    uint64_t deletedCount;
    /// Disk space actively used by docs
    uint64_t spaceUsed;
    /// Total disk space used by database
    uint64_t fileSize;
};

/**
 * Get the version number for the database.
 *
 * @param db the database instance to query
 * @return a structure with the header information
 */
LIBCOUCHSTORE_API
Header getHeader(Db& db);

/**
 * Returns true if the database is encrypted.
 */
LIBCOUCHSTORE_API
bool isEncrypted(const Db& db);

/**
 * Returns the key identifier if the database is encrypted, empty otherwise.
 */
LIBCOUCHSTORE_API
std::string_view getEncryptionKeyId(const Db& db);

/**
 * The compact filter is called with the target database as the first
 * parameter, then the DocumentInfo as the second parameter (set to
 * nullptr in the callback after all documents was processed) and the
 * documents value in the sized_buf. If sized_buf is nullptr you should return
 * COUCHSTORE_COMPACT_NEED_BODY and the system will load the value and
 * provide it again.
 *
 * The method should return one of:
 *     COUCHSTORE_COMPACT_KEEP_ITEM
 *     COUCHSTORE_COMPACT_DROP_ITEM
 *     COUCHSTORE_COMPACT_NEED_BODY
 * or any of the couchstore error codes to abort compaction
 */
using CompactFilterCallback = std::function<int(Db&, DocInfo*, sized_buf)>;

/**
 * The rewrite callback is used to change the metadata for the DocInfo
 * as part of the compaction. The first parameter is an in/out parameter
 * containing the document info (may be reallocated in the callback with
 * cb_realloc()) the second parameter contains the documents value.
 */
using CompactRewriteDocInfoCallback = std::function<int(DocInfo*&, sized_buf)>;

/**
 * Compact a Couchstore file
 *
 * @param source The source database to compact
 * @param target_filename The name of the target database
 * @param flags Extra flags to open the database with
 * @param targetEncrKeyCB Callback that returns the encryption key that
 *                        will encrypt the target per file key
 * @param filterCallback The filter callback to call for each item to check
 *                       if the document should be part of the compacted
 *                       database or not
 * @param rewriteDocInfoCallback The rewrite callback which is called for
 *                       each DocInfo to be put into the new database (to
 *                       allow upgrading the metadata section in the DocInfo)
 * @param ops The File operations to use
 * @return Couchstore error code
 */
LIBCOUCHSTORE_API
couchstore_error_t compact(Db& source,
                           const char* target_filename,
                           couchstore_compact_flags flags,
                           cb::couchstore::EncryptionKeyGetter targetEncrKeyCB,
                           CompactFilterCallback filterCallback,
                           CompactRewriteDocInfoCallback rewriteDocInfoCallback,
                           FileOpsInterface* ops,
                           PrecommitHook precommitHook = {});

/// A callback the user may provide to a PointInTime compaction which gets
/// called before the compaction starts with the database header representing
/// the database header it'll perform a full compaction up to (may be used
/// by the user to fetch the highest sequence number for instance)
/// If the callback returns anthing else than COUCHSTORE_SUCCESS compaction
/// will fail with the returned value
using PreCompactionCallback = std::function<couchstore_error_t(Db&)>;

/// A callback the user may provide to a PointInTime compaction which gets
/// called after the full comaction
/// If the callback returns anthing else than COUCHSTORE_SUCCESS compaction
/// will fail with the returned value
using PostCompactionCallback = std::function<couchstore_error_t(Db&)>;

/// A callback the user may provide which gets called as part of copying
/// each document during the replay of changes.
/// The parameters are (in the described order)
///    source The database where the document comes from
///    target The database copying stuff to
///    DocInfo The doc info for the document (or nullptr if this is a local
///            document).
///    local doc info The doc info for the local document (or nullptr if this
///                   isn't a local document)
///
/// A return value != COUCHSTORE_SUCCESS will cause replay to abort with
/// the provided error code.
using PreCopyHook = std::function<couchstore_error_t(
        Db&, Db&, const DocInfo*, const DocInfo*)>;

/**
 * Replay mutations from the current header in the source database to the
 * target database by using the specified delta as the granularity for the
 * number of headers to deduplicate. Stop when we reach the provided
 * sourceHeaderEndOffset. The precommit hook will be called for each commit
 * in the destination database
 *
 * @param source The database to copy from (current header offset)
 * @param target The database to copy data to
 * @param delta The delta between each header to persist (multiple headers
 *              within the same delta will be deduped)
 * @param sourceHeaderEndOffset The last header to include
 * @param preCopyHook The hook to be called before each document is copied over
 *        replay will copy localdocs before 'normal' documents
 * @param precommitHook The hook to call before each commit
 * @param flushThreshold how much data can be buffered by replay
 */
LIBCOUCHSTORE_API
couchstore_error_t replay(Db& source,
                          Db& target,
                          uint64_t delta,
                          uint64_t sourceHeaderEndOffset,
                          PreCopyHook preCopyHook,
                          PrecommitHook precommitHook,
                          size_t flushThreshold = 100 * 1024 * 1024);

/**
 * Save multiple local docs to the db. see couchstore_save_local_document. The
 * vector of documents can include deletes.
 *
 * @param db the database to store the documents in
 * @param documents the documents to store/delete. The function will modify the
 *        vector by sorting lexicographically by key.
 * @return COUCHSTORE_SUCCESS on success
 */
LIBCOUCHSTORE_API
couchstore_error_t saveLocalDocuments(
        Db& db, std::vector<std::reference_wrapper<LocalDoc>>& documents);

/**
 * Get a description of the last OS-level errors that Couchstore
 * encountered on this database instance.
 *
 * @throws std::bad_alloc
 */
LIBCOUCHSTORE_API
std::string getLastOsError(const Db& db);

/**
 * Get a description of the last internal error that Couchstore
 * encountered on this thread.
 *
 * @throws std::bad_alloc
 */
LIBCOUCHSTORE_API
std::string getLastInternalError();



} // namespace couchstore
} // namespace cb
