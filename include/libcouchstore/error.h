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

#ifndef COUCHSTORE_COUCH_DB_H
#error "You should include <libcouchstore/couch_db.h> instead"
#endif

/** Error values returned by CouchStore API calls. */
enum couchstore_error_t {
    COUCHSTORE_SUCCESS = 0,
    COUCHSTORE_ERROR_OPEN_FILE = -1,
    COUCHSTORE_ERROR_CORRUPT = -2,
    COUCHSTORE_ERROR_ALLOC_FAIL = -3,
    COUCHSTORE_ERROR_READ = -4,
    COUCHSTORE_ERROR_DOC_NOT_FOUND = -5,
    COUCHSTORE_ERROR_NO_HEADER = -6,
    COUCHSTORE_ERROR_WRITE = -7,
    COUCHSTORE_ERROR_HEADER_VERSION = -8,
    COUCHSTORE_ERROR_CHECKSUM_FAIL = -9,
    COUCHSTORE_ERROR_INVALID_ARGUMENTS = -10,
    COUCHSTORE_ERROR_NO_SUCH_FILE = -11,
    COUCHSTORE_ERROR_CANCEL = -12,
    COUCHSTORE_ERROR_REDUCTION_TOO_LARGE = -13,
    COUCHSTORE_ERROR_REDUCER_FAILURE = -14,
    COUCHSTORE_ERROR_FILE_CLOSED = -15,
    COUCHSTORE_ERROR_DB_NO_LONGER_VALID = -16,
    COUCHSTORE_ERROR_FILE_CLOSE = -17,
    COUCHSTORE_ERROR_NOT_SUPPORTED = -18,

    /**
     * A non success status code for the callback of
     * couchstore_changes_since and couchstore_docinfos_by_id to signal that
     * the outer function is to stop visiting the index and return this
     * status code to the caller. The callback uses this status to indicate
     * some temporary issue (e.g. a soft out of memory condition) and the
     * caller should yield and resume the index scan later.
     */
    COUCHSTORE_ERROR_SCAN_YIELD = -19,

    /**
     * A non success status code for the callback of
     * couchstore_changes_since and couchstore_docinfos_by_id to signal that
     * the outer function is to stop visiting the index and return this
     * status code to the caller. The callback uses this status to indicate
     * some non temporary issue (e.g. a change of vbucket state) and the
     * caller should cancel the scan.
     */
    COUCHSTORE_ERROR_SCAN_CANCELLED = -20,

    COUCHSTORE_ERROR_NO_ENCRYPTION_KEY = -21,
    COUCHSTORE_ERROR_ENCRYPT = -22,
    COUCHSTORE_ERROR_DECRYPT = -23
};
