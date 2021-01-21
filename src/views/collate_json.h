/*
**  collate_json.h
**  couchstore
**
**  Created by Jens Alfke on 7/9/12.
**  Copyright (c) 2012 Couchbase, Inc. All rights reserved.
*/

#pragma once

#include <libcouchstore/couch_common.h>
#include <libcouchstore/visibility.h>
#include <unicode/ucasemap.h>
#include <unicode/ucnv.h>
#include <unicode/ucol.h>
#include <cstdlib>

enum CollateJSONMode {
    kCollateJSON_Unicode, /* Compare strings as Unicode (CouchDB's default) */
    kCollateJSON_Raw, /* CouchDB's "raw" collation rules */
    kCollateJSON_ASCII /* Like Unicode except strings are compared as binary
                          UTF-8 */
};

/* Custom deleter for UCollator */
struct UCollDeleter {
    void operator() (UCollator* coll) {
        ucol_close(coll);
    }
};

/* Custom deleter for UConverter */
struct UConvDeleter {
    void operator() (UConverter* cnv) {
        ucnv_close(cnv);
    }
};

/**
 * Compares two UTF-8 JSON strings using CouchDB's collation rules.
 * CAREFUL: The two strings must be valid JSON, with no extraneous whitespace,
 * otherwise this function will return wrong results or even crash.
 */
int CollateJSON(const sized_buf *buf1,
                const sized_buf *buf2,
                CollateJSONMode mode);

/* not part of the API -- exposed for testing only (see collate_json_test.c) */
char ConvertJSONEscape(const char **in);
