/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

/**
 * @copyright 2013 Couchbase, Inc.
 *
 * @author Filipe Manana  <filipe@couchbase.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 **/

#pragma once

#include "couchstore_config.h"
#include <libcouchstore/couch_db.h>
#include <cstdio>

enum file_merger_error_t {
    FILE_MERGER_SUCCESS = 0,
    FILE_MERGER_ERROR_OPEN_FILE = -1,
    FILE_MERGER_ERROR_FILE_READ = -2,
    FILE_MERGER_ERROR_FILE_WRITE = -3,
    FILE_MERGER_ERROR_BAD_ARG = -4,
    FILE_MERGER_ERROR_ALLOC = -5,
    FILE_MERGER_SORT_ERROR = -6
};

struct file_merger_record_t {
    void* record;
    unsigned filenum;
};

/*
 * Returns the length of the record read from the file on success.
 * Returns 0 when the file's EOF is reached, and a negative value
 * on failure (a file_merger_error_t value).
 */
typedef int (*file_merger_read_record_t)(FILE* f,
                                         void** record_buffer,
                                         void* user_ctx);

/*
 * Returns FILE_MERGER_SUCCESS on success, another file_merger_error_t
 * value otherwise.
 */
typedef file_merger_error_t (*file_merger_write_record_t)(FILE* f,
                                                          void* record_buffer,
                                                          void* user_ctx);

/*
 * Returns 0 if both records compare equal, a negative value if the first record
 * is smaller than the second record, a positive value if the first record is
 * greater than the second record.
 */
typedef int (*file_merger_compare_records_t)(const void* record_buffer1,
                                             const void* record_buffer2,
                                             void* user_ctx);

typedef void (*file_merger_record_free_t)(void* record, void* user_ctx);

/* Callback which gets called for resulting merge records */
typedef file_merger_error_t (*file_merger_feed_record_t)(void* record_buffer,
                                                         void* user_ctx);

/* Among the provided records, return the winner record index */
typedef size_t (*file_merger_deduplicate_records_t)(
        file_merger_record_t** records, size_t len, void* user_ctx);

file_merger_error_t merge_files(const char* source_files[],
                                unsigned num_files,
                                const char* dest_file,
                                file_merger_read_record_t read_record,
                                file_merger_write_record_t write_record,
                                file_merger_feed_record_t feed_record,
                                file_merger_compare_records_t compare_records,
                                file_merger_deduplicate_records_t dedup_records,
                                file_merger_record_free_t free_record,
                                int skip_writeback,
                                void* user_ctx);
