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

#ifndef _FILE_SORTER_H
#define _FILE_SORTER_H

#include "couchstore_config.h"
#include <libcouchstore/couch_db.h>
#include "file_merger.h"

#ifdef __cplusplus
extern "C" {
#endif


    typedef enum {
        FILE_SORTER_SUCCESS                  = FILE_MERGER_SUCCESS,
        FILE_SORTER_ERROR_OPEN_FILE          = FILE_MERGER_ERROR_OPEN_FILE,
        FILE_SORTER_ERROR_FILE_READ          = FILE_MERGER_ERROR_FILE_READ,
        FILE_SORTER_ERROR_FILE_WRITE         = FILE_MERGER_ERROR_FILE_WRITE,
        FILE_SORTER_ERROR_BAD_ARG            = FILE_MERGER_ERROR_BAD_ARG,
        FILE_SORTER_ERROR_ALLOC              = FILE_MERGER_ERROR_ALLOC,
        FILE_SORTER_ERROR_RENAME_FILE        = -10,
        FILE_SORTER_ERROR_DELETE_FILE        = -11,
        FILE_SORTER_ERROR_MK_TMP_FILE        = -12,
        FILE_SORTER_ERROR_NOT_EMPTY_TMP_FILE = -13,
        FILE_SORTER_ERROR_TMP_FILE_BASENAME  = -14,
        FILE_SORTER_ERROR_MISSING_CALLBACK   = -15
    } file_sorter_error_t;


    file_sorter_error_t sort_file(const char *source_file,
                                  const char *tmp_dir,
                                  unsigned num_tmp_files,
                                  unsigned max_buffer_size,
                                  file_merger_read_record_t read_record,
                                  file_merger_write_record_t write_record,
                                  file_merger_feed_record_t feed_record,
                                  file_merger_compare_records_t compare_records,
                                  file_merger_record_free_t free_record,
                                  int skip_writeback,
                                  void *user_ctx);

#ifdef __cplusplus
}
#endif

#endif
