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
#include <libcouchstore/visibility.h>
#include <libcouchstore/couch_db.h>
#include "../file_merger.h"

/*
 * Merge a group files containing sorted sets of btree operations for a
 * view btree.
 */
LIBCOUCHSTORE_API
file_merger_error_t merge_view_kvs_ops_files(const char* source_files[],
                                             unsigned num_source_files,
                                             const char* dest_path);

/*
 * Merge a group files containing sorted sets of btree operations for a
 * view id btree (back index).
 */
LIBCOUCHSTORE_API
file_merger_error_t merge_view_ids_ops_files(const char* source_files[],
                                             unsigned num_source_files,
                                             const char* dest_path);

/*
 * Merge a group files containing sets of operations for a spatial view
 * index.
 */
LIBCOUCHSTORE_API
file_merger_error_t merge_spatial_kvs_ops_files(const char* source_files[],
                                                unsigned num_source_files,
                                                const char* dest_path,
                                                const char* tmp_dir);
