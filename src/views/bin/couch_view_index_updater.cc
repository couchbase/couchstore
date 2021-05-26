/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

/**
 * @copyright 2013 Couchbase, Inc.
 *
 * @author Sarath Lakshman  <sarath@couchbase.com>
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

#include "couchstore_config.h"

#include <platform/cb_malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../view_group.h"
#include "../util.h"
#include "../file_sorter.h"
#include "util.h"
#include "../mapreduce/mapreduce.h"

#define BUF_SIZE 8192

int main(int argc, char *argv[])
{
    view_group_info_t* group_info = nullptr;
    char buf[BUF_SIZE];
    char** source_files = nullptr;
    char* tmp_dir = nullptr;
    int i;
    int batch_size;
    couchstore_error_t ret = (couchstore_error_t)2;
    int is_sorted = 0;
    view_group_update_stats_t stats;
    sized_buf header_buf = {nullptr, 0};
    sized_buf header_outbuf = {nullptr, 0};
    view_error_t error_info = {nullptr, nullptr, "GENERIC"};
    cb_thread_t exit_thread;

    (void) argc;
    (void) argv;

    /*
     * Disable buffering for stdout/stderr since index updater messages
     * needs to be immediately available at erlang side
     */
    setvbuf(stdout, (char*)nullptr, _IONBF, 0);
    setvbuf(stderr, (char*)nullptr, _IONBF, 0);

    if (set_binary_mode() < 0) {
        fprintf(stderr, "Error setting binary mode\n");
        goto out;
    }

    /* Set all stats counters to zero */
    memset((char *) &stats, 0, sizeof(view_group_update_stats_t));

    if (couchstore_read_line(stdin, buf, BUF_SIZE) != buf) {
        fprintf(stderr, "Error reading temporary directory path\n");
        ret = COUCHSTORE_ERROR_INVALID_ARGUMENTS;
        goto out;
    }

    tmp_dir = cb_strdup(buf);
    if (tmp_dir == nullptr) {
        fprintf(stderr, "Memory allocation failure\n");
        ret = COUCHSTORE_ERROR_ALLOC_FAIL;
        goto out;
    }

    group_info = couchstore_read_view_group_info(stdin, stderr);
    if (group_info == nullptr) {
        ret = COUCHSTORE_ERROR_ALLOC_FAIL;
        goto out;
    }

    if (couchstore_read_line(stdin, buf, BUF_SIZE) != buf) {
        fprintf(stderr, "Error reading is_sorted flag\n");
        ret = COUCHSTORE_ERROR_INVALID_ARGUMENTS;
        goto out;
    }

    if (!strncmp(buf, "s", 1)) {
        is_sorted = 1;
    }

    source_files = (char **) cb_calloc(group_info->num_btrees + 1, sizeof(char *));
    if (source_files == nullptr) {
        fprintf(stderr, "Memory allocation failure\n");
        ret = COUCHSTORE_ERROR_ALLOC_FAIL;
        goto out;
    }

    for (i = 0; i <= group_info->num_btrees; ++i) {
        if (couchstore_read_line(stdin, buf, BUF_SIZE) != buf) {
            if (i == 0) {
                fprintf(stderr, "Error reading source file for id btree\n");
            } else {
                fprintf(stderr,
                        "Error reading source file for btree %d\n", i - 1);
            }
            ret = COUCHSTORE_ERROR_INVALID_ARGUMENTS;
            goto out;
        }

        source_files[i] = cb_strdup(buf);
        if (source_files[i] == nullptr) {
            fprintf(stderr, "Memory allocation failure\n");
            ret = COUCHSTORE_ERROR_ALLOC_FAIL;
            goto out;
        }
    }

    batch_size = couchstore_read_int(stdin, buf, sizeof(buf), &ret);
    if (ret != COUCHSTORE_SUCCESS) {
        fprintf(stderr, "Error reading batch size\n");
        ret = COUCHSTORE_ERROR_INVALID_ARGUMENTS;
        goto out;
    }

    header_buf.size = couchstore_read_int(stdin, buf, sizeof(buf), &ret);
    if (ret != COUCHSTORE_SUCCESS) {
        fprintf(stderr, "Error reading viewgroup header size\n");
        goto out;
    }

    header_buf.buf = (char*)cb_malloc(header_buf.size);
    if (header_buf.buf == nullptr) {
        fprintf(stderr, "Memory allocation failure\n");
        ret = COUCHSTORE_ERROR_ALLOC_FAIL;
        goto out;
    }

    if (fread(header_buf.buf, header_buf.size, 1, stdin) != 1) {
        fprintf(stderr,
                "Error reading viewgroup header from stdin\n");
        goto out;
    }

    ret = (couchstore_error_t)start_exit_listener(&exit_thread, 1 /*uses_v8*/);
    if (ret) {
        fprintf(stderr, "Error starting stdin exit listener thread\n");
        goto out;
    }

    mapreduce_init(argv[0]);
    ret = couchstore_update_view_group(group_info,
                                      source_files[0],
                                      (const char **) &source_files[1],
                                      batch_size,
                                      &header_buf,
                                      is_sorted,
                                      tmp_dir,
                                      &stats,
                                      &header_outbuf,
                                      &error_info);

    mapreduce_deinit();

    if (ret != COUCHSTORE_SUCCESS) {
        if (error_info.error_msg != nullptr &&
            error_info.view_name != nullptr) {
            fprintf(stderr,
                    "%s Error updating index for view `%s`, reason: %s\n",
                    error_info.idx_type,
                    error_info.view_name,
                    error_info.error_msg);
        }
        goto out;
    }

    fprintf(stdout, "Header Len : %zu\n", header_outbuf.size);
    fwrite(header_outbuf.buf, header_outbuf.size, 1, stdout);
    fprintf(stdout, "\n");

    fprintf(stdout,"Results ="
                   " id_inserts : %" PRIu64
                   ", id_deletes : %" PRIu64
                   ", kv_inserts : %" PRIu64
                   ", kv_deletes : %" PRIu64
                   ", cleanups : %" PRIu64 "\n",
                   stats.ids_inserted,
                   stats.ids_removed,
                   stats.kvs_inserted,
                   stats.kvs_removed,
                   stats.purged);

out:
    if (source_files != nullptr) {
        for (i = 0; i <= group_info->num_btrees; ++i) {
            cb_free(source_files[i]);
        }
        cb_free(source_files);
    }

    couchstore_free_view_group_info(group_info);
    cb_free((void *) error_info.error_msg);
    cb_free((void *) error_info.view_name);
    cb_free((void *) header_buf.buf);
    cb_free((void *) header_outbuf.buf);
    cb_free(tmp_dir);

    int ret_int = (int)ret;
    ret_int = (ret_int < 0) ? (100 + ret_int) : ret_int;
    _exit(ret_int);
}
