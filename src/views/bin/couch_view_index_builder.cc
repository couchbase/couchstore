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

#include "couchstore_config.h"

#include <platform/cb_malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../view_group.h"
#include "../util.h"
#include "util.h"
#include "../file_sorter.h"
#include "../mapreduce/mapreduce.h"

#define BUF_SIZE 8192

int main(int argc, char *argv[])
{
    view_group_info_t *group_info = NULL;
    char buf[BUF_SIZE];
    char **source_files = NULL;
    char *dest_file = NULL;
    char *tmp_dir = NULL;
    int i;
    int ret = 2;
    uint64_t header_pos;
    view_error_t error_info = {NULL, NULL, "GENERIC"};
    cb_thread_t exit_thread;

    (void) argc;
    (void) argv;

    /*
     * Disable buffering for stdout/stderr since index builder messages
     * needs to be immediately available at erlang side
     */
    setvbuf(stdout, (char *) NULL, _IONBF, 0);
    setvbuf(stderr, (char *) NULL, _IONBF, 0);

    if (set_binary_mode() < 0) {
        fprintf(stderr, "Error setting binary mode\n");
        goto out;
    }

    group_info = couchstore_read_view_group_info(stdin, stderr);
    if (group_info == NULL) {
        ret = COUCHSTORE_ERROR_ALLOC_FAIL;
        goto out;
    }

    if (couchstore_read_line(stdin, buf, BUF_SIZE) != buf) {
        fprintf(stderr, "Error reading temporary directory path\n");
        ret = COUCHSTORE_ERROR_INVALID_ARGUMENTS;
        goto out;
    }

    tmp_dir = cb_strdup(buf);
    if (tmp_dir == NULL) {
        fprintf(stderr, "Memory allocation failure\n");
        ret = COUCHSTORE_ERROR_ALLOC_FAIL;
        goto out;
    }

    source_files = (char **) cb_calloc(group_info->num_btrees + 1, sizeof(char *));
    if (source_files == NULL) {
        fprintf(stderr, "Memory allocation failure\n");
        ret = COUCHSTORE_ERROR_ALLOC_FAIL;
        goto out;
    }

    if (couchstore_read_line(stdin, buf, BUF_SIZE) != buf) {
        fprintf(stderr, "Error reading destination file\n");
        ret = COUCHSTORE_ERROR_INVALID_ARGUMENTS;
        goto out;
    }

    dest_file = cb_strdup(buf);
    if (dest_file == NULL) {
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
        if (source_files[i] == NULL) {
            fprintf(stderr, "Memory allocation failure\n");
            ret = COUCHSTORE_ERROR_ALLOC_FAIL;
            goto out;
        }
    }

    ret = start_exit_listener(&exit_thread, 1 /*uses_v8*/);
    if (ret) {
        fprintf(stderr, "Error starting stdin exit listener thread\n");
        goto out;
    }

    mapreduce_init();
    ret = couchstore_build_view_group(group_info,
                                      source_files[0],
                                      (const char **) &source_files[1],
                                      dest_file,
                                      tmp_dir,
                                      &header_pos,
                                      &error_info);

    mapreduce_deinit();
    if (ret != COUCHSTORE_SUCCESS) {
        if (error_info.error_msg != NULL && error_info.view_name != NULL) {
            fprintf(stderr,
                    "%s Error building index for view `%s`, reason: %s\n",
                    error_info.idx_type,
                    error_info.view_name,
                    error_info.error_msg);
        }
        goto out;
    }

out:
    if (source_files != NULL) {
        for (i = 0; i <= group_info->num_btrees; ++i) {
            cb_free(source_files[i]);
        }
        cb_free(source_files);
    }
    cb_free(tmp_dir);
    cb_free(dest_file);
    couchstore_free_view_group_info(group_info);
    cb_free((void *) error_info.error_msg);
    cb_free((void *) error_info.view_name);

    ret = (ret < 0) ? (100 + ret) : ret;
    _exit(ret);
}
