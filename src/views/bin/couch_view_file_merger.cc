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
#include <errno.h>
#include <libcouchstore/couch_db.h>
#include <v8.h>
#include "../file_merger.h"
#include "../util.h"
#include "util.h"

#define LINE_BUF_SIZE (8 * 1024)
#define MERGE_ERROR_CODE(Err) (100 + (Err))

typedef enum : char {
    MERGE_FILE_TYPE_ID_BTREE = 'i',
    MERGE_FILE_TYPE_MAPREDUCE_VIEW = 'v',
    MERGE_FILE_TYPE_SPATIAL = 's'
} merge_file_type_t;


int main(int argc, char *argv[])
{
    v8::V8::InitializeICUDefaultLocation(argv[0], nullptr);
    merge_file_type_t view_file_type;
    int num_files;
    int i, j;
    char **view_files;
    char tmp_dir[LINE_BUF_SIZE];
    char dest_file[LINE_BUF_SIZE];
    file_merger_error_t error;
    cb_thread_t exit_thread;
    int status = 0;

    (void) argc;
    (void) argv;

    /*
     * Disable buffering for stdout/stderr since file merger messages needs
     * to be immediately available at erlang side
     */
    setvbuf(stdout, (char*)nullptr, _IONBF, 0);
    setvbuf(stderr, (char*)nullptr, _IONBF, 0);

    if (set_binary_mode() < 0) {
        fprintf(stderr, "Error setting binary mode\n");
        exit(EXIT_FAILURE);
    }

    if (fscanf(stdin, "%c\n", (char *)&view_file_type) != 1) {
        fprintf(stderr, "Error reading view file type.\n");
        exit(EXIT_FAILURE);
    }
    switch(view_file_type) {
        case MERGE_FILE_TYPE_ID_BTREE:
        case MERGE_FILE_TYPE_MAPREDUCE_VIEW:
        case MERGE_FILE_TYPE_SPATIAL:
            break;
        default:
            fprintf(stderr, "View file type must be 'i', 'v' or 's'.\n");
            exit(EXIT_FAILURE);
    }

    if (view_file_type == MERGE_FILE_TYPE_SPATIAL) {
        if (couchstore_read_line(stdin, tmp_dir, LINE_BUF_SIZE) != tmp_dir) {
            fprintf(stderr, "Error reading temporary directory path.\n");
            exit(EXIT_FAILURE);
        }
    }
    if (fscanf(stdin, "%d\n", &num_files) != 1) {
        fprintf(stderr, "Error reading number of files to merge.\n");
        exit(EXIT_FAILURE);
    }
    if (num_files <= 0) {
        fprintf(stderr, "Number of files to merge is negative or zero.\n");
        exit(EXIT_FAILURE);
    }

    view_files = (char **) cb_malloc(sizeof(char *) * num_files);
    if (view_files == nullptr) {
        fprintf(stderr, "Memory allocation failure.\n");
        exit(EXIT_FAILURE);
    }

    for (i = 0; i < num_files; ++i) {
        view_files[i] = (char *) cb_malloc(LINE_BUF_SIZE);
        if (view_files[i] == nullptr) {
            for (j = 0; j < i; ++j) {
                cb_free(view_files[j]);
            }
            cb_free(view_files);
            fprintf(stderr, "Memory allocation failure.\n");
            exit(EXIT_FAILURE);
        }

        if (couchstore_read_line(stdin, view_files[i], LINE_BUF_SIZE) != view_files[i]) {
            for (j = 0; j <= i; ++j) {
                cb_free(view_files[j]);
            }
            cb_free(view_files);
            fprintf(stderr, "Error reading view file number %d.\n", (i + 1));
            exit(EXIT_FAILURE);
        }
    }

    if (couchstore_read_line(stdin, dest_file, LINE_BUF_SIZE) != dest_file) {
        fprintf(stderr, "Error reading destination file name.\n");
        status = 1;
        goto finished;
    }

    status = start_exit_listener(&exit_thread, 0 /*uses_v8*/);
    if (status) {
        fprintf(stderr, "Error starting stdin exit listener thread\n");
        goto finished;
    }

    if (num_files > 1) {
        const char **src_files = (const char **) view_files;
        switch (view_file_type) {
        case MERGE_FILE_TYPE_ID_BTREE:
            error = merge_view_ids_ops_files(src_files, num_files, dest_file);
            break;
        case MERGE_FILE_TYPE_MAPREDUCE_VIEW:
            error = merge_view_kvs_ops_files(src_files, num_files, dest_file);
            break;
        case MERGE_FILE_TYPE_SPATIAL:
            error = merge_spatial_kvs_ops_files(src_files, num_files,
                                                dest_file, tmp_dir);
            break;
        default:
            fprintf(stderr, "Unknown view file type: %c\n", view_file_type);
            status = 1;
            goto finished;
        }

        if (error == FILE_MERGER_SUCCESS) {
            for (i = 0; i < num_files; ++i) {
                /* Ignore failures.
                   Erlang side will eventually delete the files later. */
                remove(view_files[i]);
            }
        } else {
            status = MERGE_ERROR_CODE(error);
            goto finished;
        }
    } else {
        if (rename(view_files[0], dest_file) != 0) {
            fprintf(stderr, "Error renaming file %s to %s: %s\n",
                    view_files[0], dest_file, strerror(errno));
            status = 1;
            goto finished;
        }
    }

 finished:
    for (i = 0; i < num_files; ++i) {
        cb_free(view_files[i]);
    }
    cb_free(view_files);

    _exit(status);
}
