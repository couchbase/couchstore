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
#include "../view_group.h"
#include "../util.h"

#include <platform/cb_malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include "util.h"
#include "../mapreduce/mapreduce.h"

#define BUF_SIZE 8192

int main(int argc, char *argv[])
{
    view_group_info_t* group_info = nullptr;
    uint64_t purge_count;
    int ret = 2;
    uint64_t header_pos;
    view_error_t error_info = {nullptr, nullptr, nullptr};

    (void) argc;
    (void) argv;

    /*
     * Disable buffering for stdout/stderr
     */
    setvbuf(stdout, (char*)nullptr, _IONBF, 0);
    setvbuf(stderr, (char*)nullptr, _IONBF, 0);

    if (set_binary_mode() < 0) {
        fprintf(stderr, "Error setting binary mode\n");
        goto out;
    }

    group_info = couchstore_read_view_group_info(stdin, stderr);
    if (group_info == nullptr) {
        ret = COUCHSTORE_ERROR_ALLOC_FAIL;
        goto out;
    }

    ret = start_exit_listener(1 /*uses_v8*/);
    if (ret) {
        fprintf(stderr, "Error starting stdin exit listener thread\n");
        goto out;
    }

    mapreduce_init(argv[0]);
    ret = couchstore_cleanup_view_group(group_info,
                                        &header_pos,
                                        &purge_count,
                                        &error_info);
    mapreduce_deinit();

    if (ret != COUCHSTORE_SUCCESS) {
        if (error_info.error_msg != nullptr &&
            error_info.view_name != nullptr) {
            fprintf(stderr,
                    "Error cleaning up index for view `%s`, reason: %s\n",
                    error_info.view_name,
                    error_info.error_msg);
        }
        goto out;
    }

    fprintf(stdout, "PurgedCount %" PRIu64 "\n", purge_count);

out:
    couchstore_free_view_group_info(group_info);
    cb_free((void *) error_info.error_msg);
    cb_free((void *) error_info.view_name);

    ret = (ret < 0) ? (100 + ret) : ret;
    _exit(ret);
}
