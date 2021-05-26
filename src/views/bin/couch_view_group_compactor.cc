/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

/**
 * @copyright 2014 Couchbase, Inc.
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
#include "util.h"
#include "../mapreduce/mapreduce.h"

#define BUF_SIZE 8192
#define MAX(a,b) ((a) > (b) ? a : b)

static void stats_updater(uint64_t freq, uint64_t inserted)
{
    if (inserted % freq == 0) {
        fprintf(stdout, "Stats = inserted : %" PRIu64 "\n", freq);
    }
}

int main(int argc, char *argv[])
{
    view_group_info_t* group_info = nullptr;
    char buf[BUF_SIZE];
    char* target_file = nullptr;
    couchstore_error_t ret = COUCHSTORE_SUCCESS;
    sized_buf header_buf = {nullptr, 0};
    sized_buf header_outbuf = {nullptr, 0};
    uint64_t total_changes = 0;
    uint64_t header_size = 0;
    view_error_t error_info = {nullptr, nullptr, "GENERIC"};
    cb_thread_t exit_thread;
    compactor_stats_t stats;

    (void) argc;
    (void) argv;

    /*
     * Disable buffering for stdout/stderr since progress stats needs to be
     * immediately available at erlang side
     */
    setvbuf(stdout, (char*)nullptr, _IONBF, 0);
    setvbuf(stderr, (char*)nullptr, _IONBF, 0);

    if (set_binary_mode() < 0) {
        fprintf(stderr, "Error setting binary mode\n");
        goto out;
    }

    /* Read target filepath */
    if (couchstore_read_line(stdin, buf, BUF_SIZE) != buf) {
        fprintf(stderr, "Error reading compaction target filepath\n");
        ret = COUCHSTORE_ERROR_INVALID_ARGUMENTS;
        goto out;
    }

    target_file = cb_strdup(buf);
    if (target_file == nullptr) {
        fprintf(stderr, "Memory allocation failure\n");
        ret = COUCHSTORE_ERROR_ALLOC_FAIL;
        goto out;
    }

    total_changes = couchstore_read_int(stdin, buf, sizeof(buf), &ret);
    if (ret != COUCHSTORE_SUCCESS) {
        fprintf(stderr, "Error reading total changes\n");
        ret = COUCHSTORE_ERROR_INVALID_ARGUMENTS;
        goto out;
    }

    group_info = couchstore_read_view_group_info(stdin, stderr);
    if (group_info == nullptr) {
        ret = COUCHSTORE_ERROR_ALLOC_FAIL;
        goto out;
    }

    /* Read group header bin */
    header_size = couchstore_read_int(stdin, buf, sizeof(buf), &ret);
    if (ret != COUCHSTORE_SUCCESS) {
        fprintf(stderr, "Error reading viewgroup header size\n");
        ret = COUCHSTORE_ERROR_INVALID_ARGUMENTS;
        goto out;
    }

    if (header_size > MAX_VIEW_HEADER_SIZE) {
        fprintf(stderr, "View header is too large (%" PRIu64 " bytes). "
                "Maximum size is %d bytes\n",
                header_size, MAX_VIEW_HEADER_SIZE);
        ret = COUCHSTORE_ERROR_INVALID_ARGUMENTS;
        goto out;
    }

    header_buf.size = (size_t)header_size;
    header_buf.buf = (char*)cb_malloc(header_buf.size);
    if (header_buf.buf == nullptr) {
        fprintf(stderr, "Memory allocation failure\n");
        ret = COUCHSTORE_ERROR_ALLOC_FAIL;
        goto out;
    }

    if (fread(header_buf.buf, header_buf.size, 1, stdin) != 1) {
        fprintf(stderr,
                "Error reading viewgroup header from stdin\n");
        ret = COUCHSTORE_ERROR_INVALID_ARGUMENTS;
        goto out;
    }

    /* Setup stats update frequency to be percentage increment */
    stats.inserted = 0;
    stats.update_fun = stats_updater;
    stats.freq = MAX(total_changes / 100, 1);

    ret = (couchstore_error_t)start_exit_listener(&exit_thread, 1 /*uses_v8*/);
    if (ret) {
        fprintf(stderr, "Error starting stdin exit listener thread\n");
        goto out;
    }

    mapreduce_init(argv[0]);
    ret = couchstore_compact_view_group(group_info,
                                        target_file,
                                        &header_buf,
                                        &stats,
                                        &header_outbuf,
                                        &error_info);
    mapreduce_deinit();

    if (ret != COUCHSTORE_SUCCESS) {
        if (error_info.error_msg != nullptr &&
            error_info.view_name != nullptr) {
            fprintf(stderr,
                    "%s Error compacting index for view `%s`, reason: %s\n",
                    error_info.idx_type,
                    error_info.view_name,
                    error_info.error_msg);
        }
        goto out;
    }

    fprintf(stdout, "Header Len : %zu\n", header_outbuf.size);
    fwrite(header_outbuf.buf, header_outbuf.size, 1, stdout);
    fprintf(stdout, "\n");

    fprintf(stdout, "Results = inserts : %" PRIu64 "\n", stats.inserted);

out:
    couchstore_free_view_group_info(group_info);
    cb_free((void *) error_info.error_msg);
    cb_free((void *) error_info.view_name);
    cb_free((void *) header_buf.buf);
    cb_free((void *) header_outbuf.buf);
    cb_free(target_file);

    int ret_int = (int)ret;
    ret_int = (ret_int < 0) ? (100 + ret_int) : ret_int;
    _exit(ret_int);
}
