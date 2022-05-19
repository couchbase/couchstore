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
#include "util.h"

#include "../mapreduce/mapreduce.h"

#include <platform/dirutils.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <system_error>
#include <thread>

static void do_exit(int ret, int uses_v8)
{
    /* Notify and delete conditional variables,
    and join waiting threads when v8 is used */
    if(uses_v8) {
        deinit_terminator_thread(true /*fatal_exit*/);
    }
    _exit(ret);
}

static void exit_thread_helper(int uses_v8) {
    char buf[4];
    int len = fread(buf, 1, 4, stdin);

    /* If the other end closed the pipe */
    if (len == 0) {
        do_exit(1, uses_v8);
    } else if (len == 4 && !strncmp(buf, "exit", 4)) {
        do_exit(1, uses_v8);
    } else {
        fprintf(stderr, "Error occured waiting for exit message (%d)\n", len);
        do_exit(2, uses_v8);
    }
}

/* Start a watcher thread to gracefully die on exit message */
int start_exit_listener(int uses_v8) {
    auto listener = std::thread{[uses_v8]() { exit_thread_helper(uses_v8); }};
    listener.detach();
    return 0;
}

int set_binary_mode()
{
    try {
        cb::io::setBinaryMode(stdin);
        cb::io::setBinaryMode(stdout);
        cb::io::setBinaryMode(stderr);
    } catch (const std::system_error&) {
        return -1;
    }
    return 0;
}
