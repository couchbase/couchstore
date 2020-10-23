/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2017 Couchbase, Inc
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

#pragma once

#include "couch_common.h"

#include <libcouchstore/visibility.h>
#include <platform/histogram.h>
#include <platform/processclock.h>

using CouchLatencyHisto = MicrosecondHistogram;
using CouchLatencyMicroSec = UnsignedMicroseconds;
using CouchLatencyMicroSecRep = UnsignedMicroseconds::rep;

/**
 * Begin to collect Couchstore API latency.
 */
LIBCOUCHSTORE_API
void couchstore_latency_collector_start();

/**
 * The callback function used by couchstore_get_latency_info(),
 * to get latency histogram data.
 *
 * @param stat_name Name of statistic item.
 * @param latencies Latency histogram of the statistic item.
 * @param elapsed_time Total elapsed time in microseconds.
 * @param ctx User context
 * @return 1 to stop getting latency info, 0 otherwise.
 */
using couchstore_latency_callback_fn =
        std::function<int(const char*,
                          CouchLatencyHisto* latencies,
                          const CouchLatencyMicroSecRep elapsed_time,
                          void* ctx)>;

/**
 * Latency info dump options.
 */
struct couchstore_latency_dump_options {
    /**
     * Currently empty, but left it for future extension.
     */
};

/**
 * Dump collected latency data through the given
 * callback function.
 *
 * @param callback Callback function.
 * @param options Latency dump options.
 * @param ctx User context
 */
LIBCOUCHSTORE_API
void couchstore_get_latency_info(couchstore_latency_callback_fn callback,
                                 couchstore_latency_dump_options options,
                                 void *ctx);

/**
 * Stop collecting Couchstore API latency.
 */
LIBCOUCHSTORE_API
void couchstore_latency_collector_stop();

