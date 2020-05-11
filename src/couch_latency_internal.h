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

#include <libcouchstore/couch_latency.h>
#include <relaxed_atomic.h>

#include <memory>
#include <mutex>
#include <unordered_map>

struct CouchLatencyItem {
    CouchLatencyItem() : latencySum(0), registered(false) {
    }

    CouchLatencyItem(std::string _name)
        : statName(_name),
          latencySum(0),
          registered(false) {
    }

    void add(CouchLatencyMicroSec val) {
        latencies.add(val);
        latencySum.fetch_add(val.count());
    }

    bool isRegistered() const {
        return registered.load();
    }

    void changeRegisterStatus(bool to) {
        registered.store(to);
    }

    void resetHistogram() {
        latencies.reset();
        latencySum = 0;
    }

    uint64_t count() {
        return latencies.total();
    }

    // Name of latency stat.
    const std::string statName;
    // Histogram for latency values (in microseconds).
    CouchLatencyHisto latencies;
    // Sum of all latencies, to calculate average value.
    cb::RelaxedAtomic<CouchLatencyMicroSecRep> latencySum;
    // Flag that indicates whether or not this instance is
    // registered to the singleton CouchLatency instance.
    cb::RelaxedAtomic<bool> registered;
};

// A wrapper for singleton instance, including mutex for guard.
template<typename T>
struct SingletonWrapper {
    SingletonWrapper() {
    }
    SingletonWrapper(T _init) : object(_init) {
    }

    T object;
    std::mutex mutex;
};

// Singleton class
class CouchLatency {
public:
    static CouchLatency* getInstance();

    static CouchLatency* init();

    static void destroyInstance();

    CouchLatencyItem* addItem(CouchLatencyItem* _item);

    void getLatencyInfo(couchstore_latency_callback_fn cb_func,
                        couchstore_latency_dump_options options,
                        void *ctx);

private:
    ~CouchLatency();

    // Global static CouchLatency instance.
    static SingletonWrapper<cb::RelaxedAtomic<CouchLatency*> > instance;

    // Map of {Item name, CouchLatencyItem instance}.
    SingletonWrapper<std::unordered_map<std::string, CouchLatencyItem*> >
            itemsMap;
};

// Wrapper class for GenericBlockTimer to use CouchLatencyItem.
class CouchLatencyTimer {
public:
    CouchLatencyTimer(CouchLatencyItem *_item) : blockTimer(_item) {
    }

private:
    GenericBlockTimer<CouchLatencyItem, 600000ul> blockTimer;
};

#if defined(WIN32) || defined(_WIN32)
#define CL_func_name __FUNCTION__
#else
#define CL_func_name __func__
#endif

#define COLLECT_LATENCY()                                             \
    /* Actual item. */                                                \
    static std::unique_ptr<CouchLatencyItem> CL_item;                 \
    /* Atomic pointer to above instance. */                           \
    static cb::RelaxedAtomic<CouchLatencyItem*> CL_item_ptr(nullptr); \
    CouchLatency* CL_lat_collector = CouchLatency::getInstance();     \
    if (CL_lat_collector) {                                           \
        /* Register the item if                                       \
         * 1) it is the first attempt, OR                             \
         * 2) it was deregistered (or disabled) before. */            \
        CouchLatencyItem* cur_item = CL_item_ptr.load();              \
        if (!cur_item) {                                              \
            /* Case 1) */                                             \
            std::unique_ptr<CouchLatencyItem> tmp;                    \
            tmp = std::make_unique<CouchLatencyItem>(CL_func_name);   \
            CL_item_ptr = CL_lat_collector->addItem(tmp.get());       \
            if (tmp.get() == CL_item_ptr) {                           \
                /* Registration succeeded (only one thread can        \
                 * do this). Move it to static variable. */           \
                CL_item = std::move(tmp);                             \
            } /* Otherwise: discard 'tmp' */                          \
        } else if (!cur_item->isRegistered()) {                       \
            /* Case 2) */                                             \
            CL_item_ptr = CL_lat_collector->addItem(cur_item);        \
        }                                                             \
    } else if (CL_item_ptr.load()) {                                  \
        /* Latency collector is disabled. */                          \
        CL_item_ptr.store(nullptr);                                   \
    }                                                                 \
    CouchLatencyTimer CL_timer(CL_item_ptr)
