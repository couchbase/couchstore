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

#include "couch_latency_internal.h"

SingletonWrapper<cb::RelaxedAtomic<CouchLatency*> > CouchLatency::instance(
        cb::RelaxedAtomic<CouchLatency*>(nullptr));

CouchLatency* CouchLatency::init() {
    CouchLatency* tmp = instance.object.load();
    if (tmp == nullptr) {
        // Ensure two threads don't both create an instance.
        std::lock_guard<std::mutex> lock(instance.mutex);
        tmp = instance.object.load();
        if (tmp == nullptr) {
            tmp = new CouchLatency();
            instance.object.store(tmp);
        }
    }
    return tmp;
}

CouchLatency* CouchLatency::getInstance() {
    // Instance should be initialized explicitly.
    return instance.object.load();
}

void CouchLatency::destroyInstance() {
    std::lock_guard<std::mutex> lock(instance.mutex);
    CouchLatency* tmp = instance.object.load();
    if (tmp != nullptr) {
        delete tmp;
        instance.object = nullptr;
    }
}

CouchLatency::~CouchLatency() {
    // Deregister all items, and reset their Histograms.
    // As CouchLatencyItem itself is a static unique_ptr
    // that is owned by each API functions,
    // it doesn't need to be destroyed here.
    for (auto& itr : itemsMap.object) {
        itr.second->changeRegisterStatus(false);
        itr.second->resetHistogram();
    }
}

CouchLatencyItem* CouchLatency::addItem(CouchLatencyItem* item) {
    // This lock will be grabbed during the registration phase only.
    // Once an item is registered, they will run in a lock-free manner.
    std::lock_guard<std::mutex> l(itemsMap.mutex);
    auto itr = itemsMap.object.find(item->statName);
    if (itr != itemsMap.object.end()) {
        // Already registered by other thread.
        // Return it.
        return itr->second;
    }
    itemsMap.object.insert( std::make_pair(item->statName, item) );
    item->changeRegisterStatus(true);
    return item;
}

void CouchLatency::getLatencyInfo(couchstore_latency_callback_fn cb_func,
                                  couchstore_latency_dump_options options,
                                  void *ctx) {
    (void)options;
    for (auto& itr : itemsMap.object) {
        CouchLatencyItem *item = itr.second;
        if (!item->latencySum) {
            continue;
        }
        int ret = cb_func(item->statName.c_str(),
                          &item->latencies,
                          item->latencySum,
                          ctx);
        if (ret) {
            // Abort by user.
            break;
        }
    }
}

LIBCOUCHSTORE_API
void couchstore_latency_collector_start() {
    CouchLatency::init();
}

LIBCOUCHSTORE_API
void couchstore_get_latency_info(couchstore_latency_callback_fn callback,
                                 couchstore_latency_dump_options options,
                                 void *ctx) {
    CouchLatency* tmp = CouchLatency::getInstance();
    if (!tmp) {
        // Latency collector is disabled.
        return;
    }
    tmp->getLatencyInfo(callback, options, ctx);
}


LIBCOUCHSTORE_API
void couchstore_latency_collector_stop() {
    CouchLatency::destroyInstance();
}


