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

/**
 * Implementation of all exported (public) functions, pure C.
 **/
#include <condition_variable>
#include <cstring>
#include <iostream>
#include <platform/cb_malloc.h>
#include <platform/cbassert.h>
#include <thread>
#include <unordered_set>

#include "mapreduce.h"
#include "mapreduce_internal.h"

static const char *MEM_ALLOC_ERROR_MSG = "memory allocation failure";
static bool terminator_active = false;

static std::thread terminator_thread;
static std::unique_ptr<std::condition_variable> cv;
static std::mutex  cvMutex, registryMutex, initMutex;
static std::atomic<int> terminator_timeout;
static std::atomic<bool> shutdown_terminator;

static std::unordered_set<mapreduce_ctx_t *> ctx_registry;

static mapreduce_error_t start_context(const char *functions[],
                                       int num_functions,
                                       void **context,
                                       char **error_msg);

static void make_function_list(const char *sources[],
                               int num_sources,
                               std::list<std::string> &list);

static void copy_error_msg(const std::string &msg, char **to);

static void register_ctx(mapreduce_ctx_t *ctx);
static void unregister_ctx(mapreduce_ctx_t *ctx);
static void terminator_loop();


LIBMAPREDUCE_API
mapreduce_error_t mapreduce_start_map_context(const char *map_functions[],
                                              int num_functions,
                                              void **context,
                                              char **error_msg)
{
    return start_context(map_functions, num_functions, context, error_msg);
}


LIBMAPREDUCE_API
mapreduce_error_t mapreduce_map(void *context,
                                const mapreduce_json_t *doc,
                                const mapreduce_json_t *meta,
                                mapreduce_map_result_list_t **result)
{
    mapreduce_ctx_t *ctx = (mapreduce_ctx_t *) context;

    *result = (mapreduce_map_result_list_t *) cb_malloc(sizeof(**result));
    if (*result == NULL) {
        return MAPREDUCE_ALLOC_ERROR;
    }

    int num_funs = ctx->functions->size();
    size_t sz = sizeof(mapreduce_map_result_t) * num_funs;
    (*result)->list = (mapreduce_map_result_t *) cb_malloc(sz);

    if ((*result)->list == NULL) {
        cb_free(*result);
        *result = NULL;
        return MAPREDUCE_ALLOC_ERROR;
    }

    (*result)->length = 0;
    try {
        mapDoc(ctx, *doc, *meta, *result);
    } catch (MapReduceError &e) {
        mapreduce_free_map_result_list(*result);
        *result = NULL;
        return e.getError();
    } catch (std::bad_alloc &) {
        mapreduce_free_map_result_list(*result);
        *result = NULL;
        return MAPREDUCE_ALLOC_ERROR;
    }

    cb_assert((*result)->length == num_funs);
    return MAPREDUCE_SUCCESS;
}


LIBMAPREDUCE_API
mapreduce_error_t mapreduce_start_reduce_context(const char *reduce_functions[],
                                                 int num_functions,
                                                 void **context,
                                                 char **error_msg)
{
    return start_context(reduce_functions, num_functions, context, error_msg);
}


LIBMAPREDUCE_API
mapreduce_error_t mapreduce_reduce_all(void *context,
                                       const mapreduce_json_list_t *keys,
                                       const mapreduce_json_list_t *values,
                                       mapreduce_json_list_t **result,
                                       char **error_msg)
{
    mapreduce_ctx_t *ctx = (mapreduce_ctx_t *) context;

    try {
        json_results_list_t list = runReduce(ctx, *keys, *values);
        size_t sz = list.size();
        json_results_list_t::iterator it = list.begin();

        cb_assert(sz == ctx->functions->size());

        *result = (mapreduce_json_list_t *) cb_malloc(sizeof(**result));
        if (*result == NULL) {
            for ( ; it != list.end(); ++it) {
                cb_free((*it).json);
            }
            throw std::bad_alloc();
        }

        (*result)->length = sz;
        (*result)->values = (mapreduce_json_t *) cb_malloc(sizeof(mapreduce_json_t) * sz);
        if ((*result)->values == NULL) {
            cb_free(*result);
            for ( ; it != list.end(); ++it) {
                cb_free((*it).json);
            }
            throw std::bad_alloc();
        }
        for (int i = 0; it != list.end(); ++it, ++i) {
            (*result)->values[i] = *it;
        }
    } catch (MapReduceError &e) {
        copy_error_msg(e.getMsg(), error_msg);
        *result = NULL;
        return e.getError();
    } catch (std::bad_alloc &) {
        copy_error_msg(MEM_ALLOC_ERROR_MSG, error_msg);
        *result = NULL;
        return MAPREDUCE_ALLOC_ERROR;
    }

    *error_msg = NULL;
    return MAPREDUCE_SUCCESS;
}


LIBMAPREDUCE_API
mapreduce_error_t mapreduce_reduce(void *context,
                                   int reduceFunNum,
                                   const mapreduce_json_list_t *keys,
                                   const mapreduce_json_list_t *values,
                                   mapreduce_json_t **result,
                                   char **error_msg)
{
    mapreduce_ctx_t *ctx = (mapreduce_ctx_t *) context;

    try {
        mapreduce_json_t red = runReduce(ctx, reduceFunNum, *keys, *values);

        *result = (mapreduce_json_t *) cb_malloc(sizeof(**result));
        if (*result == NULL) {
            cb_free(red.json);
            throw std::bad_alloc();
        }
        **result = red;
    } catch (MapReduceError &e) {
        copy_error_msg(e.getMsg(), error_msg);
        *result = NULL;
        return e.getError();
    } catch (std::bad_alloc &) {
        copy_error_msg(MEM_ALLOC_ERROR_MSG, error_msg);
        *result = NULL;
        return MAPREDUCE_ALLOC_ERROR;
    }

    *error_msg = NULL;
    return MAPREDUCE_SUCCESS;
}


LIBMAPREDUCE_API
mapreduce_error_t mapreduce_rereduce(void *context,
                                     int reduceFunNum,
                                     const mapreduce_json_list_t *reductions,
                                     mapreduce_json_t **result,
                                     char **error_msg)
{
    mapreduce_ctx_t *ctx = (mapreduce_ctx_t *) context;

    try {
        mapreduce_json_t red = runRereduce(ctx, reduceFunNum, *reductions);

        *result = (mapreduce_json_t *) cb_malloc(sizeof(**result));
        if (*result == NULL) {
            cb_free(red.json);
            throw std::bad_alloc();
        }
        **result = red;
    } catch (MapReduceError &e) {
        copy_error_msg(e.getMsg(), error_msg);
        *result = NULL;
        return e.getError();
    } catch (std::bad_alloc &) {
        copy_error_msg(MEM_ALLOC_ERROR_MSG, error_msg);
        *result = NULL;
        return MAPREDUCE_ALLOC_ERROR;
    }

    *error_msg = NULL;
    return MAPREDUCE_SUCCESS;
}


LIBMAPREDUCE_API
void mapreduce_free_context(void *context)
{
    if (context != NULL) {
        mapreduce_ctx_t *ctx = (mapreduce_ctx_t *) context;

        unregister_ctx(ctx);
        destroyContext(ctx);
        delete ctx;
    }
}


LIBMAPREDUCE_API
void mapreduce_free_json(mapreduce_json_t *value)
{
    if (value != NULL) {
        cb_free(value->json);
        cb_free(value);
    }
}


LIBMAPREDUCE_API
void mapreduce_free_json_list(mapreduce_json_list_t *list)
{
    if (list != NULL) {
        for (int i = 0; i < list->length; ++i) {
            cb_free(list->values[i].json);
        }
        cb_free(list->values);
        cb_free(list);
    }
}


LIBMAPREDUCE_API
void mapreduce_free_map_result_list(mapreduce_map_result_list_t *list)
{
    if (list == NULL) {
        return;
    }

    for (int i = 0; i < list->length; ++i) {
        mapreduce_map_result_t mr = list->list[i];

        switch (mr.error) {
        case MAPREDUCE_SUCCESS:
            {
                mapreduce_kv_list_t kvs = mr.result.kvs;

                for (int j = 0; j < kvs.length; ++j) {
                    mapreduce_kv_t kv = kvs.kvs[j];
                    cb_free(kv.key.json);
                    cb_free(kv.value.json);
                }
                cb_free(kvs.kvs);
            }
            break;
        default:
            cb_free(mr.result.error_msg);
            break;
        }
    }

    cb_free(list->list);
    cb_free(list);
}


LIBMAPREDUCE_API
void mapreduce_free_error_msg(char *error_msg)
{
    cb_free(error_msg);
}


LIBMAPREDUCE_API
void mapreduce_set_timeout(unsigned int seconds)
{
    std::lock_guard<std::mutex> lk(cvMutex);
    terminator_timeout = seconds;
    cv->notify_one();
}


static mapreduce_error_t start_context(const char *functions[],
                                       int num_functions,
                                       void **context,
                                       char **error_msg)
{
    mapreduce_ctx_t *ctx = NULL;
    mapreduce_error_t ret = MAPREDUCE_SUCCESS;

    try {
        ctx = new mapreduce_ctx_t();
        std::list<std::string> functions_list;

        make_function_list(functions, num_functions, functions_list);
        initContext(ctx, functions_list);
    } catch (MapReduceError &e) {
        copy_error_msg(e.getMsg(), error_msg);
        ret = e.getError();
    } catch (std::bad_alloc &) {
        copy_error_msg(MEM_ALLOC_ERROR_MSG, error_msg);
        ret = MAPREDUCE_ALLOC_ERROR;
    }

    if (ret == MAPREDUCE_SUCCESS) {
        register_ctx(ctx);
        *context = (void *) ctx;
        *error_msg = NULL;
    } else {
        delete ctx;
    }
    return ret;
}


static void make_function_list(const char *sources[],
                               int num_sources,
                               std::list<std::string> &list)
{
    for (int i = 0; i < num_sources; ++i) {
        std::string source;
        size_t len = strlen(sources[i]);

        source.reserve(1 + len + 1);
        source += '(';
        source.append(sources[i], len);
        source += ')';

        list.push_back(source);
    }
}


static void copy_error_msg(const std::string &msg, char **to)
{
    if (to != NULL) {
        size_t len = msg.length();

        *to = (char *) cb_malloc(len + 1);
        if (*to != NULL) {
            msg.copy(*to, len);
            (*to)[len] = '\0';
        }
    }
}

LIBCOUCHSTORE_API
void init_terminator_thread()
{
    std::lock_guard<std::mutex> initGuard(initMutex);
    shutdown_terminator = false;
    // Default 5 seconds for mapreduce tasks
    terminator_timeout = 5;
    try {
        cv = std::unique_ptr<std::condition_variable>(new std::condition_variable());
    }
    catch (std::bad_alloc) {
        std::cerr << "Error creating conditional variable: " << std::endl;
        exit(1);
    }
    try {
        terminator_thread = std::thread(terminator_loop);
    }
    catch (...) {
        std::cerr << "Error creating terminator thread: " << std::endl;
        exit(1);
    }
    terminator_active = true;
}

LIBCOUCHSTORE_API
void deinit_terminator_thread(bool fatal_exit=false)
{
    initMutex.lock();
    if(terminator_active) {
        // There is no conditional wait on this shared variable. Hence no mutex.
        shutdown_terminator = true;
        // Wake the thread up to shutdown
        cv->notify_one();
        terminator_thread.join();
        //delete cv;
        terminator_active = false;
    }
    if(!fatal_exit) initMutex.unlock();
}


LIBCOUCHSTORE_API
void mapreduce_init(const char* executable_img)
{
    initV8(executable_img);
    init_terminator_thread();
}

LIBCOUCHSTORE_API
void mapreduce_deinit()
{
    deinit_terminator_thread();
    deinitV8();
}

static void register_ctx(mapreduce_ctx_t *ctx)
{
    registryMutex.lock();
    bool inserted = ctx_registry.insert(ctx).second;
    registryMutex.unlock();
    cb_assert(inserted == true);
}


static void unregister_ctx(mapreduce_ctx_t *ctx)
{
    registryMutex.lock();
    ctx_registry.erase(ctx);
    registryMutex.unlock();
}


static void terminator_loop()
{
    time_t now;

    while (!shutdown_terminator) {
        registryMutex.lock();
        now = time(NULL);
        for (mapreduce_ctx_t *ctx : ctx_registry) {
            ctx->exitMutex.lock();
            if (ctx->taskStartTime >= 0) {
                if (ctx->taskStartTime + terminator_timeout < now) {
                    terminateTask(ctx);
                }
            }
            ctx->exitMutex.unlock();
        }

        registryMutex.unlock();
        std::unique_lock<std::mutex> lk(cvMutex);
        cv->wait_for(lk, std::chrono::seconds(terminator_timeout));
    }
}
