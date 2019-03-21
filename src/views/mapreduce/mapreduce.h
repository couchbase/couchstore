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
 * This is the public, plain C interface to expose to the outside.
 **/

#ifndef _MAPREDUCE_H
#define _MAPREDUCE_H

#include "couchstore_config.h"
#include "visibility.h"
#include <libcouchstore/visibility.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

    typedef struct {
        char *json;
        int  length;
    } mapreduce_json_t;

    typedef struct {
        mapreduce_json_t *values;
        int              length;
    } mapreduce_json_list_t;

    typedef struct {
        mapreduce_json_t key;
        mapreduce_json_t value;
    } mapreduce_kv_t;

    typedef enum {
        MAPREDUCE_SUCCESS,
        MAPREDUCE_SYNTAX_ERROR,
        MAPREDUCE_RUNTIME_ERROR,
        MAPREDUCE_ALLOC_ERROR,
        MAPREDUCE_INVALID_ARG,
        MAPREDUCE_TIMEOUT
    } mapreduce_error_t;

    typedef struct {
        mapreduce_kv_t *kvs;
        int            length;
    } mapreduce_kv_list_t;

    typedef struct {
        mapreduce_error_t error;
        union {
            /* valid if error is MAPREDUCE_SUCCESS */
            mapreduce_kv_list_t kvs;
            /* valid if error is other than MAPREDUCE_SUCCESS */
            char                *error_msg;
        } result;
    } mapreduce_map_result_t;

    typedef struct {
        mapreduce_map_result_t *list;
        int                    length;
    } mapreduce_map_result_list_t;

    /**
     * This API needs to be called once per process to initialize
     * v8 javascript engine. This needs to be called before
     * any v8 APIs like creating v8 isolate and v8 context.
     **/
    LIBCOUCHSTORE_API
    void initV8();

    /**
     * This API needs to be called once per process to cleanup
     * v8 resources. This needs to be called after disposing all
     * v8 thread contexts like v8 isolate and v8 context.
     **/
    LIBCOUCHSTORE_API NO_SANITIZE_VPTR void deinitV8();

    /**
     * All mapreduce initialization are done in this function.
     **/
    LIBCOUCHSTORE_API
    void mapreduce_init();

    /**
     * All mapreduce deinitialization are done in this function.
     **/
    LIBCOUCHSTORE_API
    void mapreduce_deinit();

    /**
     * Creates terminator thread to kill long running map reduce tasks.
     **/
    LIBCOUCHSTORE_API
    void init_terminator_thread();

    /**
     * Destroys terminator thread at the end of the process. Setting
     * fatal_exit to true prevents the accidental initialization of
     * terminator_thread in case of exit due to an Erlang signal.
     **/
    LIBCOUCHSTORE_API
    void deinit_terminator_thread(bool fatal_exit);

    /**
     * If return value other than MAPREDUCE_SUCCESS, error_msg might be
     * assigned an error message, for which the caller is responsible to
     * deallocate via mapreduce_free_error_msg().
     **/
    LIBMAPREDUCE_API
    mapreduce_error_t mapreduce_start_map_context(const char *map_functions[],
                                                  int num_functions,
                                                  void **context,
                                                  char **error_msg);

    /**
     * If return value is MAPREDUCE_SUCCESS, the caller is responsible for
     * free'ing result output parameter with a call to
     * mapreduce_free_map_result_list().
     */
    LIBMAPREDUCE_API
    mapreduce_error_t mapreduce_map(void *context,
                                    const mapreduce_json_t *doc,
                                    const mapreduce_json_t *meta,
                                    mapreduce_map_result_list_t **result);

    LIBMAPREDUCE_API
    void mapreduce_free_json_list(mapreduce_json_list_t *list);

    LIBMAPREDUCE_API
    void mapreduce_free_json(mapreduce_json_t *value);

    LIBMAPREDUCE_API
    void mapreduce_free_map_result_list(mapreduce_map_result_list_t *list);

    LIBMAPREDUCE_API
    void mapreduce_free_error_msg(char *error_msg);

    /**
     * If return value other than MAPREDUCE_SUCCESS, error_msg might be
     * assigned an error message, for which the caller is responsible to
     * deallocate via mapreduce_free_error_msg().
     **/
    LIBMAPREDUCE_API
    mapreduce_error_t mapreduce_start_reduce_context(const char *reduce_functions[],
                                                     int num_functions,
                                                     void **context,
                                                     char **error_msg);

    /**
     * If return value other than MAPREDUCE_SUCCESS, error_msg might be
     * assigned an error message, for which the caller is responsible to
     * deallocate via mapreduce_free_error_msg().
     *
     * If return value is MAPREDUCE_SUCCESS, the caller is responsible for
     * free'ing result output parameter with a call to
     * mapreduce_free_json_list().
     */
    LIBMAPREDUCE_API
    mapreduce_error_t mapreduce_reduce_all(void *context,
                                           const mapreduce_json_list_t *keys,
                                           const mapreduce_json_list_t *values,
                                           mapreduce_json_list_t **result,
                                           char **error_msg);

    /**
     * If return value other than MAPREDUCE_SUCCESS, error_msg might be
     * assigned an error message, for which the caller is responsible to
     * deallocate via mapreduce_free_error_msg().
     *
     * If return value is MAPREDUCE_SUCCESS, the caller is responsible for
     * free'ing result output parameter with a call to
     * mapreduce_free_json().
     **/
    LIBMAPREDUCE_API
    mapreduce_error_t mapreduce_reduce(void *context,
                                       int reduceFunNum,
                                       const mapreduce_json_list_t *keys,
                                       const mapreduce_json_list_t *values,
                                       mapreduce_json_t **result,
                                       char **error_msg);

    /**
     * If return value other than MAPREDUCE_SUCCESS, error_msg might be
     * assigned an error message, for which the caller is responsible to
     * deallocate via mapreduce_free_error_msg().
     *
     * If return value is MAPREDUCE_SUCCESS, the caller is responsible for
     * free'ing result output parameter with a call to
     * mapreduce_free_json().
     **/
    LIBMAPREDUCE_API
    mapreduce_error_t mapreduce_rereduce(void *context,
                                         int reduceFunNum,
                                         const mapreduce_json_list_t *reductions,
                                         mapreduce_json_t **result,
                                         char **error_msg);

    LIBMAPREDUCE_API
    void mapreduce_free_context(void *context);

    LIBMAPREDUCE_API
    void mapreduce_set_timeout(unsigned int seconds);


#ifdef __cplusplus
}
#endif

#endif
