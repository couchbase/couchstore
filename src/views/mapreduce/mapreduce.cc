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

#include "mapreduce.h"
#include "mapreduce_internal.h"
#include <iostream>
#include <cstring>
#include <platform/cb_malloc.h>
#include <stdlib.h>
// This is libv8_libplatform library which handles garbage collection for v8
#include <libplatform/libplatform.h>

using namespace v8;
typedef struct {
    Persistent<Object>    jsonObject;
    Persistent<Function>  jsonParseFun;
    Persistent<Function>  stringifyFun;
    mapreduce_ctx_t       *ctx;
} isolate_data_t;


static const char *SUM_FUNCTION_STRING =
    "(function(values) {"
    "    var sum = 0;"
    "    for (var i = 0; i < values.length; ++i) {"
    "        sum += values[i];"
    "    }"
    "    return sum;"
    "})";

static const char *DATE_FUNCTION_STRING =
    // I wish it was on the prototype, but that will require bigger
    // C changes as adding to the date prototype should be done on
    // process launch. The code you see here may be faster, but it
    // is less JavaScripty.
    // "Date.prototype.toArray = (function() {"
    "(function(date) {"
    "    date = date.getUTCDate ? date : new Date(date);"
    "    return isFinite(date.valueOf()) ?"
    "      [date.getUTCFullYear(),"
    "      (date.getUTCMonth() + 1),"
    "       date.getUTCDate(),"
    "       date.getUTCHours(),"
    "       date.getUTCMinutes(),"
    "       date.getUTCSeconds()] : null;"
    "})";

static const char *BASE64_FUNCTION_STRING =
    "(function(b64) {"
    "    var i, j, l, tmp, scratch, arr = [];"
    "    var lookup = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';"
    "    if (typeof b64 !== 'string') {"
    "        throw 'Input is not a string';"
    "    }"
    "    if (b64.length % 4 > 0) {"
    "        throw 'Invalid base64 source.';"
    "    }"
    "    scratch = b64.indexOf('=');"
    "    scratch = scratch > 0 ? b64.length - scratch : 0;"
    "    l = scratch > 0 ? b64.length - 4 : b64.length;"
    "    for (i = 0, j = 0; i < l; i += 4, j += 3) {"
    "        tmp = (lookup.indexOf(b64[i]) << 18) | (lookup.indexOf(b64[i + 1]) << 12);"
    "        tmp |= (lookup.indexOf(b64[i + 2]) << 6) | lookup.indexOf(b64[i + 3]);"
    "        arr.push((tmp & 0xFF0000) >> 16);"
    "        arr.push((tmp & 0xFF00) >> 8);"
    "        arr.push(tmp & 0xFF);"
    "    }"
    "    if (scratch === 2) {"
    "        tmp = (lookup.indexOf(b64[i]) << 2) | (lookup.indexOf(b64[i + 1]) >> 4);"
    "        arr.push(tmp & 0xFF);"
    "    } else if (scratch === 1) {"
    "        tmp = (lookup.indexOf(b64[i]) << 10) | (lookup.indexOf(b64[i + 1]) << 4);"
    "        tmp |= (lookup.indexOf(b64[i + 2]) >> 2);"
    "        arr.push((tmp >> 8) & 0xFF);"
    "        arr.push(tmp & 0xFF);"
    "    }"
    "    return arr;"
    "})";



static Local<Context> createJsContext();
static void emit(const FunctionCallbackInfo<Value> &args);

static void doInitContext(mapreduce_ctx_t *ctx);
static Handle<Function> compileFunction(const std::string &function);
static std::string exceptionString(const TryCatch &tryCatch);
static void loadFunctions(mapreduce_ctx_t *ctx,
                          const std::list<std::string> &function_sources);
static inline isolate_data_t *getIsolateData();
static inline mapreduce_json_t jsonStringify(const Handle<Value> &obj);
static inline Handle<Value> jsonParse(const mapreduce_json_t &thing);
static inline void taskStarted(mapreduce_ctx_t *ctx);
static inline void taskFinished(mapreduce_ctx_t *ctx);
static void freeKvListEntries(kv_list_int_t &kvs);
static void freeJsonListEntries(json_results_list_t &list);
static inline Handle<Array> jsonListToJsArray(const mapreduce_json_list_t &list);

static std::unique_ptr<v8::Platform> v8platform;

void initV8(const char* executable_img)
{
    V8::InitializeICUDefaultLocation(executable_img, nullptr);
    v8platform = platform::NewDefaultPlatform();
    V8::InitializePlatform(v8platform.get());
    V8::Initialize();
}

void deinitV8()
{
    V8::Dispose();
    V8::ShutdownPlatform();
}

void initContext(mapreduce_ctx_t *ctx,
                 const std::list<std::string> &function_sources)
{
    doInitContext(ctx);

    try {
        Locker locker(ctx->isolate);
        Isolate::Scope isolate_scope(ctx->isolate);
        HandleScope handle_scope(ctx->isolate);
        Local<Context> context =
            Local<Context>::New(ctx->isolate, ctx->jsContext);
        Context::Scope context_scope(context);

        loadFunctions(ctx, function_sources);
    } catch (...) {
        destroyContext(ctx);
        throw;
    }
}


void destroyContext(mapreduce_ctx_t *ctx)
{
    {
        Locker locker(ctx->isolate);
        Isolate::Scope isolate_scope(ctx->isolate);
        HandleScope handle_scope(ctx->isolate);
        Local<Context> context =
            Local<Context>::New(ctx->isolate, ctx->jsContext);
        Context::Scope context_scope(context);

        for (unsigned int i = 0; i < ctx->functions->size(); ++i) {
            (*ctx->functions)[i]->Reset();
            delete (*ctx->functions)[i];

        }
        delete ctx->functions;

        isolate_data_t *isoData = getIsolateData();
        isoData->jsonObject.Reset();
        isoData->jsonParseFun.Reset();
        isoData->stringifyFun.Reset();
        delete isoData;

        ctx->jsContext.Reset();
    }

    ctx->isolate->Dispose();
    delete ctx->bufAllocator;
}

static Local<String> createUtf8String(Isolate *isolate, const char *str)
{
    return String::NewFromUtf8(isolate, str,
        NewStringType::kNormal).ToLocalChecked();
}

static Local<String> createUtf8String(Isolate *isolate, const char *str,
                                      size_t len)
{
    return String::NewFromUtf8(isolate, str,
        NewStringType::kNormal, len).ToLocalChecked();
}

static void doInitContext(mapreduce_ctx_t *ctx)
{
    ctx->bufAllocator = ArrayBuffer::Allocator::NewDefaultAllocator();
    Isolate::CreateParams createParams;
    createParams.array_buffer_allocator = ctx->bufAllocator;
    ctx->isolate = Isolate::New(createParams);
    Locker locker(ctx->isolate);
    Isolate::Scope isolate_scope(ctx->isolate);

    HandleScope handle_scope(ctx->isolate);
    ctx->jsContext.Reset(ctx->isolate, createJsContext());
    Local<Context> context = Local<Context>::New(ctx->isolate, ctx->jsContext);
    Context::Scope context_scope(context);
    Local<String> jsonString = createUtf8String(ctx->isolate, "JSON");
    Handle<Object> jsonObject =
        Local<Object>::Cast(context->Global()->Get(context, jsonString).ToLocalChecked());

    Local<String> parseString = createUtf8String(ctx->isolate, "parse");
    Handle<Function> parseFun =
        Local<Function>::Cast(jsonObject->Get(context, parseString).ToLocalChecked());
    Local<String> stringifyString = createUtf8String(ctx->isolate, "stringify");
    Handle<Function> stringifyFun =
        Local<Function>::Cast(jsonObject->Get(context, stringifyString).ToLocalChecked());

    isolate_data_t *isoData = new isolate_data_t();
    isoData->jsonObject.Reset(ctx->isolate, jsonObject);
    isoData->jsonParseFun.Reset(ctx->isolate, parseFun);
    isoData->stringifyFun.Reset(ctx->isolate, stringifyFun);
    isoData->ctx = ctx;

    ctx->isolate->SetData(0, (void *)isoData);
    ctx->taskStartTime = -1;
}


static Local<Context> createJsContext()
{
    Isolate *isolate = Isolate::GetCurrent();
    EscapableHandleScope handle_scope(isolate);

    Handle<ObjectTemplate> global = ObjectTemplate::New(isolate);
    global->Set(createUtf8String(isolate, "emit"),
            FunctionTemplate::New(isolate, emit));

    Handle<Context> context = Context::New(isolate, nullptr, global);
    Context::Scope context_scope(context);

    Handle<Function> sumFun = compileFunction(SUM_FUNCTION_STRING);
    CHECK_SUCCESS(context->Global()->Set(context, createUtf8String(isolate, "sum"), sumFun));

    Handle<Function> decodeBase64Fun =
        compileFunction(BASE64_FUNCTION_STRING);
    CHECK_SUCCESS(context->Global()->Set(context, createUtf8String(isolate, "decodeBase64"),
        decodeBase64Fun));

    Handle<Function> dateToArrayFun =
        compileFunction(DATE_FUNCTION_STRING);
    CHECK_SUCCESS(context->Global()->Set(context, createUtf8String(isolate, "dateToArray"),
                           dateToArrayFun));

    // Use EscapableHandleScope and return using .Escape
    // This will ensure that return values are not garbage collected
    // as soon as the function returns.
    return handle_scope.Escape(context);
}


void mapDoc(mapreduce_ctx_t *ctx,
            const mapreduce_json_t &doc,
            const mapreduce_json_t &meta,
            mapreduce_map_result_list_t *results)
{
    Locker locker(ctx->isolate);
    Isolate::Scope isolate_scope(ctx->isolate);
    HandleScope handle_scope(ctx->isolate);
    Local<Context> context = Local<Context>::New(ctx->isolate, ctx->jsContext);
    Context::Scope context_scope(context);
    Handle<Value> docObject = jsonParse(doc);
    Handle<Value> metaObject = jsonParse(meta);


    if (!metaObject->IsObject()) {
        throw MapReduceError(MAPREDUCE_INVALID_ARG,
                "metadata is not a JSON object");
    }

    Handle<Value> funArgs[] = { docObject, metaObject };

    taskStarted(ctx);
    kv_list_int_t kvs;
    ctx->kvs = &kvs;

    for (unsigned int i = 0; i < ctx->functions->size(); ++i) {
        mapreduce_map_result_t mapResult;
        Local<Function> fun =
            Local<Function>::New(ctx->isolate, *(*ctx->functions)[i]);
        TryCatch try_catch(ctx->isolate);
        Handle<Value> result;

        if (fun->Call(context, context->Global(), 2, funArgs).ToLocal(&result)) {
            mapResult.error = MAPREDUCE_SUCCESS;
            mapResult.result.kvs.length = kvs.size();
            size_t sz = sizeof(mapreduce_kv_t) * mapResult.result.kvs.length;
            mapResult.result.kvs.kvs = (mapreduce_kv_t *) cb_malloc(sz);
            if (mapResult.result.kvs.kvs == nullptr) {
                freeKvListEntries(kvs);
                throw std::bad_alloc();
            }
            kv_list_int_t::iterator it = kvs.begin();
            for (int j = 0; it != kvs.end(); ++it, ++j) {
                mapResult.result.kvs.kvs[j] = *it;
            }
        } else {
            freeKvListEntries(kvs);

            if (!try_catch.CanContinue()) {
                throw MapReduceError(MAPREDUCE_TIMEOUT, "timeout");
            }

            mapResult.error = MAPREDUCE_RUNTIME_ERROR;
            std::string exceptString = exceptionString(try_catch);
            size_t len = exceptString.length();

            mapResult.result.error_msg = (char *) cb_malloc(len + 1);
            if (mapResult.result.error_msg == nullptr) {
                throw std::bad_alloc();
            }
            memcpy(mapResult.result.error_msg, exceptString.data(), len);
            mapResult.result.error_msg[len] = '\0';
        }

        results->list[i] = mapResult;
        results->length += 1;
        kvs.clear();
    }

    taskFinished(ctx);
}


json_results_list_t runReduce(mapreduce_ctx_t *ctx,
                              const mapreduce_json_list_t &keys,
                              const mapreduce_json_list_t &values)
{
    Locker locker(ctx->isolate);
    Isolate::Scope isolateScope(ctx->isolate);
    HandleScope handle_scope(ctx->isolate);
    Local<Context> context = Local<Context>::New(ctx->isolate, ctx->jsContext);
    Context::Scope context_scope(context);
    Handle<Array> keysArray = jsonListToJsArray(keys);
    Handle<Array> valuesArray = jsonListToJsArray(values);
    json_results_list_t results;

    Handle<Value> args[] =
        { keysArray, valuesArray, Boolean::New(ctx->isolate, false) };

    taskStarted(ctx);

    for (unsigned int i = 0; i < ctx->functions->size(); ++i) {
        Local<Function> fun =
            Local<Function>::New(ctx->isolate, *(*ctx->functions)[i]);
        TryCatch try_catch(ctx->isolate);
        Handle<Value> result;

        if (!fun->Call(context, context->Global(), 3, args).ToLocal(&result)) {
            freeJsonListEntries(results);

            if (!try_catch.CanContinue()) {
                throw MapReduceError(MAPREDUCE_TIMEOUT, "timeout");
            }

            throw MapReduceError(MAPREDUCE_RUNTIME_ERROR,
                    exceptionString(try_catch));
        }

        try {
            mapreduce_json_t jsonResult = jsonStringify(result);
            results.push_back(jsonResult);
        } catch(...) {
            freeJsonListEntries(results);
            throw;
        }
    }

    taskFinished(ctx);

    return results;
}


mapreduce_json_t runReduce(mapreduce_ctx_t *ctx,
                           int reduceFunNum,
                           const mapreduce_json_list_t &keys,
                           const mapreduce_json_list_t &values)
{
    Locker locker(ctx->isolate);
    Isolate::Scope isolateScope(ctx->isolate);
    HandleScope handle_scope(ctx->isolate);
    Local<Context> context = Local<Context>::New(ctx->isolate, ctx->jsContext);
    Context::Scope context_scope(context);

    reduceFunNum -= 1;
    if (reduceFunNum < 0 ||
        static_cast<unsigned int>(reduceFunNum) >= ctx->functions->size()) {
        throw MapReduceError(MAPREDUCE_INVALID_ARG,
                "invalid reduce function number");
    }

    Local<Function> fun =
        Local<Function>::New(ctx->isolate, *(*ctx->functions)[reduceFunNum]);
    Handle<Array> keysArray = jsonListToJsArray(keys);
    Handle<Array> valuesArray = jsonListToJsArray(values);
    Handle<Value> args[] =
        { keysArray, valuesArray, Boolean::New(ctx->isolate, false) };

    taskStarted(ctx);

    TryCatch try_catch(ctx->isolate);
    Handle<Value> result;
    bool isEmpty = !fun->Call(context, context->Global(), 3, args).ToLocal(&result);

    taskFinished(ctx);

    if (isEmpty) {
        if (!try_catch.CanContinue()) {
            throw MapReduceError(MAPREDUCE_TIMEOUT, "timeout");
        }

        throw MapReduceError(MAPREDUCE_RUNTIME_ERROR,
                exceptionString(try_catch));
    }

    return jsonStringify(result);
}


mapreduce_json_t runRereduce(mapreduce_ctx_t *ctx,
                             int reduceFunNum,
                             const mapreduce_json_list_t &reductions)
{
    Locker locker(ctx->isolate);
    Isolate::Scope isolateScope(ctx->isolate);
    HandleScope handle_scope(ctx->isolate);
    Local<Context> context = Local<Context>::New(ctx->isolate, ctx->jsContext);
    Context::Scope context_scope(context);

    reduceFunNum -= 1;
    if (reduceFunNum < 0 ||
        static_cast<unsigned int>(reduceFunNum) >= ctx->functions->size()) {
        throw MapReduceError(MAPREDUCE_INVALID_ARG,
                "invalid reduce function number");
    }

    Local<Function> fun =
        Local<Function>::New(ctx->isolate, *(*ctx->functions)[reduceFunNum]);
    Handle<Array> valuesArray = jsonListToJsArray(reductions);
    Handle<Value> args[] =
        { Null(ctx->isolate), valuesArray, Boolean::New(ctx->isolate, true) };

    taskStarted(ctx);

    TryCatch try_catch(ctx->isolate);
    Handle<Value> result;
    bool isEmpty = !fun->Call(context, context->Global(), 3, args).ToLocal(&result);

    taskFinished(ctx);

    if (isEmpty) {
        if (!try_catch.CanContinue()) {
            throw MapReduceError(MAPREDUCE_TIMEOUT, "timeout");
        }

        throw MapReduceError(MAPREDUCE_RUNTIME_ERROR,
                exceptionString(try_catch));
    }

    return jsonStringify(result);
}


void terminateTask(mapreduce_ctx_t *ctx)
{
    ctx->isolate->TerminateExecution();
    ctx->taskStartTime = -1;
}


static void freeKvListEntries(kv_list_int_t &kvs)
{
    kv_list_int_t::iterator it = kvs.begin();

    for ( ; it != kvs.end(); ++it) {
        mapreduce_kv_t kv = *it;
        cb_free(kv.key.json);
        cb_free(kv.value.json);
    }
    kvs.clear();
}


static void freeJsonListEntries(json_results_list_t &list)
{
    json_results_list_t::iterator it = list.begin();

    for ( ; it != list.end(); ++it) {
        cb_free((*it).json);
    }
    list.clear();
}


static Handle<Function> compileFunction(const std::string &funSource)
{
    Isolate *isolate = Isolate::GetCurrent();
    Local<Context> context(isolate->GetCurrentContext());
    EscapableHandleScope handle_scope(isolate);
    TryCatch try_catch(isolate);
    Local<String> source = createUtf8String(isolate, funSource.data(),
        funSource.length());
    Local<Script> script;
    if (!Script::Compile(context, source).ToLocal(&script)) {
        throw MapReduceError(MAPREDUCE_SYNTAX_ERROR,
                exceptionString(try_catch));
    }

    if (script.IsEmpty()) {
        throw MapReduceError(MAPREDUCE_SYNTAX_ERROR,
                exceptionString(try_catch));
    }

    MaybeLocal<Value> result = script->Run(context);
    Local<Value> retval;

    if (!result.ToLocal(&retval)) {
        throw MapReduceError(MAPREDUCE_SYNTAX_ERROR,
                exceptionString(try_catch));
    }

    if (retval.IsEmpty()) {
        throw MapReduceError(MAPREDUCE_SYNTAX_ERROR,
                exceptionString(try_catch));
    }

    if (!retval->IsFunction()) {
        throw MapReduceError(MAPREDUCE_SYNTAX_ERROR,
                std::string("Invalid function: ") + funSource.c_str());
    }

    // Use EscapableHandleScope and return using .Escape
    // This will ensure that return values are not garbage collected
    // as soon as the function returns.
    return handle_scope.Escape(Handle<Function>::Cast(retval));
}


static std::string exceptionString(const TryCatch &tryCatch)
{
    Isolate *isolate = Isolate::GetCurrent();
    Local<Context> context(isolate->GetCurrentContext());
    HandleScope handle_scope(Isolate::GetCurrent());
    String::Utf8Value exception(isolate, tryCatch.Exception());
    const char *exceptionString = (*exception);

    if (exceptionString) {
        Handle<Message> message = tryCatch.Message();
        return std::string(exceptionString) + " (line " +
            std::to_string(message->GetLineNumber(context).FromMaybe(0)) + ":" +
            std::to_string(message->GetStartColumn()) + ")";
    }

    return std::string("runtime error");
}


static void loadFunctions(mapreduce_ctx_t *ctx,
                          const std::list<std::string> &function_sources)
{
    HandleScope handle_scope(ctx->isolate);

    ctx->functions = new function_vector_t();

    std::list<std::string>::const_iterator it = function_sources.begin();

    for ( ; it != function_sources.end(); ++it) {
        Handle<Function> fun = compileFunction(*it);
        Persistent<Function> *perFn = new Persistent<Function>();
        perFn->Reset(ctx->isolate, fun);
        ctx->functions->push_back(perFn);
    }
}


static void emit(const FunctionCallbackInfo<Value> &args)
{
    isolate_data_t *isoData = getIsolateData();

    if (isoData->ctx->kvs == nullptr) {
        return;
    }

    try {
        mapreduce_kv_t result;

        result.key   = jsonStringify(args[0]);
        result.value = jsonStringify(args[1]);
        isoData->ctx->kvs->push_back(result);

        return;
    } catch(Local<String> &ex) {
        isoData->ctx->isolate->ThrowException(ex);
    }
}


static inline isolate_data_t *getIsolateData()
{
    Isolate *isolate = Isolate::GetCurrent();
    return reinterpret_cast<isolate_data_t*>(isolate->GetData(0));
}


static inline mapreduce_json_t jsonStringify(const Handle<Value> &obj)
{
    isolate_data_t *isoData = getIsolateData();
    Local<Context> context(isoData->ctx->isolate->GetCurrentContext());
    Handle<Value> args[] = { obj };
    TryCatch try_catch(isoData->ctx->isolate);
    Local<Function> stringifyFun =
        Local<Function>::New(isoData->ctx->isolate, isoData->stringifyFun);
    Local<Object> jsonObject =
        Local<Object>::New(isoData->ctx->isolate, isoData->jsonObject);
    Handle<Value> result;
    bool isEmpty = !stringifyFun->Call(context, jsonObject, 1, args).ToLocal(&result);

    if (isEmpty) {
        throw try_catch.Exception();
    }

    mapreduce_json_t jsonResult;

    if (!result->IsUndefined()) {
        Handle<String> str = Handle<String>::Cast(result);
        jsonResult.length = str->Utf8Length(isoData->ctx->isolate);
        jsonResult.json = (char *) cb_malloc(jsonResult.length);
        if (jsonResult.json == nullptr) {
            throw std::bad_alloc();
        }
        str->WriteUtf8(isoData->ctx->isolate,
                       jsonResult.json,
                       jsonResult.length,
                       nullptr,
                       String::NO_NULL_TERMINATION);
    } else {
        jsonResult.length = sizeof("null") - 1;
        jsonResult.json = (char *) cb_malloc(jsonResult.length);
        if (jsonResult.json == nullptr) {
            throw std::bad_alloc();
        }
        memcpy(jsonResult.json, "null", jsonResult.length);
    }

    // Caller responsible for freeing jsonResult.json
    return jsonResult;
}


static inline Handle<Value> jsonParse(const mapreduce_json_t &thing)
{
    isolate_data_t *isoData = getIsolateData();
    Local<Context> context(isoData->ctx->isolate->GetCurrentContext());
    Handle<Value> args[] =
        { createUtf8String(isoData->ctx->isolate, thing.json,
            thing.length) };
    TryCatch try_catch(isoData->ctx->isolate);
    Local<Function> jsonParseFun =
        Local<Function>::New(isoData->ctx->isolate, isoData->jsonParseFun);
    Local<Object> jsonObject =
        Local<Object>::New(isoData->ctx->isolate, isoData->jsonObject);
    Handle<Value> result;
    bool isEmpty = !jsonParseFun->Call(context, jsonObject, 1, args).ToLocal(&result);

    if (isEmpty) {
        throw MapReduceError(MAPREDUCE_RUNTIME_ERROR,
                exceptionString(try_catch));
    }

    return result;
}


static inline void taskStarted(mapreduce_ctx_t *ctx)
{
    ctx->taskStartTime = time(nullptr);
    ctx->kvs = nullptr;
}


static inline void taskFinished(mapreduce_ctx_t *ctx)
{
    ctx->exitMutex.lock();
    ctx->taskStartTime = -1;
    ctx->exitMutex.unlock();
}


static inline Handle<Array> jsonListToJsArray(const mapreduce_json_list_t &list)
{
    Isolate *isolate = Isolate::GetCurrent();
    Local<Context> context(isolate->GetCurrentContext());
    Handle<Array> array = Array::New(isolate, list.length);

    for (int i = 0 ; i < list.length; ++i) {
        Handle<Value> v = jsonParse(list.values[i]);
        CHECK_SUCCESS(array->Set(context, Number::New(isolate, i), v));
    }

    return array;
}
