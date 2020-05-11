/*
 *     Copyright 2020 Couchbase, Inc.
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

struct fatbuf {
    size_t pos;
    size_t size;
    char buf[1];
};

fatbuf* fatbuf_alloc(size_t bytes);
void* fatbuf_get(fatbuf* fb, size_t bytes);
void fatbuf_free(fatbuf* fb);

namespace cb::couchstore {
struct FatbufDeletor {
    void operator()(fatbuf* fb);
};

using unique_fatbuf_ptr = std::unique_ptr<fatbuf, FatbufDeletor>;
} // namespace cb::couchstore
