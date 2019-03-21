/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

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

#ifndef _VIEW_TESTS_H
#define _VIEW_TESTS_H

#include "couchstore_config.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../macros.h"
#include "../src/views/bitmap.h"
#include "../src/views/sorted_list.h"
#include "../src/views/index_header.h"
#include "../src/views/reductions.h"
#include "../src/views/keys.h"
#include "../src/views/values.h"
#include "../src/views/reducers.h"
#include "../src/views/purgers.h"

#ifdef __cplusplus
extern "C" {
#endif

void view_tests(void);
void test_bitmaps(void);
void test_sorted_lists(void);
void test_collate_json(void);
void test_index_headers_v1(void);
void test_index_headers_v2(void);
void test_reductions(void);
void test_keys(void);
void test_values(void);
void reducer_tests(void);
void cleanup_tests(void);

#ifdef __cplusplus
}
#endif

#endif
