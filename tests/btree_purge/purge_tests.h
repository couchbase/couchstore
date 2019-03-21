/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

/**
 * @copyright 2013 Couchbase, Inc.
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

#ifndef _PURGE_TESTS_H
#define _PURGE_TESTS_H

#include "couchstore_config.h"
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

void test_no_purge_items(void);
void test_all_purge_items(void);
void test_partial_purge_items(void);
void test_partial_purge_items2(void);
void test_partial_purge_with_stop(void);
void test_add_remove_purge(void);

void purge_tests(void);
void test_only_single_leafnode(void);

#ifdef __cplusplus
}
#endif

#endif
