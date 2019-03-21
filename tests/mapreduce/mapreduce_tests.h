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

#ifndef _MAPREDUCE_TESTS_H
#define _MAPREDUCE_TESTS_H

#include "couchstore_config.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../macros.h"
#include "../../src/views/mapreduce/mapreduce.h"

/* main test function */
void mapreduce_tests(void);
void map_tests(void);
void reduce_tests(void);
void builtin_tests(void);

#endif
