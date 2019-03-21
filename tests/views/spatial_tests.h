/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

/**
 * @copyright 2013 Couchbase, Inc.
 *
 * @author Volker Mische <volker@couchbase.com>
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

#ifndef _VIEW_SPATIAL_TESTS_H
#define _VIEW_SPATIAL_TESTS_H

#include "couchstore_config.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include "../macros.h"
#include "../src/views/bitmap.h"
#include "../src/views/spatial.h"

/* Those functions are normaly static. They are declared here to prevent
 * compile time warning */
couchstore_error_t encode_spatial_key(const sized_mbb_t *mbb,
                                      char *key,
                                      size_t nkey);
couchstore_error_t decode_spatial_key(const char *key, sized_mbb_t *mbb);
couchstore_error_t expand_mbb(sized_mbb_t *original, sized_mbb_t *expander);


void test_interleaving(void);
void test_spatial_scale_factor(void);
void test_spatial_center(void);
void test_spatial_scale_point(void);
void test_set_bit_sized(void);
void test_encode_spatial_key(void);
void test_decode_spatial_key(void);
void test_expand_mbb(void);
void test_view_spatial_reduce(void);

#endif
