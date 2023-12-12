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

#include "view_tests.h"
#include "spatial_tests.h"


void view_tests()
{
    fprintf(stderr, "\n\nRunning view tests\n\n");

    test_bitmaps();
    test_sorted_lists();
    test_collate_json();
    test_reductions();
    test_keys();
    test_values();
    reducer_tests();
    cleanup_tests();

    /* spatial tests */
    test_interleaving();
    test_spatial_scale_factor();
    test_spatial_center();
    test_spatial_scale_point();
    test_set_bit_sized();
    test_encode_spatial_key();
    test_decode_spatial_key();
    test_expand_mbb();
    test_view_spatial_reduce();
}
