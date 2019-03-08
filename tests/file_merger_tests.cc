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

#include "config.h"

#include "../src/file_merger.h"
#include "macros.h"
#include <platform/cb_malloc.h>
#include <platform/cbassert.h>
#include <platform/dirutils.h>
#include <stdio.h>
#include <stdlib.h>

#define N_FILES 4
#define MAX_RECORDS_PER_FILE 100

static int read_record(FILE* f, void** buffer, void* ctx) {
    int* rec = (int*)cb_malloc(sizeof(int));
    (void)ctx;

    if (rec == NULL) {
        return FILE_MERGER_ERROR_ALLOC;
    }

    if (fread(rec, sizeof(int), 1, f) != 1) {
        cb_free(rec);
        if (feof(f)) {
            return 0;
        } else {
            return FILE_MERGER_ERROR_FILE_READ;
        }
    }

    *buffer = rec;

    return sizeof(int);
}

static file_merger_error_t write_record(FILE* f, void* buffer, void* ctx) {
    (void)ctx;

    if (fwrite(buffer, sizeof(int), 1, f) != 1) {
        return FILE_MERGER_ERROR_FILE_WRITE;
    }

    return FILE_MERGER_SUCCESS;
}

static int compare_records(const void* rec1, const void* rec2, void* ctx) {
    (void)ctx;

    return *((const int*)rec1) - *((const int*)rec2);
}

static void free_record(void* rec, void* ctx) {
    (void)ctx;

    cb_free(rec);
}

static unsigned long check_file_sorted(const char* file_path) {
    FILE* f;
    void *a = NULL, *b;
    int record_size;
    unsigned long num_records = 0;

    f = fopen(file_path, "rb");
    cb_assert(f != NULL);

    record_size = read_record(f, &a, NULL);
    cb_assert(record_size > 0);
    num_records += 1;

    while (record_size > 0) {
        record_size = read_record(f, &b, NULL);
        cb_assert(record_size >= 0);

        if (record_size > 0) {
            num_records += 1;
            cb_assert(compare_records(a, b, NULL) < 0);
            free_record(a, NULL);
            a = b;
        }
    }

    free_record(a, NULL);
    fclose(f);

    return num_records;
}

int main() {
    const char* source_files[N_FILES] = {"merger_sorted_file_1.tmp",
                                         "merger_sorted_file_2.tmp",
                                         "merger_sorted_file_3.tmp",
                                         "merger_sorted_file_4.tmp"};
    const auto dest_file = cb::io::mktemp("merged_file");

    const int batches[N_FILES][MAX_RECORDS_PER_FILE] = {
            {3,  5,  6,  14, 18, 19, 29, 30, 35, 38, 44, 45,  46,  51,
             54, 57, 62, 65, 75, 76, 81, 83, 91, 92, 95, 104, 105, 107},
            {1,  2,   4,   9,   17,  23,  25,  32,  33,  37, 41, 49,
             55, 58,  61,  68,  70,  71,  72,  77,  80,  87, 89, 94,
             98, 100, 111, 112, 113, 114, 115, 116, 117, 119},
            {10, 12, 15,  20,  21,  22,  27,  34,  36, 39, 42,
             47, 52, 53,  56,  63,  64,  74,  78,  79, 86, 88,
             93, 99, 103, 106, 108, 109, 121, 122, 123},
            {7,  8,  11, 13, 16, 24, 26, 28, 31, 40,  43,  48,  50,  59, 60,
             66, 69, 73, 82, 84, 85, 90, 96, 97, 101, 102, 110, 118, 120}};
    unsigned i, j;
    unsigned num_records = 0;
    file_merger_error_t ret;

    fprintf(stderr, "\nRunning file merger tests...\n");

    for (i = 0; i < N_FILES; ++i) {
        FILE* f;

        remove(source_files[i]);
        f = fopen(source_files[i], "ab");
        cb_assert(f != NULL);

        for (j = 0; j < MAX_RECORDS_PER_FILE; ++j) {
            if (batches[i][j] == 0) {
                break;
            }
            if (j > 0) {
                cb_assert(batches[i][j] > batches[i][j - 1]);
            }
            cb_assert(fwrite(&batches[i][j], sizeof(batches[i][j]), 1, f) == 1);
            num_records += 1;
        }

        fclose(f);
    }

    cb::io::rmrf(dest_file);
    ret = merge_files(source_files,
                      N_FILES,
                      dest_file.c_str(),
                      read_record,
                      write_record,
                      NULL,
                      compare_records,
                      NULL,
                      free_record,
                      0,
                      NULL);

    cb_assert(ret == FILE_MERGER_SUCCESS);
    cb_assert(check_file_sorted(dest_file.c_str()) == num_records);

    for (i = 0; i < N_FILES; ++i) {
        remove(source_files[i]);
    }
    cb::io::rmrf(dest_file);

    fprintf(stderr, "Running file merger tests passed\n\n");
    return 0;
}
