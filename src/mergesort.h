
#pragma once

#include <cstdio>

/*
 * Returns the length of the record read from the file on success.
 * Returns 0 when the file's EOF is reached, and a negative value
 * on failure.
 */
typedef int (*mergesort_read_record_t)(FILE *f,
                                       void *record_buffer,
                                       void *pointer);

/*
 * Returns zero if the write failed. If the write succeeded, it returns a
 * value different from zero.
 */
typedef int (*mergesort_write_record_t)(FILE *f,
                                        void *record_buffer,
                                        void *pointer);

/*
 * Returns 0 if both records compare equal, a negative value if the first record
 * is smaller than the second record, a positive value if the first record is
 * greater than the second record.
 */
typedef int (*mergesort_compare_records_t)(const void *record_buffer1,
                                           const void *record_buffer2,
                                           void *pointer);

typedef char *(*mergesort_record_alloc_t)(void);
typedef char *(*mergesort_record_duplicate_t)(char *record);
typedef void  (*mergesort_record_free_t)(char *record);

void *sort_linked_list(void *, unsigned, int (*)(void *, void *, void *), void *, unsigned long *);

FILE *openTmpFile(char *path);

int merge_sort(FILE *unsorted_file, FILE *sorted_file,
               char *tmp_path,
               mergesort_read_record_t read,
               mergesort_write_record_t write,
               mergesort_compare_records_t compare,
               mergesort_record_alloc_t record_alloc,
               mergesort_record_duplicate_t record_duplicate,
               mergesort_record_free_t record_free,
               void *pointer,
               unsigned long block_size,
               unsigned long *pcount);

