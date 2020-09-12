/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* Merge Sort
   by Philip J. Erdelsky
   pje@efgh.com
   http://www.efgh.com/software/mergesor.htm
*/
#include "mergesort.h"
#include "couchstore_config.h"
#include "internal.h"
#include "util.h"

#include <platform/cb_malloc.h>
#include <stdlib.h>
#include <string.h>
struct record_in_memory {
    struct record_in_memory *next;
    char *record;
};

struct compare_info {
    mergesort_compare_records_t compare;
    void *pointer;
};

struct tape {
    FILE *fp;
    unsigned long count;
    char path[PATH_MAX];
};

static void free_memory_blocks(struct record_in_memory *first,
                               mergesort_record_free_t record_free)
{
    while (first != NULL) {
        struct record_in_memory *next = first->next;
        (*record_free)(first->record);
        cb_free(first);
        first = next;
    }
}

static int compare_records(void *p, void *q, void *pointer)
{
#define pp ((struct record_in_memory *) p)
#define qq ((struct record_in_memory *) q)
#define point ((struct compare_info *) pointer)
    return (*point->compare)(pp->record, qq->record, point->pointer);
}

FILE *openTmpFile(char *path) {
    FILE *tempFile = NULL;
    int pos = strlen(path);
    // If file name is 4.couch.2.compact.btree-tmp_356
    // pull out suffix as int in reverse i.e 653
    // increment suffix by 1 to 654
    // append new suffix in reverse as 4.couch.2.compact.btree-tmp_456
    int suffix = 0;
    while (path[--pos] != '_'){ // ok to crash on underflow
        suffix = suffix * 10 + (path[pos] - '0'); // atoi
    }

    suffix++;

    // do itoa in reverse
    while (suffix) {
        int tens = suffix % 10;
        path[++pos] = tens + '0';
        suffix = suffix / 10;
    }
    path[++pos] = '\0';

    tempFile = fopen(path, "w+b");

    return tempFile;
}

void releaseTmpFile(struct tape *tmp_file) {
    if (tmp_file) {
        fclose(tmp_file->fp);
        remove(tmp_file->path);
    }
}

#define OK                   COUCHSTORE_SUCCESS
#define INSUFFICIENT_MEMORY  COUCHSTORE_ERROR_ALLOC_FAIL
#define FILE_CREATION_ERROR  COUCHSTORE_ERROR_OPEN_FILE
#define FILE_WRITE_ERROR     COUCHSTORE_ERROR_WRITE
#define FILE_READ_ERROR      COUCHSTORE_ERROR_READ

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
               unsigned long *pcount)
{
    struct tape source_tape[2];
    char *record[2];
    /* allocate memory */
    if ((record[0] = (*record_alloc)()) == NULL) {
        return INSUFFICIENT_MEMORY;
    }
    if ((record[1] = (*record_alloc)()) == NULL) {
        (*record_free)(record[0]);
        return INSUFFICIENT_MEMORY;
    }
    /* create temporary files source_tape[0] and source_tape[1] */
    source_tape[0].fp = openTmpFile(tmp_path);
    source_tape[0].count = 0L;
    if (source_tape[0].fp == NULL) {
        (*record_free)(record[0]);
        (*record_free)(record[1]);
        return FILE_CREATION_ERROR;
    }
    if (strncpy_safe(source_tape[0].path, tmp_path, PATH_MAX)) {
        releaseTmpFile(&source_tape[0]);
        (*record_free)(record[0]);
        (*record_free)(record[1]);
        return FILE_CREATION_ERROR;
    }
    source_tape[1].fp = openTmpFile(tmp_path);
    source_tape[1].count = 0L;
    if (source_tape[1].fp == NULL) {
        releaseTmpFile(&source_tape[0]);
        (*record_free)(record[0]);
        (*record_free)(record[1]);
        return FILE_CREATION_ERROR;
    }
    if (strncpy_safe(source_tape[1].path, tmp_path, PATH_MAX)) {
        releaseTmpFile(&source_tape[0]);
        releaseTmpFile(&source_tape[1]);
        (*record_free)(record[0]);
        (*record_free)(record[1]);
        return FILE_CREATION_ERROR;
    }
    /* read blocks, sort them in memory, and write the alternately to */
    /* tapes 0 and 1 */
    {
        struct record_in_memory *first = NULL;
        unsigned long block_count = 0;
        unsigned destination = 0;
        struct compare_info comp;
        comp.compare = compare;
        comp.pointer = pointer;
        while (1) {
            int record_size = (*read)(unsorted_file, record[0], pointer);
            if (record_size > 0) {
                struct record_in_memory *p = (struct record_in_memory *) cb_malloc(sizeof(*p));
                if (p == NULL) {
                    releaseTmpFile(&source_tape[0]);
                    releaseTmpFile(&source_tape[1]);
                    (*record_free)(record[0]);
                    (*record_free)(record[1]);
                    free_memory_blocks(first, record_free);
                    return INSUFFICIENT_MEMORY;
                }
                p->record = (*record_duplicate)(record[0]);
                if (p->record == NULL) {
                    releaseTmpFile(&source_tape[0]);
                    releaseTmpFile(&source_tape[1]);
                    cb_free(p);
                    (*record_free)(record[0]);
                    (*record_free)(record[1]);
                    free_memory_blocks(first, record_free);
                    return INSUFFICIENT_MEMORY;
                }
                p->next = first;
                first = p;
                block_count++;
            } else if (record_size < 0) {
                releaseTmpFile(&source_tape[0]);
                releaseTmpFile(&source_tape[1]);
                (*record_free)(record[0]);
                (*record_free)(record[1]);
                free_memory_blocks(first, record_free);
                return FILE_READ_ERROR;
            }
            if (block_count == block_size || (record_size == 0 && block_count != 0)) {
                first = static_cast<record_in_memory*>(sort_linked_list(first, 0, compare_records, &comp, NULL));
                while (first != NULL) {
                    struct record_in_memory *next = first->next;
                    if ((*write)(source_tape[destination].fp, first->record,
                                 pointer) == 0) {
                        releaseTmpFile(&source_tape[0]);
                        releaseTmpFile(&source_tape[1]);
                        (*record_free)(record[0]);
                        (*record_free)(record[1]);
                        free_memory_blocks(first, record_free);
                        return FILE_WRITE_ERROR;
                    }
                    source_tape[destination].count++;
                    (*record_free)(first->record);
                    cb_free(first);
                    first = next;
                }
                destination ^= 1;
                block_count = 0;
            }
            if (record_size == 0) {
                break;
            }
        }
    }
    if (sorted_file == unsorted_file) {
        rewind(unsorted_file);
    }
    rewind(source_tape[0].fp);
    rewind(source_tape[1].fp);
    /* delete the unsorted file here, if required (see instructions) */
    /* handle case where memory sort is all that is required */
    if (source_tape[1].count == 0L) {
        releaseTmpFile(&source_tape[1]);
        source_tape[1] = source_tape[0];
        source_tape[0].fp = sorted_file;
        while (source_tape[1].count-- != 0L) {
            if ((*read)(source_tape[1].fp, record[0], pointer) <= 0) {
                releaseTmpFile(&source_tape[1]);
                (*record_free)(record[0]);
                (*record_free)(record[1]);
                return FILE_READ_ERROR;
            }
            if ((*write)(source_tape[0].fp, record[0], pointer) == 0) {
                releaseTmpFile(&source_tape[1]);
                (*record_free)(record[0]);
                (*record_free)(record[1]);
                return FILE_WRITE_ERROR;
            }
        }
    } else {
        /* merge tapes, two by two, until every record is in source_tape[0] */
        while (source_tape[1].count != 0L) {
            unsigned destination = 0;
            struct tape destination_tape[2];
            int record1_size, record2_size;
            destination_tape[0].fp = source_tape[0].count <= block_size ?
                                     sorted_file : openTmpFile(tmp_path);
            destination_tape[0].count = 0L;

            if (destination_tape[0].fp == NULL) {
                releaseTmpFile(&source_tape[0]);
                releaseTmpFile(&source_tape[1]);
                (*record_free)(record[0]);
                (*record_free)(record[1]);
                return FILE_CREATION_ERROR;
            }

            if (destination_tape[0].fp != sorted_file) {
                if (strncpy_safe(
                            destination_tape[0].path, tmp_path, PATH_MAX)) {
                    releaseTmpFile(&destination_tape[0]);
                    releaseTmpFile(&source_tape[0]);
                    releaseTmpFile(&source_tape[1]);
                    (*record_free)(record[0]);
                    (*record_free)(record[1]);
                    return FILE_CREATION_ERROR;
                }
            }

            destination_tape[1].fp = openTmpFile(tmp_path);
            destination_tape[1].count = 0L;
            if (destination_tape[1].fp == NULL) {
                if (destination_tape[0].fp != sorted_file) {
                    releaseTmpFile(&destination_tape[0]);
                }
                releaseTmpFile(&source_tape[0]);
                releaseTmpFile(&source_tape[1]);
                (*record_free)(record[0]);
                (*record_free)(record[1]);
                return FILE_CREATION_ERROR;
            }
            if (strncpy_safe(destination_tape[1].path, tmp_path, PATH_MAX)) {
                if (destination_tape[0].fp != sorted_file) {
                    releaseTmpFile(&destination_tape[0]);
                }
                releaseTmpFile(&source_tape[0]);
                releaseTmpFile(&source_tape[1]);
                (*record_free)(record[0]);
                (*record_free)(record[1]);
                return FILE_CREATION_ERROR;
            }
            record1_size = (*read)(source_tape[0].fp, record[0], pointer);
            record2_size = (*read)(source_tape[1].fp, record[1], pointer);
            if (record1_size <= 0 || record2_size <= 0) {
                if (destination_tape[0].fp != sorted_file) {
                    releaseTmpFile(&destination_tape[0]);
                }
                releaseTmpFile(&source_tape[0]);
                releaseTmpFile(&source_tape[1]);
                (*record_free)(record[0]);
                (*record_free)(record[1]);
                return FILE_READ_ERROR;
            }
            while (source_tape[0].count != 0L) {
                unsigned long count[2];
                count[0] = source_tape[0].count;
                if (count[0] > block_size) {
                    count[0] = block_size;
                }
                count[1] = source_tape[1].count;
                if (count[1] > block_size) {
                    count[1] = block_size;
                }
                while (count[0] + count[1] != 0) {
                    unsigned select = count[0] == 0 ? 1 : count[1] == 0 ? 0 :
                                      compare(record[0], record[1], pointer) < 0 ? 0 : 1;
                    if ((*write)(destination_tape[destination].fp, record[select],
                                 pointer) == 0) {
                        if (destination_tape[0].fp != sorted_file) {
                            releaseTmpFile(&destination_tape[0]);
                        }
                        releaseTmpFile(&destination_tape[1]);
                        releaseTmpFile(&source_tape[0]);
                        releaseTmpFile(&source_tape[1]);
                        (*record_free)(record[0]);
                        (*record_free)(record[1]);
                        return FILE_WRITE_ERROR;
                    }
                    if (source_tape[select].count > 1L) {
                        if ((*read)(source_tape[select].fp, record[select], pointer) <= 0) {
                            if (destination_tape[0].fp != sorted_file) {
                                releaseTmpFile(&destination_tape[0]);
                            }
                            releaseTmpFile(&destination_tape[1]);
                            releaseTmpFile(&source_tape[0]);
                            releaseTmpFile(&source_tape[1]);
                            (*record_free)(record[0]);
                            (*record_free)(record[1]);
                            return FILE_READ_ERROR;
                        }
                    }
                    source_tape[select].count--;
                    count[select]--;
                    destination_tape[destination].count++;
                }
                destination ^= 1;
            }
            releaseTmpFile(&source_tape[0]);
            releaseTmpFile(&source_tape[1]);
            if (fflush(destination_tape[0].fp) == EOF ||
                    fflush(destination_tape[1].fp) == EOF) {
                if (destination_tape[0].fp != sorted_file) {
                    releaseTmpFile(&destination_tape[0]);
                }
                releaseTmpFile(&destination_tape[1]);
                (*record_free)(record[0]);
                (*record_free)(record[1]);
                return FILE_WRITE_ERROR;
            }
            rewind(destination_tape[0].fp);
            rewind(destination_tape[1].fp);
            memcpy(source_tape, destination_tape, sizeof(source_tape));
            block_size <<= 1;
        }
    }
    releaseTmpFile(&source_tape[1]);
    if (pcount != NULL) {
        *pcount = source_tape[0].count;
    }
    (*record_free)(record[0]);
    (*record_free)(record[1]);
    return OK;
}

