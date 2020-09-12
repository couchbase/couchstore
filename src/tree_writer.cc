/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#include "couchstore_config.h"

#include "arena.h"
#include "bitfield.h"
#include "couch_btree.h"
#include "internal.h"
#include "mergesort.h"
#include "reduces.h"
#include "tree_writer.h"
#include "util.h"

#include <platform/cb_malloc.h>
#include <stdlib.h>


#define ID_SORT_CHUNK_SIZE (500 * 1024) // max # in memory items in sort run
#define ID_SORT_MAX_RECORD_SIZE 4196


static char *alloc_record(void);
static char *duplicate_record(char *rec);
static void free_record(char *rec);
static int read_id_record(FILE *in, void *buf, void *ctx);
static int write_id_record(FILE *out, void *ptr, void *ctx);
static int compare_id_record(const void *r1, const void *r2, void *ctx);


struct TreeWriter {
    FILE* file;
    char *tmp_path; // a buffer used to build unique temporary filenames
    char path[PATH_MAX];
    compare_callback key_compare;
    reduce_fn reduce;
    reduce_fn rereduce;
    void *user_reduce_ctx;
};


couchstore_error_t TreeWriterOpen(char* unsortedFilePath,
                                  compare_callback key_compare,
                                  reduce_fn reduce,
                                  reduce_fn rereduce,
                                  void *user_reduce_ctx,
                                  TreeWriter** out_writer)
{
    couchstore_error_t errcode = COUCHSTORE_SUCCESS;
    TreeWriter* writer = static_cast<TreeWriter*>(cb_calloc(1, sizeof(TreeWriter)));
    error_unless(writer, COUCHSTORE_ERROR_ALLOC_FAIL);
    if (unsortedFilePath) {
        // stash the temp file path into context for uniq tempfile construction
        writer->tmp_path = unsortedFilePath;
        writer->file = openTmpFile(writer->tmp_path);
    }

    if (!writer->file) {
        TreeWriterFree(writer);
        error_pass(COUCHSTORE_ERROR_NO_SUCH_FILE);
    }

    if (strncpy_safe(writer->path, writer->tmp_path, PATH_MAX)) {
        error_pass(COUCHSTORE_ERROR_NO_SUCH_FILE);
    }
    if (unsortedFilePath) {
        fseek(writer->file, 0, SEEK_END);  // in case more items will be added
    }
    writer->key_compare = (key_compare ? key_compare : ebin_cmp);
    writer->reduce = reduce;
    writer->rereduce = rereduce;
    writer->user_reduce_ctx = user_reduce_ctx;
    *out_writer = writer;
cleanup:
    return errcode;
}


void TreeWriterFree(TreeWriter* writer)
{
    if (writer && writer->file) {
        fclose(writer->file);
        remove(writer->path);
    }
    cb_free(writer);
}


couchstore_error_t TreeWriterAddItem(TreeWriter* writer, sized_buf key, sized_buf value)
{
    couchstore_error_t errcode = COUCHSTORE_SUCCESS;

    uint16_t klen = htons((uint16_t) key.size);
    uint32_t vlen = htonl((uint32_t) value.size);
    error_unless(fwrite(&klen, sizeof(klen), 1, writer->file) == 1, COUCHSTORE_ERROR_WRITE);
    error_unless(fwrite(&vlen, sizeof(vlen), 1, writer->file) == 1, COUCHSTORE_ERROR_WRITE);
    error_unless(fwrite(key.buf, key.size, 1, writer->file) == 1, COUCHSTORE_ERROR_WRITE);
    error_unless(fwrite(value.buf, value.size, 1, writer->file) == 1, COUCHSTORE_ERROR_WRITE);

cleanup:
    return errcode;
}


couchstore_error_t TreeWriterSort(TreeWriter* writer)
{
    rewind(writer->file);
    return static_cast<couchstore_error_t>(merge_sort(writer->file,
                                                      writer->file,
                                                      writer->tmp_path,
                                                      read_id_record,
                                                      write_id_record,
                                                      compare_id_record,
                                                      alloc_record,
                                                      duplicate_record,
                                                      free_record,
                                                      writer,  // 'context' parameter to the above callbacks
                                                      ID_SORT_CHUNK_SIZE,
                                                      NULL));
}


couchstore_error_t TreeWriterWrite(TreeWriter* writer,
                                   tree_file* treefile,
                                   node_pointer** out_root)
{
    couchstore_error_t errcode = COUCHSTORE_SUCCESS;
    arena* transient_arena = new_arena(0);
    arena* persistent_arena = new_arena(0);
    compare_info idcmp;
    uint16_t klen;
    uint32_t vlen;
    sized_buf k, v;
    int readerr;
    couchfile_modify_result* target_mr;

    error_unless(transient_arena && persistent_arena, COUCHSTORE_ERROR_ALLOC_FAIL);

    rewind(writer->file);

    // Create the structure to write the tree to the db:
    idcmp.compare = writer->key_compare;

    target_mr = new_btree_modres(persistent_arena,
                                 transient_arena,
                                 treefile, &idcmp,
                                 writer->reduce,
                                 writer->rereduce,
                                 writer->user_reduce_ctx,
                                 treefile->options.kv_nodesize,
                                 treefile->options.kp_nodesize);
    if (target_mr == NULL) {
        error_pass(COUCHSTORE_ERROR_ALLOC_FAIL);
    }

    // Read all the key/value pairs from the file and add them to the tree:
    while (1) {
        if (fread(&klen, sizeof(klen), 1, writer->file) != 1) {
            break;
        }
        if (fread(&vlen, sizeof(vlen), 1, writer->file) != 1) {
            break;
        }
        k.size = ntohs(klen);
        k.buf = static_cast<char*>(arena_alloc(transient_arena, k.size));
        v.size = ntohl(vlen);
        v.buf = static_cast<char*>(arena_alloc(transient_arena, v.size));
        if (fread(k.buf, k.size, 1, writer->file) != 1) {
            error_pass(COUCHSTORE_ERROR_READ);
        }
        if (fread(v.buf, v.size, 1, writer->file) != 1) {
            error_pass(COUCHSTORE_ERROR_READ);
        }
        //printf("K: '%.*s'\n", k.size, k.buf);
        mr_push_item(&k, &v, target_mr);
        if (target_mr->count == 0) {
            /* No items queued, we must have just flushed. We can safely rewind the transient arena. */
            arena_free_all(transient_arena);
        }
    }

    // Check for file error:
    readerr = ferror(writer->file);
    if (readerr != 0 && readerr != EOF) {
        error_pass(COUCHSTORE_ERROR_READ);
    }

    // Finish up the tree:
    if(*out_root != nullptr) {
        cb_free(*out_root);
    }
    *out_root = complete_new_btree(target_mr, &errcode);

cleanup:
    delete_arena(transient_arena);
    delete_arena(persistent_arena);
    return errcode;
}


//////// MERGE-SORT CALLBACKS:


typedef struct extsort_record {
    sized_buf k;
    sized_buf v;
    char buf[1];
} extsort_record;

static int read_id_record(FILE *in, void *buf, void *ctx)
{
    (void) ctx;
    uint16_t klen;
    uint32_t vlen;
    extsort_record *rec = (extsort_record *) buf;
    if (fread(&klen, 2, 1, in) != 1) {
        if (feof(in)) {
            return 0;
        } else {
            return -1;
        }
    }
    if (fread(&vlen, 4, 1, in) != 1) {
        return -1;
    }
    klen = ntohs(klen);
    vlen = ntohl(vlen);
    rec->k.size = klen;
    rec->k.buf = rec->buf;
    rec->v.size = vlen;
    rec->v.buf = rec->buf + klen;
    if (fread(rec->k.buf, klen, 1, in) != 1) {
        return -1;
    }
    if (fread(rec->v.buf, vlen, 1, in) != 1) {
        return -1;
    }
    return sizeof(extsort_record) + klen + vlen;
}

static int write_id_record(FILE *out, void *ptr, void *ctx)
{
    (void) ctx;
    extsort_record *rec = (extsort_record *) ptr;
    uint16_t klen = htons((uint16_t) rec->k.size);
    uint32_t vlen = htonl((uint32_t) rec->v.size);
    if (fwrite(&klen, 2, 1, out) != 1) {
        return 0;
    }
    if (fwrite(&vlen, 4, 1, out) != 1) {
        return 0;
    }
    if (fwrite(rec->buf, rec->k.size + rec->v.size, 1, out) != 1) {
        return 0;
    }
    return 1;
}

static int compare_id_record(const void *r1, const void *r2, void *ctx)
{
    TreeWriter* writer = static_cast<TreeWriter*>(ctx);
    extsort_record *e1 = (extsort_record *) r1, *e2 = (extsort_record *) r2;
    e1->k.buf = e1->buf;
    e2->k.buf = e2->buf;
    return writer->key_compare(&e1->k, &e2->k);
}

static char *alloc_record(void)
{
    return static_cast<char*>(cb_malloc(ID_SORT_MAX_RECORD_SIZE));
}

static char *duplicate_record(char *rec)
{
    extsort_record *record = (extsort_record *) rec;
    size_t record_size = sizeof(extsort_record) + record->k.size + record->v.size;
    extsort_record *new_record = (extsort_record *) cb_malloc(record_size);

    if (new_record != NULL) {
        memcpy(new_record, record, record_size);
    }

    return (char *) new_record;
}

static void free_record(char *rec)
{
    cb_free(rec);
}
