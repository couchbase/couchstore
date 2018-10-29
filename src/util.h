#ifndef COUCHSTORE_UTIL_H
#define COUCHSTORE_UTIL_H

#include <string.h>
#include <signal.h>
#include <libcouchstore/couch_db.h>

#include "internal.h"
#include "fatbuf.h"
#include "arena.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Plain lexicographic comparison of the contents of two sized_bufs. */
int ebin_cmp(const sized_buf *e1, const sized_buf *e2);

/** Compares sequence numbers (48-bit big-endian unsigned ints) stored in sized_bufs. */
int seq_cmp(const sized_buf *k1, const sized_buf *k2);

/* Copy buffer to arena */
sized_buf* arena_copy_buf(arena* a, const sized_buf *src);

/* Copy rev_meta from docinfo and buffer to arena */
sized_buf* arena_special_copy_buf_and_revmeta(arena *a, const sized_buf *val,
                                              const DocInfo *docinfo);

/** Offsets the pointer PTR by BYTES bytes. Result is of the same type as PTR. */
#define offsetby(PTR, BYTES)    ((__typeof(PTR))((uint8_t*)(PTR) + (BYTES)))

/* Aligns the offset to the start of the next block */
cs_off_t align_to_next_block(cs_off_t offset);

   /* Sets errcode to the result of C, and jumps to the cleanup: label if it's nonzero. */
#ifdef DEBUG
    void report_error(couchstore_error_t, const char* file, int line);
    #define error_pass(C)                                  \
        do {                                               \
            if ((errcode = (C)) < 0) {                     \
                report_error(errcode, __FILE__, __LINE__); \
                goto cleanup;                              \
            }                                              \
        } while (0)

    // Set errcode on error, without termination.
    #define error_tolerate(C)                              \
        do {                                               \
            if ((C) < 0) {                                 \
                errcode = (C);                             \
                report_error(errcode, __FILE__, __LINE__); \
            }                                              \
        } while (0)
#else
    #define error_pass(C)              \
        do {                           \
            if ((errcode = (C)) < 0) { \
                goto cleanup;          \
            }                          \
        } while (0)

    #define error_tolerate(C)  \
        do {                   \
            if ((C) < 0) {     \
                errcode = (C); \
            }                  \
        } while (0)
#endif

/* If the condition C evaluates to false/zero, sets errcode to E and jumps to the cleanup: label. */
#define error_unless(C, E) \
    do { \
        if(!(C)) { error_pass(E); } \
    } while (0)

/* If the parameter C is nonzero, sets errcode to E and jumps to the cleanup: label. */
#define error_nonzero(C, E) \
    do { \
        if((C) != 0) { error_pass(E); } \
    } while (0)

    couchstore_error_t log_last_internal_error(const char *format, ...) CB_FORMAT_PRINTF(1, 2);

#ifdef __cplusplus
}
#endif

#endif /* COUCHSTORE_UTIL_H */
