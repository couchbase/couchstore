/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#include "couchstore_config.h"
#include "node_types.h"
#include "util.h"

#include <platform/cb_malloc.h>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>

#ifdef DEBUG
#include <stdio.h>
#endif

static std::function<void(std::string_view)> onInternalError;

int ebin_cmp(const sized_buf *e1, const sized_buf *e2)
{
    size_t size;
    if (e2->size < e1->size) {
        size = e2->size;
    } else {
        size = e1->size;
    }

    int cmp = memcmp(e1->buf, e2->buf, size);
    if (cmp == 0) {
        if (size < e2->size) {
            return -1;
        } else if (size < e1->size) {
            return 1;
        }
    }
    return cmp;
}

int seq_cmp(const sized_buf *k1, const sized_buf *k2)
{
    uint64_t e1val = decode_sequence_key(k1);
    uint64_t e2val = decode_sequence_key(k2);
    if (e1val == e2val) {
        return 0;
    }
    return (e1val < e2val ? -1 : 1);
}

void cb::couchstore::FatbufDeletor::operator()(fatbuf* fb) {
    fatbuf_free(fb);
}

fatbuf *fatbuf_alloc(size_t bytes)
{
    fatbuf *fb = (fatbuf *) cb_malloc(sizeof(fatbuf) + bytes);
#ifdef DEBUG
    memset(fb->buf, 0x44, bytes);
#endif
    if (!fb) {
        return nullptr;
    }

    fb->size = bytes;
    fb->pos = 0;
    return fb;
}

void *fatbuf_get(fatbuf *fb, size_t bytes)
{
    if (fb->pos + bytes > fb->size) {
        return nullptr;
    }
#ifdef DEBUG
    if (fb->buf[fb->pos] != 0x44 && bytes > 0) {
        fprintf(stderr, "Fatbuf space has been written to before it was taken!\n");
    }
#endif
    void *rptr = fb->buf + fb->pos;
    fb->pos += bytes;
    return rptr;
}

void fatbuf_free(fatbuf *fb)
{
    cb_free(fb);
}

#ifdef DEBUG
void report_error(couchstore_error_t errcode, const char* file, int line) {
    fprintf(stderr, "Couchstore error `%s' at %s:%d\r\n", \
            couchstore_strerror(errcode), file, line);
}
#endif

sized_buf* arena_copy_buf(arena* a, const sized_buf *src)
{
    sized_buf *nbuf = static_cast<sized_buf*>(arena_alloc(a, sizeof(sized_buf)));
    if (nbuf == nullptr) {
        return nullptr;
    }
    nbuf->buf = static_cast<char*>(arena_alloc(a, src->size));
    if (nbuf->buf == nullptr) {
        return nullptr;
    }
    nbuf->size = src->size;
    memcpy(nbuf->buf, src->buf, src->size);
    return nbuf;
}

sized_buf* arena_special_copy_buf_and_revmeta(arena *a, const sized_buf *val,
                                              const DocInfo *docinfo)
{
    sized_buf *nbuf = static_cast<sized_buf*>(arena_alloc(a, sizeof(sized_buf)));
    if (nbuf == nullptr) {
        return nullptr;
    }

    const raw_seq_index_value *raw = (const raw_seq_index_value*)val->buf;
    uint32_t idsize, datasize;
    decode_kv_length(&raw->sizes, &idsize, &datasize);

    nbuf->size = sizeof(*raw) + idsize + docinfo->rev_meta.size;
    nbuf->buf = static_cast<char*>(arena_alloc(a, nbuf->size));
    if (nbuf->buf == nullptr) {
        return nullptr;
    }
    memcpy(nbuf->buf, val->buf, sizeof(*raw) + idsize);
    memcpy(nbuf->buf + sizeof(*raw) + idsize, docinfo->rev_meta.buf,
           docinfo->rev_meta.size);
    return nbuf;
}

cs_off_t align_to_next_block(cs_off_t offset)
{
    if (offset % COUCH_BLOCK_SIZE != 0) {
        return offset + COUCH_BLOCK_SIZE - (offset % COUCH_BLOCK_SIZE);
    }
    return offset;
}

void cb::couchstore::setOnInternalError(
        std::function<void(std::string_view)> handler) {
    onInternalError = std::move(handler);
}

void log_last_internal_error(const char* format, ...) {
    va_list args;
    va_start(args, format);
    vsnprintf(internal_error_string, MAX_ERR_STR_LEN, format, args);
    va_end(args);
    if (onInternalError) {
        onInternalError(internal_error_string);
    }
}

int strncpy_safe(char* d, const char* s, size_t n) {
    int b = snprintf(d, n, "%s", s);
    if (b < 0 || (size_t)b >= n) {
        return -1;
    } else {
        return 0;
    }
}
