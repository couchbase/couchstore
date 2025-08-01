/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

/*
 * qsort taken from FreeBSD, slightly modified to match glibc's
 * argument ordering
 */

/*-
 * Copyright (c) 1992, 1993
 *    The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/* $FreeBSD: src/lib/libc/stdlib/qsort.c,v 1.13.2.1.8.1 2010/12/21 17:10:29 kensmith Exp $ */

#include <stdlib.h>
#include "quicksort.h"

typedef struct {
    sort_cmp_t *func;
    void       *ctx;
} qsort_wrapper;

#if(defined __APPLE__ || defined _WIN32)
static int qsort_cmp_wrap(void *ctx, const void *a, const void *b)
{
    qsort_wrapper *wrap = (qsort_wrapper *) ctx;
    return (*wrap->func)(a, b, wrap->ctx);
}

#elif(!defined HAVE_QSORT_R)

static inline char    *med3(char *, char *, char *, sort_cmp_t *, void *);
static inline void     swapfunc(char *, char *, size_t, int);

#define min(a, b)    (a) < (b) ? a : b

/*
 * Qsort routine from Bentley & McIlroy's "Engineering a Sort Function".
 */
#define swapcode(TYPE, parmi, parmj, n) {         \
    size_t i = (n) / sizeof (TYPE);             \
    TYPE *pi = (TYPE *) (parmi);         \
    TYPE *pj = (TYPE *) (parmj);         \
    do {                         \
        TYPE    t = *pi;        \
        *pi++ = *pj;                \
        *pj++ = t;                \
        } while (--i > 0);                \
}

#define SWAPINIT(a, es) swaptype = ((char *)a - (char *)0) % sizeof(long) || \
    es % sizeof(long) ? 2 : es == sizeof(long)? 0 : 1;

static inline void
swapfunc(char *a, char *b, size_t n, int swaptype)
{
    if(swaptype <= 1)
        swapcode(long, a, b, n)
    else
        swapcode(char, a, b, n)
}

#define swap(a, b)                    \
    if (swaptype == 0) {                \
        long t = *(long *)(a);            \
        *(long *)(a) = *(long *)(b);        \
        *(long *)(b) = t;            \
    } else                        \
        swapfunc(a, b, es, swaptype)

#define vecswap(a, b, n)     if ((n) > 0) swapfunc(a, b, n, swaptype)

#define    CMP(t, x, y) (cmp((x), (y), (t)))

static inline char *med3(char *a, char *b, char *c, sort_cmp_t *cmp, void *thunk)
{
    return CMP(thunk, a, b) < 0 ?
           (CMP(thunk, b, c) < 0 ? b : (CMP(thunk, a, c) < 0 ? c : a ))
              :(CMP(thunk, b, c) > 0 ? b : (CMP(thunk, a, c) < 0 ? a : c ));
}

static void qsort_fallback(void *a, size_t n, size_t es, sort_cmp_t *cmp, void *thunk)
{
    char *pa, *pb, *pc, *pd, *pl, *pm, *pn;
    size_t d, r;
    int cmp_result;
    int swaptype;

loop:
    SWAPINIT(a, es);
    if (n < 7) {
        for (pm = (char *)a + es; pm < (char *)a + n * es; pm += es)
            for (pl = pm;
                 pl > (char *)a && CMP(thunk, pl - es, pl) > 0;
                 pl -= es)
                swap(pl, pl - es);
        return;
    }
    pm = (char *)a + (n / 2) * es;
    if (n > 7) {
        pl = a;
        pn = (char *)a + (n - 1) * es;
        if (n > 40) {
            d = (n / 8) * es;
            pl = med3(pl, pl + d, pl + 2 * d, cmp, thunk);
            pm = med3(pm - d, pm, pm + d, cmp, thunk);
            pn = med3(pn - 2 * d, pn - d, pn, cmp, thunk);
        }
        pm = med3(pl, pm, pn, cmp, thunk);
    }
    swap(a, pm);
    pa = pb = (char *)a + es;

    pc = pd = (char *)a + (n - 1) * es;
    for (;;) {
        while (pb <= pc && (cmp_result = CMP(thunk, pb, a)) <= 0) {
            if (cmp_result == 0) {
                swap(pa, pb);
                pa += es;
            }
            pb += es;
        }
        while (pb <= pc && (cmp_result = CMP(thunk, pc, a)) >= 0) {
            if (cmp_result == 0) {
                swap(pc, pd);
                pd -= es;
            }
            pc -= es;
        }
        if (pb > pc)
            break;
        swap(pb, pc);
        pb += es;
        pc -= es;
    }

    pn = (char *)a + n * es;
    r = min(pa - (char *)a, pb - pa);
    vecswap(a, pb - r, r);
    r = min(pd - pc, pn - pd - es);
    vecswap(pb, pn - r, r);
    if ((r = pb - pa) > es)
        qsort_fallback(a, r / es, es, cmp, thunk);
    if ((r = pd - pc) > es) {
        /* Iterate rather than recurse to save stack space */
        a = pn - r;
        n = r / es;
        goto loop;
    }
/*        qsort(pn - r, r / es, es, cmp);*/
}

#endif

void quicksort(void *a, size_t n, size_t es, sort_cmp_t *cmp, void *ctx)
{
#if(defined __APPLE__ || _WIN32)
    qsort_wrapper wrapper;
    wrapper.func = cmp;
    wrapper.ctx = ctx;
#endif

#if(defined __APPLE__)
    qsort_r(a, n, es, &wrapper, qsort_cmp_wrap);
#elif (defined _WIN32)
    qsort_s(a, n, es, qsort_cmp_wrap, &wrapper);
#elif (defined __linux__ && HAVE_QSORT_R)
    qsort_r(a, n, es, cmp, ctx);
#else
    qsort_fallback(a, n, es, cmp, ctx);
#endif
}
