/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#include "couchstore_config.h"

#include "bitfield.h"

#include <libcouchstore/couch_db.h>
#include <platform/compress.h>

#include <getopt.h>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <string>

static int quiet = 0;
struct compare_context {
    Db* self;
    DbInfo self_info;
    Db* other;
    DbInfo other_info;
    int diff;
};

static void usage() {
    printf("USAGE: dbdiff [-q] file1 file2\n");
    printf("   -q\tquiet\n");
    exit(EXIT_FAILURE);
}

static int is_printable_key(sized_buf key) {
    size_t ii;
    for (ii = 0; ii < key.size; ++ii) {
        if (!isprint(key.buf[ii])) {
            return 0;
        }
    }

    return 1;
}

static void print_key(sized_buf key, FILE* out = stdout) {
    if (is_printable_key(key)) {
        fwrite(key.buf, 1, key.size, out);
    } else {
        size_t ii;
        for (ii = 0; ii < key.size; ++ii) {
            fprintf(out, "0x%02x", int(key.buf[ii]));
        }
    }
}

static void print_missing(sized_buf key, const char* fname) {
    if (!quiet) {
        printf("Document \"");
        print_key(key);
        printf("\" is missing from \"%s\"\n", fname);
    }
}

// Encoding of Couchbase per-revision metadata
struct CouchbaseRevMeta {
    raw_64 cas;
    raw_32 expiry;
    raw_32 flags;
};

static void compare_docinfo(compare_context* ctx,
                            const DocInfo* a,
                            const DocInfo* b,
                            bool& compressed) {
    if (a->db_seq != b->db_seq) {
        ctx->diff = 1;
        if (!quiet) {
            printf("Document db_seq differs for \"");
            print_key(a->id);
            printf("\": %" PRIu64 " - %" PRIu64 "\n", a->db_seq, b->db_seq);
        }
    }

    if (a->rev_seq != b->rev_seq) {
        ctx->diff = 1;
        if (!quiet) {
            printf("Document rev_seq differs for \"");
            print_key(a->id);
            printf("\": %" PRIu64 " - %" PRIu64 "\n", a->rev_seq, b->rev_seq);
        }
    }

    // Assume datatype is raw; unless we decode otherwise later.
    uint8_t a_datatype = 0;
    uint8_t b_datatype = 0;

    if (a->rev_meta.size != b->rev_meta.size) {
        ctx->diff = 1;
        if (!quiet) {
            printf("Document rev_meta size differs for \"");
            print_key(a->id);
            printf("\": %" PRIu64 " - %" PRIu64 "\n",
                   (uint64_t)a->rev_meta.size,
                   (uint64_t)b->rev_meta.size);
            printf("\"\n");
        }
    } else if (a->rev_meta.size >= sizeof(CouchbaseRevMeta)) {
        // Decode as CouchbaseRevMeta, compare each field.
        const auto* a_meta = reinterpret_cast<const CouchbaseRevMeta *>(a->rev_meta.buf);
        const uint64_t a_cas = decode_raw64(a_meta->cas);
        const uint32_t a_expiry = decode_raw32(a_meta->expiry);
        const uint32_t a_flags = decode_raw32(a_meta->flags);

        const auto* b_meta = reinterpret_cast<const CouchbaseRevMeta *>(b->rev_meta.buf);
        const uint64_t b_cas = decode_raw64(b_meta->cas);
        const uint32_t b_expiry = decode_raw32(b_meta->expiry);
        const uint32_t b_flags = decode_raw32(b_meta->flags);

        if (a_cas != b_cas) {
            ctx->diff = 1;
            if (!quiet) {
                printf("Document CAS differs for \"");
                print_key(a->id);
                printf("\": %" PRIu64 " - %" PRIu64 "\n", a_cas, b_cas);
            }
        }

        if (a_expiry != b_expiry) {
            ctx->diff = 1;
            if (!quiet) {
                printf("Document expiry differs for \"");
                print_key(a->id);
                printf("\": %" PRIu32 " - %" PRIu32 "\n", a_expiry, b_expiry);
            }
        }

        // Flags are not replicated for deleted documements; so ignore any
        // differences if deleted.
        if (a_flags != b_flags && !a->deleted) {
            ctx->diff = 1;
            if (!quiet) {
                printf("Document flags differ for \"");
                print_key(a->id);
                printf("\": 0x%" PRIx32 " - 0x%" PRIx32 "\n", a_flags, b_flags);
            }
        }

        if ((a->rev_meta.size > sizeof(CouchbaseRevMeta)) &&
            (a->rev_meta.size <= sizeof(CouchbaseRevMeta) + 2)) {
            // 18 bytes of rev_meta indicates CouchbaseRevMeta along with
            // flex_meta_code (1B) and datatype (1B)
            const uint8_t a_flex_code = *((uint8_t *) (a->rev_meta.buf +
                                                       sizeof(CouchbaseRevMeta)));
            a_datatype = *((uint8_t *) (a->rev_meta.buf +
                                        sizeof(CouchbaseRevMeta) +
                                        sizeof(uint8_t)));

            const uint8_t b_flex_code = *((uint8_t *) (b->rev_meta.buf +
                                                       sizeof(CouchbaseRevMeta)));
            b_datatype = *((uint8_t *) (b->rev_meta.buf +
                                        sizeof(CouchbaseRevMeta) +
                                        sizeof(uint8_t)));

            if (a_flex_code != b_flex_code) {
                ctx->diff = 1;
                if (!quiet) {
                    printf("Document flex_code differ for \"");
                    print_key(a->id);
                    printf("\": %" PRIx8 " - %" PRIx8 "\n", a_flex_code, b_flex_code);
                }
            }

            if (a_datatype != b_datatype) {
                ctx->diff = 1;
                if (!quiet) {
                    printf("Document datatype differ for \"");
                    print_key(a->id);
                    printf("\": %" PRIx8 " - %" PRIx8 "\n", a_datatype, b_datatype);
                }
            }
        }

    } else if (memcmp(a->rev_meta.buf, b->rev_meta.buf, a->rev_meta.size) != 0) {
        ctx->diff = 1;
        if (!quiet) {
            printf("Document rev_meta differs for \"");
            print_key(a->id);
            printf("\"\n");
        }
    }

    if (a->deleted != b->deleted) {
        ctx->diff = 1;
        if (!quiet) {
            printf("Document deleted status differs for \"");
            print_key(a->id);
            printf("\": %u - %u\n", a->deleted, b->deleted);
        }
    }

    if (a->content_meta != b->content_meta) {
        ctx->diff = 1;
        if (!quiet) {
            printf("Document content_meta differs for \"");
            print_key(a->id);
            printf("\": %02x - %02x\n", a->content_meta, b->content_meta);
        }
    }

    // If the documents are compressed; then comparing the raw size is
    // misleading as any difference could be due to how it was compressed.
    // Instead compare uncompressed length later, in compare_documents (when we
    // have the document value to decompress).
    compressed = (a_datatype & 0x2) == 0;
    if (a->physical_size != b->physical_size && !compressed) {
        ctx->diff = 1;
        if (!quiet) {
            printf("Document size differs for \"");
            print_key(a->id);
            printf("\": %" PRIu64 " - %" PRIu64 "\n",
                   (uint64_t)a->physical_size,
                   (uint64_t)b->physical_size);
        }
    }
}

static void compare_documents(compare_context* ctx,
                              DocInfo* this_doc_info,
                              DocInfo* other_doc_info,
                              bool compressed) {
    couchstore_error_t e1, e2;
    Doc *d1, *d2;

    if (this_doc_info->deleted) {
        return;
    }

    e1 = couchstore_open_document(
            ctx->self, this_doc_info->id.buf, this_doc_info->id.size, &d1, 0);
    e2 = couchstore_open_document(ctx->other,
                                  other_doc_info->id.buf,
                                  other_doc_info->id.size,
                                  &d2,
                                  0);

    if (e1 == COUCHSTORE_SUCCESS && e2 == COUCHSTORE_SUCCESS) {
        cb::compression::Buffer d1_uncompressed;
        cb::compression::Buffer d2_uncompressed;
        sized_buf d1_val = d1->data;
        sized_buf d2_val = d2->data;

        // If the documents are compressed; compare uncompressed data / size.
        if (compressed) {
            if (!cb::compression::inflate(cb::compression::Algorithm::Snappy,
                                          {d1->data.buf, d1->data.size},
                                          d1_uncompressed)) {
                fprintf(stderr,
                        "Failed to uncompress Snappy-compressed document \"");
                print_key(d1->id, stderr);
                fprintf(stderr, "\"\n");
                exit(EXIT_FAILURE);
            }
            d1_val = {d1_uncompressed.data(), d1_uncompressed.size()};

            if (!cb::compression::inflate(cb::compression::Algorithm::Snappy,
                                          {d2->data.buf, d2->data.size},
                                          d2_uncompressed)) {
                fprintf(stderr,
                        "Failed to uncompress Snappy-compressed document \"");
                print_key(d1->id, stderr);
                fprintf(stderr, "\"\n");
                exit(EXIT_FAILURE);
            }
            d2_val = {d2_uncompressed.data(), d2_uncompressed.size()};
        }

        if (d1_val.size != d2_val.size) {
            ctx->diff = 1;
            if (!quiet) {
                printf("Document \"");
                print_key(this_doc_info->id);
                printf("\" differs in size!\n");
            }
        } else if (memcmp(d1_val.buf, d2_val.buf, d1_val.size) != 0) {
            ctx->diff = 1;
            if (!quiet) {
                printf("Document \"");
                print_key(this_doc_info->id);
                printf("\" content differs!\n");
            }
        }

        couchstore_free_document(d1);
        couchstore_free_document(d2);
    } else {
        fprintf(stderr,
                "Failed to open document from this\n this: %s\n other: %s\n",
                couchstore_strerror(e1),
                couchstore_strerror(e2));
        exit(EXIT_FAILURE);
    }
}

static int deep_compare(Db* db, DocInfo* docinfo, void* c) {
    auto* ctx = reinterpret_cast<compare_context*>(c);
    DocInfo* other_doc_info;
    couchstore_error_t err;

    err = couchstore_docinfo_by_id(
            ctx->other, docinfo->id.buf, docinfo->id.size, &other_doc_info);

    if (err == COUCHSTORE_SUCCESS) {
        /* verify that the docinfos are the same.. */
        bool compressed;
        compare_docinfo(ctx, docinfo, other_doc_info, compressed);
        compare_documents(ctx, docinfo, other_doc_info, compressed);
        couchstore_free_docinfo(other_doc_info);
    } else {
        ctx->diff = 1;
        print_missing(docinfo->id, ctx->other_info.filename);
    }

    return 0;
}

static int check_existing(Db* db, DocInfo* docinfo, void* c) {
    auto* ctx = reinterpret_cast<compare_context*>(c);
    couchstore_error_t err;
    DocInfo* other_info;

    // This function will be called for all docs, including those which are
    // deleted (tombstones). As such, we need to first lookup the docinfo in
    // the 'other' file, only reporting as missing if their delete flags differ.
    err = couchstore_docinfo_by_id(
            ctx->other, docinfo->id.buf, docinfo->id.size, &other_info);

    if (err == COUCHSTORE_SUCCESS) {
        if (other_info->deleted != docinfo->deleted) {
            ctx->diff = 1;
            print_missing(docinfo->id, ctx->other_info.filename);
        }
        couchstore_free_docinfo(other_info);
    } else if (err == COUCHSTORE_ERROR_DOC_NOT_FOUND) {
        ctx->diff = 1;
        print_missing(docinfo->id, ctx->other_info.filename);
    } else {
        fprintf(stderr, "Error trying to read \"");
        print_key(docinfo->id, stderr);
        fprintf(stderr,
                "\" from \"%s\": %s\n",
                ctx->other_info.filename,
                couchstore_strerror(err));
        exit(EXIT_FAILURE);
    }

    return 0;
}

static int diff(Db** dbs) {
    couchstore_error_t err;
    compare_context ctx;
    DbInfo info;

    ctx.diff = 0;
    ctx.self = dbs[0];
    ctx.other = dbs[1];

    if (couchstore_db_info(ctx.self, &ctx.self_info) != COUCHSTORE_SUCCESS ||
        couchstore_db_info(ctx.other, &ctx.other_info) != COUCHSTORE_SUCCESS) {
        fprintf(stderr, "Failed to get database info..\n");
        exit(EXIT_FAILURE);
    }

    err = couchstore_all_docs(ctx.self, nullptr, 0, deep_compare, &ctx);
    if (err != COUCHSTORE_SUCCESS) {
        fprintf(stderr, "An error occured: %s\n", couchstore_strerror(err));
        return -1;
    }

    ctx.self = dbs[1];
    ctx.other = dbs[0];
    info = ctx.self_info;
    ctx.self_info = ctx.other_info;
    ctx.other_info = info;

    err = couchstore_all_docs(ctx.self, nullptr, 0, check_existing, &ctx);
    if (err != COUCHSTORE_SUCCESS) {
        fprintf(stderr, "An error occured: %s\n", couchstore_strerror(err));
        return -1;
    }

    return ctx.diff;
}

int main(int argc, char** argv) {
    int cmd;
    int ii;
    Db* dbs[2];
    int difference;

    while ((cmd = getopt(argc, argv, "q")) != -1) {
        switch (cmd) {
        case 'q':
            quiet = 1;
            break;

        default:
            usage();
            /* NOT REACHED */
        }
    }

    if ((optind + 2) != argc) {
        fprintf(stderr, "Exactly two filenames should be specified\n");
        usage();
        /* NOT REACHED */
    }

    for (ii = 0; ii < 2; ++ii) {
        couchstore_error_t err;
        err = couchstore_open_db(
                argv[optind + ii], COUCHSTORE_OPEN_FLAG_RDONLY, &dbs[ii]);
        if (err != COUCHSTORE_SUCCESS) {
            fprintf(stderr,
                    "Failed to open \"%s\": %s\n",
                    argv[optind + ii],
                    couchstore_strerror(err));
            if (ii == 1) {
                couchstore_close_file(dbs[0]);
                couchstore_free_db(dbs[0]);
            }
            exit(EXIT_FAILURE);
        }
    }

    difference = diff(dbs);
    for (ii = 0; ii < 2; ++ii) {
        couchstore_close_file(dbs[ii]);
        couchstore_free_db(dbs[ii]);
    }

    if (difference == 0) {
        if (!quiet) {
            fprintf(stdout, "The content of the databases is the same\n");
        }
        return EXIT_SUCCESS;
    }

    return EXIT_FAILURE;
}
