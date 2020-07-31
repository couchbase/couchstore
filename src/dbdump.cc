/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#include "couchstore_config.h"

#include "bitfield.h"
#include "couch_btree.h"
#include "flatbuffers/idl.h"
#include "internal.h"
#include "node_types.h"
#include "tracking_file_ops.h"
#include "util.h"
#include "views/index_header.h"
#include "views/util.h"
#include "views/view_group.h"
#include <collections/kvstore_generated.h>
#include <libcouchstore/couch_db.h>
#include <mcbp/protocol/unsigned_leb128.h>
#include <memcached/protocol_binary.h>
#include <nlohmann/json.hpp>
#include <platform/cb_malloc.h>
#include <platform/cbassert.h>
#include <snappy-c.h>
#include <cinttypes>

#include <platform/string_hex.h>
#include <xattr/blob.h>
#include <xattr/utils.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <iostream>
#include <optional>

#define MAX_HEADER_SIZE (64 * 1024)

typedef enum {
    DumpBySequence,
    DumpByID,
    DumpLocals,
    DumpFileMap,
} DumpMode;

static DumpMode mode = DumpBySequence;
static bool dumpTree = false;
static bool dumpJson = false;
static bool dumpHex = false;
static bool oneKey = false;
static bool dumpBody = true;
static bool decodeVbucket = true;
static bool decodeIndex = false;
static bool decodeNamespace = true;
static bool iterateHeaders = false;
static bool dumpHeaders = false;
static std::optional<cs_off_t> headerOffset;
static sized_buf dumpKey;

typedef struct {
    raw_64 cas;
    raw_32 expiry;
    raw_32 flags;
} CouchbaseRevMeta;

// Additional Couchbase V1 metadata:
struct CouchbaseRevMetaV1 {
    uint8_t flex_code;
    uint8_t datatype;
};

// Additional Couchbase V2 metadata:
struct CouchbaseRevMetaV2 {
    uint8_t confResMode;
};

// Additional Couchbase V3 metadata - SyncReplication state
struct CouchbaseRevMetaV3 {
    uint8_t operation;
    uint8_t level;

    const char* getOperationName() const {
        switch (operation) {
        case 0:
            return "pending";
        case 1:
            return "commit";
        case 2:
            return "abort";
        default:
            return "<INVALID>";
        }
    }
    const char* getLevelName() const {
        switch (level) {
        case 0:
            return "none";
        case 1:
            return "majority";
        case 2:
            return "majorityAndPersistOnMaster";
        case 3:
            return "persistToMajority";
        default:
            return "<INVALID>";
        }
    }
};

extern const std::string vbucket_serialised_manifest_entry_raw_schema;
extern const std::string collections_kvstore_schema;

static int view_btree_cmp(const sized_buf *key1, const sized_buf *key2)
{
    return view_key_cmp(key1, key2, NULL);
}

static void printsb(const sized_buf *sb)
{
    if (sb->buf == NULL) {
        printf("null\n");
        return;
    }
    printf("%.*s\n", (int) sb->size, sb->buf);
}

static void printsbhexraw(const sized_buf* sb) {
    size_t ii;
    for (ii = 0; ii < sb->size; ++ii) {
        printf("%.02x", (uint8_t)sb->buf[ii]);
    }
}

static void printsbhex(const sized_buf *sb, int with_ascii)
{
    size_t i;

    if (sb->buf == NULL) {
        printf("null\n");
        return;
    }
    printf("{");
    for (i = 0; i < sb->size; ++i) {
        printf("%.02x", (uint8_t)sb->buf[i]);
        if (i % 4 == 3) {
            printf(" ");
        }
    }
    printf("}");
    if (with_ascii) {
        printf("  (\"");
        for (i = 0; i < sb->size; ++i) {
            uint8_t ch = sb->buf[i];
            if (ch < 32 || ch >= 127) {
                ch = '?';
            }
            printf("%c", ch);
        }
        printf("\")");
    }
    printf("\n");
}

static void printjquote(const sized_buf *sb)
{
    const char* i = sb->buf;
    const char* end = sb->buf + sb->size;
    if (sb->buf == NULL) {
        return;
    }
    for (; i < end; i++) {
        if (*i > 31 && *i != '\"' && *i != '\\') {
            fputc(*i, stdout);
        } else {
            fputc('\\', stdout);
            switch(*i)
            {
                case '\\': fputc('\\', stdout);break;
                case '\"': fputc('\"', stdout);break;
                case '\b': fputc('b', stdout);break;
                case '\f': fputc('f', stdout);break;
                case '\n': fputc('n', stdout);break;
                case '\r': fputc('r', stdout);break;
                case '\t': fputc('t', stdout);break;
                default:
                           printf("u00%.02x", *i);
            }
        }
    }
}

static void print_datatype_as_json(const std::string& datatype) {
    printf("\"datatype_as_text\":[");

    std::string::size_type start = 0;
    std::string::size_type end;
    bool need_comma = false;
    while ((end = datatype.find(',', start)) != std::string::npos) {
        auto token = datatype.substr(start, end - start);
        if (need_comma) {
            printf(",");
        }
        printf("\"%s\"", token.c_str());
        start = end + 1;
        need_comma = true;
    }

    if (need_comma) {
        printf(",");
    }
    auto token = datatype.substr(start);
    printf("\"%s\"", token.c_str());
    printf("]");
}

static std::string getNamespaceString(uint32_t ns) {
    switch (ns) {
    case 0:
        return "collection:0x0:default";
    case 1:
        return "system-event-key:";
    case 2:
        return "prepare:";
    default:
        std::stringstream ss;
        ss << "collection:0x" << std::hex << ns;
        return ss.str();
    }
}

static void printDocId(const char* prefix, const sized_buf* sb) {
    if (decodeNamespace && sb->size >= sizeof(uint32_t)) {
        // Decode the collection-ID of the key
        auto [cid, rawKey] = cb::mcbp::unsigned_leb128<uint32_t>::decode(
                {reinterpret_cast<uint8_t*>(sb->buf), sb->size});

        auto collectionInfo = getNamespaceString(cid);

        if (cid == 2) {
            // Synchronous Replication 'Prepare' namespace prefix.
            // Decode again.
            auto [newCid, newRawKey] =
                    cb::mcbp::unsigned_leb128<uint32_t>::decode(rawKey);
            cid = newCid;
            rawKey = newRawKey;
            collectionInfo += getNamespaceString(cid);
        }

        // Some keys in the system event namespace have a format we can decode:
        // \1_collection:<affected collection-id leb128>
        // \1_scope:<affected scope-id leb128>
        std::string collectionsPrefix("_collection");
        std::string scopePrefix("_scope");
        std::string key{reinterpret_cast<const char*>(rawKey.data()),
                        rawKey.size()};
        if (cid == 1) {
            auto [systemType, systemKey] =
                    cb::mcbp::unsigned_leb128<uint32_t>::decode(
                            {reinterpret_cast<const uint8_t*>(rawKey.data()),
                             rawKey.size()});

            // System event namespace
            if (systemType == 0 &&
                key.find(collectionsPrefix) != std::string::npos) {
                auto [affectedCid, keyRemainder] =
                        cb::mcbp::unsigned_leb128<uint32_t>::decode(systemKey);
                key = std::string{
                        reinterpret_cast<const char*>(keyRemainder.data()),
                        keyRemainder.size()};
                std::stringstream ss;
                ss << collectionInfo << "collection:0x" << std::hex
                   << affectedCid;
                collectionInfo = ss.str();
            } else if (systemType == 1 &&
                       key.find(scopePrefix) != std::string::npos) {
                auto [affectedSid, keyRemainder] =
                        cb::mcbp::unsigned_leb128<uint32_t>::decode(systemKey);
                key = std::string{
                        reinterpret_cast<const char*>(keyRemainder.data()),
                        keyRemainder.size()};
                std::stringstream ss;
                ss << collectionInfo << "scope:0x" << std::hex << affectedSid;
                collectionInfo = ss.str();
            }
        }
        printf("%s(%s) %s\n", prefix, collectionInfo.c_str(), key.c_str());
    } else {
        printf("%s%.*s\n", prefix, (int)sb->size, sb->buf);
    }
}

static int foldprint(Db *db, DocInfo *docinfo, void *ctx)
{
    int *count = (int *) ctx;
    Doc *doc = NULL;
    uint64_t cas;
    uint32_t expiry, flags;
    protocol_binary_datatype_t datatype = PROTOCOL_BINARY_RAW_BYTES;
    bool ttl_delete = false;
    couchstore_error_t docerr;
    (*count)++;

    if (dumpJson) {
        printf("{\"seq\":%" PRIu64 ",\"id\":\"", docinfo->db_seq);
        printjquote(&docinfo->id);
        printf("\",");
    } else {
        if (mode == DumpBySequence) {
            printf("Doc seq: %" PRIu64 "\n", docinfo->db_seq);
            printDocId("     id: ", &docinfo->id);
        } else {
            printDocId("  Doc ID: ", &docinfo->id);
            if (docinfo->db_seq > 0) {
                printf("     seq: %" PRIu64 "\n", docinfo->db_seq);
            }
        }
    }
    if (docinfo->bp == 0 && docinfo->deleted == 0 && !dumpJson) {
        printf("         ** This b-tree node is corrupt; raw node value follows:*\n");
        printf("    raw: ");
        printsbhex(&docinfo->rev_meta, 1);
        return 0;
    }
    if (dumpJson) {
        printf("\"rev\":%" PRIu64 ",\"content_meta\":%d,", docinfo->rev_seq,
                                                         docinfo->content_meta);
        printf("\"physical_size\":%" PRIu64 ",", (uint64_t)docinfo->physical_size);
    } else {
        printf("     rev: %" PRIu64 "\n", docinfo->rev_seq);
        printf("     content_meta: %d\n", docinfo->content_meta);
        printf("     size (on disk): %" PRIu64 "\n", (uint64_t)docinfo->physical_size);
    }

    if (docinfo->rev_meta.size >= sizeof(CouchbaseRevMeta)) {
        const CouchbaseRevMeta* meta = (const CouchbaseRevMeta*)docinfo->rev_meta.buf;
        cas = decode_raw64(meta->cas);
        expiry = decode_raw32(meta->expiry);
        flags = decode_raw32(meta->flags);
        if (dumpJson) {
            printf("\"cas\":\"%" PRIu64 "\",\"expiry\":%" PRIu32
                   ",\"flags\":%" PRIu32,
                   cas,
                   expiry,
                   flags);
        } else {
            printf("     cas: %" PRIu64 ", expiry: %" PRIu32
                   ", flags: %" PRIu32,
                   cas,
                   expiry,
                   flags);
        }
    }

    if (docinfo->rev_meta.size >=
        sizeof(CouchbaseRevMeta) + sizeof(CouchbaseRevMetaV1)) {
        // 18 bytes of rev_meta indicates CouchbaseRevMetaV1 - adds
        // flex_meta_code (1B) and datatype (1B)
        if (docinfo->rev_meta.size <
            sizeof(CouchbaseRevMeta) + sizeof(CouchbaseRevMetaV1)) {
            printf("     Error parsing the document: Possible corruption\n");
            return 1;
        }
        const auto* metaV1 =
                (const CouchbaseRevMetaV1*)(docinfo->rev_meta.buf +
                                            sizeof(CouchbaseRevMeta));

        if (metaV1->flex_code < 0x01) {
            printf("     Error: Flex code mismatch (bad code: %d)\n",
                   metaV1->flex_code);
            return 1;
        }
        ttl_delete = ((metaV1->flex_code << 7) & 0x1) == 1;

        datatype = metaV1->datatype;
        const auto datatype_string = mcbp::datatype::to_string(datatype);

        if (dumpJson) {
            printf(",\"datatype\":%d,", datatype);
            print_datatype_as_json(datatype_string);
        } else {
            printf(", datatype: 0x%02x (%s)",
                   datatype,
                   datatype_string.c_str());
        }
    }

    if (docinfo->rev_meta.size == sizeof(CouchbaseRevMeta) +
                                          sizeof(CouchbaseRevMetaV1) +
                                          sizeof(CouchbaseRevMetaV2)) {
        // 19 bytes of rev_meta indicates CouchbaseRevMetaV2 - adds
        // resolution flag (1B).
        // Note: This is no longer written since Watson; but could still
        // exist in old files.
        const auto* metaV2 =
                (const CouchbaseRevMetaV2*)(docinfo->rev_meta.buf +
                                            sizeof(CouchbaseRevMeta) +
                                            sizeof(CouchbaseRevMetaV1));

        const auto conf_res_mode = metaV2->confResMode;

        if (dumpJson) {
            printf(",\"conflict_resolution_mode\":%d", conf_res_mode);
        } else {
            printf(", conflict_resolution_mode: %d", conf_res_mode);
        }
    }

    if (docinfo->rev_meta.size == sizeof(CouchbaseRevMeta) +
                                          sizeof(CouchbaseRevMetaV1) +
                                          sizeof(CouchbaseRevMetaV3)) {
        // 21 bytes of rev_meta indicates CouchbaseRevMetaV3 - adds
        // Synchronous Replication state.
        const auto* metaV3 =
                (const CouchbaseRevMetaV3*)(docinfo->rev_meta.buf +
                                            sizeof(CouchbaseRevMeta) +
                                            sizeof(CouchbaseRevMetaV1));

        if (dumpJson) {
            printf(",\"sync_write\":\"%s\"", metaV3->getOperationName());
            if (metaV3->operation == 0 /*Pending*/) {
                printf(",\"level\":\"%s\"", metaV3->getLevelName());
            }
        } else {
            printf(", sync_write: %s", metaV3->getOperationName());
            if (metaV3->operation == 0 /*Pending*/) {
                printf(" [level: %s]", metaV3->getLevelName());
            }
        }
    }

    if (!dumpJson) {
        printf("\n");
    }

    if (docinfo->deleted) {
        const char* deleteSource = ttl_delete ? "TTL" : "explicit";
        if (dumpJson) {
            printf(",\"deleted\":\"%s\"", deleteSource);
        } else {
            printf("     doc deleted (%s)\n", deleteSource);
        }
    }

    if (dumpBody) {
        docerr = couchstore_open_doc_with_docinfo(db, docinfo, &doc, DECOMPRESS_DOC_BODIES);
        if (docerr != COUCHSTORE_SUCCESS) {
            if (dumpJson) {
                printf(",\"body\":null}\n");
            } else {
                printf("     could not read document body: %s\n", couchstore_strerror(docerr));
            }
        } else if (doc) {
            std::string xattrs;
            sized_buf body = doc->data;

            // If datatype is snappy (and not marked compressed) we must inflate
            cb::compression::Buffer inflated;
            if (mcbp::datatype::is_snappy(datatype) &&
                !(docinfo->content_meta & COUCH_DOC_IS_COMPRESSED)) {
                // Inflate the entire document so we can work with it
                if (!cb::compression::inflate(
                            cb::compression::Algorithm::Snappy,
                            {doc->data.buf, doc->data.size},
                            inflated)) {
                    if (dumpJson) {
                        printf(",\"body\":null}\n");
                    } else {
                        printf("     could not inflate document body\n");
                    }
                    return 0;
                }

                body = _sized_buf{inflated.data(), inflated.size()};
            }

            if (mcbp::datatype::is_xattr(datatype)) {
                cb::xattr::Blob blob({body.buf, body.size}, false);
                xattrs = blob.to_json().dump();
                body = _sized_buf{body.buf + blob.size(),
                                  body.size - blob.size()};
            }

            if (dumpJson) {
                printf(",\"size\":%" PRIu64 ",", (uint64_t)doc->data.size);
                if (docinfo->content_meta & COUCH_DOC_IS_COMPRESSED) {
                    printf("\"snappy\":true,\"display\":\"inflated\",");
                }

                if (xattrs.size() > 0) {
                    sized_buf xa{const_cast<char*>(xattrs.data()), xattrs.size()};
                    printf("\"xattr\":\"");
                    printjquote(&xa);
                    printf("\",");
                }

                printf("\"body\":\"");
                printjquote(&body);
                printf("\"}\n");
            } else {
                printf("     size: %" PRIu64 "\n", (uint64_t)doc->data.size);
                if (xattrs.size() > 0) {
                    printf("     xattrs: ");
                    sized_buf xa{const_cast<char*>(xattrs.data()), xattrs.size()};
                    if (dumpHex) {
                        printsbhexraw(&xa);
                        printf("\n");
                    } else {
                        printsb(&xa);
                    }
                }
                printf("     data: ");

                if (docinfo->content_meta & COUCH_DOC_IS_COMPRESSED) {
                    printf("(snappy) ");
                }

                if (dumpHex) {
                    printsbhexraw(&body);
                    printf("\n");
                } else {
                    printsb(&body);
                }
            }
        }
    } else {
        if (dumpJson) {
            printf("\"body\":null}\n");
        } else {
            printf("\n");
        }
    }

    couchstore_free_document(doc);
    return 0;
}


static int visit_node(Db *db,
                      int depth,
                      const DocInfo* docinfo,
                      uint64_t subtreeSize,
                      const sized_buf* reduceValue,
                      void *ctx)
{
    int i;
    (void) db;

    for (i = 0; i < depth; ++i)
        printf("  ");
    if (reduceValue) {
        /* This is a tree node: */
        printf("+ (%" PRIu64 ") ", subtreeSize);
        printsbhex(reduceValue, 0);
        return 0;
    }

    // This is a leaf node.
    const auto key = docinfo->id;
    if ((docinfo->bp > 0) || (docinfo->bp == 0 && docinfo->deleted) ||
            (mode == DumpLocals)) {
        int *count;
        /* This is a document / local document: */
        printf("%c (%" PRIu64 ",%" PRIu64 ") ",
               (docinfo->deleted ? 'x' : '*'),
               uint64_t(docinfo->physical_size), uint64_t(docinfo->rev_meta.size));
        if (mode == DumpBySequence) {
            printf("#%" PRIu64 " ", docinfo->db_seq);
        }
        if (mode == DumpLocals) {
            // Local doc has no collections prefix
            printf(" id:%.*s\n", int(key.size), key.buf);
        } else {
            printDocId(" id:", &key);
        }

        count = (int *) ctx;
        (*count)++;
    } else {
        /* Document, but not in a known format: */
        printf("**corrupt?** ");
        printsbhex(&docinfo->rev_meta, 1);
    }
    return 0;
}

/// Visitor function for filemap mode - just trigger a read of the document
/// so the FileMap ops can record where they reside on disk.
static int filemap_visit(Db* db,
                         int depth,
                         const DocInfo* docinfo,
                         uint64_t subtreeSize,
                         const sized_buf* reduceValue,
                         void* ctx) {
    if (docinfo == nullptr) {
        // Tree node.
        return 0;
    }
    Doc* doc = nullptr;
    ScopedFileTag tag(db->file.ops, db->file.handle, FileTag::Document);
    couchstore_open_doc_with_docinfo(db, docinfo, &doc, DECOMPRESS_DOC_BODIES);
    couchstore_free_document(doc);
    return 0;
}

static int noop_visit(Db* db,
                      int depth,
                      const DocInfo* docinfo,
                      uint64_t subtreeSize,
                      const sized_buf* reduceValue,
                      void* ctx) {
    return 0;
}


template<class RootType>
static couchstore_error_t read_collection_flatbuffer_collections(
        const std::string& name,
        const std::string& rootType,
        const sized_buf* v,
        std::string& out) {
    flatbuffers::Verifier verifier(reinterpret_cast<uint8_t*>(v->buf), v->size);
    if (!verifier.VerifyBuffer<RootType>(nullptr)) {
        std::cerr << "WARNING: \"" << name
                  << "\" root:" << rootType << ", contains invalid "
                     "flatbuffers data of size:"
                  << v->size << std::endl;
        ;
        return COUCHSTORE_ERROR_CORRUPT;
    }

    // Use flatbuffers::Parser to generate JSON output of the binary blob
    flatbuffers::IDLOptions idlOptions;

    // Configure IDL
    // strict_json:true adds quotes to keys
    // indent_step < 0: no indent and no newlines, external tools can format
    idlOptions.strict_json = true;
    idlOptions.indent_step = -1;
    idlOptions.output_default_scalars_in_json = true;
    flatbuffers::Parser parser(idlOptions);
    parser.Parse(collections_kvstore_schema.c_str());
    parser.SetRootType(rootType.c_str());
    std::string jsongen;
    GenerateText(parser, v->buf, &out);
    return COUCHSTORE_SUCCESS;
}

static couchstore_error_t read_collection_leb128_metadata(const sized_buf* v,
                                                          std::string& out) {
    uint64_t count = 0;
    uint64_t seqno = 0;
    uint64_t diskSize = 0;

    auto decoded1 = cb::mcbp::unsigned_leb128<uint64_t>::decode(
            {reinterpret_cast<uint8_t*>(v->buf), v->size});
    count = decoded1.first;

    if (decoded1.second.size()) {
        decoded1 = cb::mcbp::unsigned_leb128<uint64_t>::decode(decoded1.second);
        seqno = decoded1.first;
    }

    if (decoded1.second.size()) {
        decoded1 = cb::mcbp::unsigned_leb128<uint64_t>::decode(decoded1.second);
        diskSize = decoded1.first;
    }

    std::stringstream ss;
    ss << R"({"item_count":)" << count << R"(, "high_seqno":)" << seqno
       << R"(, "disk_size":)" << diskSize << "}";
    out = ss.str();

    return COUCHSTORE_SUCCESS;
}

static couchstore_error_t maybe_decode_local_doc(const sized_buf* id,
                                                 const sized_buf* v,
                                                 std::string& decodedData) {
    // Check for known non-JSON meta-data documents
    if (strncmp(id->buf, "_local/collections/open", id->size) == 0) {
        return read_collection_flatbuffer_collections<Collections::KVStore::OpenCollections>(
                id->buf, "OpenCollections", v, decodedData);
    } else if (strncmp(id->buf, "_local/collections/dropped", id->size) == 0) {
        return read_collection_flatbuffer_collections<Collections::KVStore::DroppedCollections>(
                id->buf, "DroppedCollections", v, decodedData);
    } else if (strncmp(id->buf, "_local/scope/open", id->size) == 0) {
        return read_collection_flatbuffer_collections<Collections::KVStore::Scopes>(
                id->buf, "Scopes", v, decodedData);
    } else if (strncmp(id->buf, "_local/collections/manifest", id->size) == 0) {
        return read_collection_flatbuffer_collections<Collections::KVStore::CommittedManifest>(
                id->buf, "CommittedManifest", v, decodedData);
    } else if (id->buf[0] == '|') {
        return read_collection_leb128_metadata(v, decodedData);
    }

    // Nothing todo
    return COUCHSTORE_SUCCESS;
}

static couchstore_error_t local_doc_print(couchfile_lookup_request *rq,
                                          const sized_buf *k,
                                          const sized_buf *v)
{
    int* count = (int*) rq->callback_ctx;
    if (!v) {
        return COUCHSTORE_ERROR_DOC_NOT_FOUND;
    }
    (*count)++;
    sized_buf* id = (sized_buf*)k;
    sized_buf value = {v->buf, v->size};

    printf("Key: ");
    printsb(id);

    std::string decodedData;
    auto rv = maybe_decode_local_doc(k, v, decodedData);

    if (rv != COUCHSTORE_SUCCESS) {
        return rv;
    }

    if (!decodedData.empty()) {
        value.buf = const_cast<char*>(decodedData.data());
        value.size = decodedData.size();
    }

    printf("Value: ");
    printsb(&value);
    printf("Value size: %" PRIu64, uint64_t(v->size));

    printf("\n");

    return COUCHSTORE_SUCCESS;
}

static couchstore_error_t local_doc_print_json(couchfile_lookup_request* rq,
                                               const sized_buf* k,
                                               const sized_buf* v) {
    int* count = (int*)rq->callback_ctx;
    if (!v) {
        return COUCHSTORE_ERROR_DOC_NOT_FOUND;
    }
    (*count)++;
    sized_buf value = {v->buf, v->size};

    std::string decodedData;
    auto rv = maybe_decode_local_doc(k, v, decodedData);

    if (rv != COUCHSTORE_SUCCESS) {
        return rv;
    }

    if (!decodedData.empty()) {
        value.buf = const_cast<char*>(decodedData.data());
        value.size = decodedData.size();
    }

    nlohmann::json parsed;
     parsed["id"] = std::string(k->buf, k->size);
    try {
        parsed["value"] = nlohmann::json::parse(value.buf, value.buf + value.size);
    } catch (const nlohmann::json::exception& e) {
        std::cerr << "WARNING: Failed nlohmann::json::parse of id:";
        std::cerr.write(k->buf, k->size);
        std::cerr << " with value:";
        std::cerr.write(value.buf, value.size);
        std::cerr << std::endl;
        return COUCHSTORE_ERROR_CORRUPT;
    }


    std::cout << parsed.dump() << std::endl;

    return COUCHSTORE_SUCCESS;
}

static couchstore_error_t local_doc_ignore(couchfile_lookup_request* rq,
                                           const sized_buf* k,
                                           const sized_buf* v) {
    return COUCHSTORE_SUCCESS;
}

typedef couchstore_error_t (*fetch_callback_fn)(
        struct couchfile_lookup_request* rq,
        const sized_buf* k,
        const sized_buf* v);

static couchstore_error_t couchstore_print_local_docs(
        Db* db, fetch_callback_fn fetch_cb, int* count) {
    sized_buf key;
    sized_buf *keylist = &key;
    couchfile_lookup_request rq;
    couchstore_error_t errcode;

    if (db->header.local_docs_root == NULL) {
        if (oneKey) {
            return COUCHSTORE_ERROR_DOC_NOT_FOUND;
        } else {
            return COUCHSTORE_SUCCESS;
        }
    }

    key.buf = (char *)"\0";
    key.size = 0;

    rq.cmp.compare = ebin_cmp;
    rq.file = &db->file;
    rq.num_keys = 1;
    rq.keys = &keylist;
    rq.callback_ctx = count;
    rq.fetch_callback = fetch_cb;
    rq.node_callback = NULL;
    rq.fold = 1;

    if (oneKey) {
        rq.fold = 0;
        key = dumpKey;
    }

    errcode = btree_lookup(&rq, db->header.local_docs_root->pointer);
    return errcode;
}

static int process_vbucket_file(const char *file, int *total)
{
    Db *db;
    couchstore_error_t errcode;
    int count = 0;

    TrackingFileOps* trackingFileOps = nullptr;
    couchstore_open_flags flags = COUCHSTORE_OPEN_FLAG_RDONLY;
    if (mode == DumpFileMap) {
        flags |= COUCHSTORE_OPEN_FLAG_UNBUFFERED;
        trackingFileOps = new TrackingFileOps();
        errcode = couchstore_open_db_ex(file, flags, trackingFileOps, &db);
    } else {
        errcode = couchstore_open_db(file, flags, &db);
    }
    if (errcode != COUCHSTORE_SUCCESS) {
        fprintf(stderr, "Failed to open \"%s\": %s\n",
                file, couchstore_strerror(errcode));
        return -1;
    }

    // Use a unique pointer to keep track of the database instance to make
    // sure it is released properly in all exit paths
    cb::couchstore::UniqueDbPtr uniqueDbPtr(db);

    if (headerOffset) {
        errcode = cb::couchstore::seek(*db, *headerOffset);
        if (errcode != COUCHSTORE_SUCCESS) {
            fprintf(stderr,
                    "Failed to open \"%s\" at offset 0x%" PRIx64 ": %s\n",
                    file,
                    *headerOffset,
                    couchstore_strerror(errcode));
            return -1;
        }
    }

    printf("Dumping \"%s\":\n", file);

next_header:
    if (dumpHeaders) {
        try {
            const auto header = cb::couchstore::getHeader(*db).to_json().dump();
            printf("File header: %s\n", header.c_str());
        } catch (const std::exception& ex) {
            fprintf(stderr, "Failed to fetch database header information: %s\n",
                   ex.what());
            return -1;
        }
    }

    switch (mode) {
    case DumpBySequence:
        if (dumpTree) {
            errcode = couchstore_walk_seq_tree(
                    db, 0, COUCHSTORE_TOLERATE_CORRUPTION,
                    visit_node, &count);
        } else {
            errcode = couchstore_changes_since(
                    db, 0, COUCHSTORE_TOLERATE_CORRUPTION,
                    foldprint, &count);
        }
        break;
    case DumpByID:
        if (dumpTree) {
            errcode = couchstore_walk_id_tree(
                    db, NULL, COUCHSTORE_TOLERATE_CORRUPTION,
                    visit_node, &count);
        } else if (oneKey) {
            DocInfo* info;
            errcode = couchstore_docinfo_by_id(db, dumpKey.buf, dumpKey.size, &info);
            if (errcode == COUCHSTORE_SUCCESS) {
                foldprint(db, info, &count);
                couchstore_free_docinfo(info);
            }
        } else {
            errcode = couchstore_all_docs(
                    db, NULL, COUCHSTORE_TOLERATE_CORRUPTION,
                    foldprint, &count);
        }
        break;
    case DumpLocals:
        if (dumpTree) {
            errcode = couchstore_walk_local_tree(db,
                                              NULL,
                                              visit_node,
                                              &count);
        } else if (dumpJson) {
            errcode = couchstore_print_local_docs(
                    db, local_doc_print_json, &count);
        } else {
            errcode = couchstore_print_local_docs(db, local_doc_print, &count);
        }
        break;

    case DumpFileMap:
        // Visit all three indexes in the file. Note we don't actually need to
        // do anything in the callback; the map is built up using a custom
        // FileOps class and annotations in couchstore itself to tag the
        // different structures.
        cb_assert(trackingFileOps != nullptr);
        trackingFileOps->setTree(db->file.handle,
                                 TrackingFileOps::Tree::Sequence);
        couchstore_walk_seq_tree(
                db, 0, COUCHSTORE_TOLERATE_CORRUPTION, filemap_visit, &count);

        // Note for the ID tree we specify a different (noop) callback; as we
        // don't want or need to read the document bodies again.
        trackingFileOps->setTree(db->file.handle, TrackingFileOps::Tree::Id);
        couchstore_walk_id_tree(
                db, NULL, COUCHSTORE_TOLERATE_CORRUPTION, noop_visit, &count);

        trackingFileOps->setTree(db->file.handle, TrackingFileOps::Tree::Local);
        int dummy = 0;
        couchstore_print_local_docs(db, local_doc_ignore, &dummy);

        // Mark that we are now on old headers
        trackingFileOps->setHistoricData(db->file.handle, true);
        break;
    }
    if (iterateHeaders) {
        errcode =
                cb::couchstore::seek(*db, cb::couchstore::Direction::Backward);
        if (errcode == COUCHSTORE_SUCCESS) {
            printf("\n");
            goto next_header;
        }
    }

    if (errcode < 0) {
        fprintf(stderr, "Failed to dump database \"%s\": %s\n",
                file, couchstore_strerror(errcode));
        return -1;
    }

    *total += count;
    return 0;
}

static couchstore_error_t lookup_callback(couchfile_lookup_request *rq,
                                          const sized_buf *k,
                                          const sized_buf *v)
{
    const uint16_t json_key_len = decode_raw16(*((raw_16 *) k->buf));
    sized_buf json_key;
    sized_buf json_value;

    json_key.buf = k->buf + sizeof(uint16_t);
    json_key.size = json_key_len;

    json_value.size = v->size - sizeof(raw_kv_length);
    json_value.buf = v->buf + sizeof(raw_kv_length);

    if (dumpJson) {
        printf("{\"id\":\"");
        printjquote(&json_key);
        printf("\",\"data\":\"");
        printjquote(&json_value);
        printf("\"}\n");
    } else {
        printf("Doc ID: ");
        printsb(&json_key);
        printf("data: ");
        printsb(&json_value);
    }

    printf("\n");
    rq->num_keys++;

    return COUCHSTORE_SUCCESS;
}

static couchstore_error_t find_view_header_at_pos(view_group_info_t *info,
                                                cs_off_t pos)
{
    couchstore_error_t errcode = COUCHSTORE_SUCCESS;
    uint8_t buf;
    ssize_t readsize = info->file.ops->pread(&info->file.lastError,
                                            info->file.handle,
                                            &buf, 1, pos);
    error_unless(readsize == 1, static_cast<couchstore_error_t>(readsize));
    if (buf == 0) {
        return COUCHSTORE_ERROR_NO_HEADER;
    } else if (buf != 1) {
        return COUCHSTORE_ERROR_CORRUPT;
    }

    info->header_pos = pos;

    return COUCHSTORE_SUCCESS;

cleanup:
    return errcode;
}

static couchstore_error_t find_view_header(view_group_info_t *info,
                                        int64_t start_pos)
{
    couchstore_error_t last_header_errcode = COUCHSTORE_ERROR_NO_HEADER;
    int64_t pos = start_pos;
    pos -= pos % COUCH_BLOCK_SIZE;
    for (; pos >= 0; pos -= COUCH_BLOCK_SIZE) {
        couchstore_error_t errcode = find_view_header_at_pos(info, pos);
        switch(errcode) {
            case COUCHSTORE_SUCCESS:
                // Found it!
                return COUCHSTORE_SUCCESS;
            case COUCHSTORE_ERROR_NO_HEADER:
                // No header here, so keep going
                break;
            case COUCHSTORE_ERROR_ALLOC_FAIL:
                // Fatal error
                return errcode;
            default:
                // Invalid header; continue, but remember the last error
                last_header_errcode = errcode;
                break;
        }
    }
    return last_header_errcode;
}

static int process_view_file(const char *file, int *total)
{
    view_group_info_t *info;
    couchstore_error_t errcode;
    index_header_t *header = NULL;
    char *header_buf = NULL;
    int header_len;

    info = (view_group_info_t *)cb_calloc(1, sizeof(view_group_info_t));
    if (info == NULL) {
        fprintf(stderr, "Unable to allocate memory\n");
        return -1;
    }
    info->type = VIEW_INDEX_TYPE_MAPREDUCE;

    errcode = open_view_group_file(file, COUCHSTORE_OPEN_FLAG_RDONLY, &info->file);
    if (errcode != COUCHSTORE_SUCCESS) {
        fprintf(stderr, "Failed to open \"%s\": %s\n",
                file, couchstore_strerror(errcode));
        return -1;
    } else {
        printf("Dumping \"%s\":\n", file);
    }

    info->file.pos = info->file.ops->goto_eof(&info->file.lastError,
                                              info->file.handle);

    errcode = find_view_header(info, info->file.pos - 2);
    if (errcode != COUCHSTORE_SUCCESS) {
        fprintf(stderr, "Unable to find header position \"%s\": %s\n",
                file, couchstore_strerror(errcode));
        return -1;
    }

    header_len = pread_header(&info->file, (cs_off_t)info->header_pos, &header_buf,
                            MAX_HEADER_SIZE);

    if (header_len < 0) {
        return -1;
    }

    errcode = decode_index_header(header_buf, (size_t) header_len, &header);
    if (errcode != COUCHSTORE_SUCCESS) {
        fprintf(stderr, "Unable to decode header \"%s\": %s\n",
                file, couchstore_strerror(errcode));
        return -1;
    }
    cb_free(header_buf);
    printf("Num views: %d\n", header->num_views);

    for (int i = 0; i < header->num_views; ++i) {
        printf("\nKV pairs from index: %d\n", i);
        sized_buf nullkey = {NULL, 0};
        sized_buf *lowkeys = &nullkey;
        couchfile_lookup_request rq;

        rq.cmp.compare = view_btree_cmp;
        rq.file = &info->file;
        rq.num_keys = 1;
        rq.keys = &lowkeys;
        rq.callback_ctx = NULL;
        rq.fetch_callback = lookup_callback;
        rq.node_callback = NULL;
        rq.fold = 1;

        errcode = btree_lookup(&rq, header->view_states[i]->pointer);
        if (errcode != COUCHSTORE_SUCCESS) {
            return -1;
        }
        *total = rq.num_keys - 1;
    }
    return 0;
}

static void usage(void) {
    printf("USAGE: couch_dbdump [options] file.couch [main_xxxx.view.X ...]\n");
    printf("\nOptions:\n");
    printf("    --vbucket <vb_file> decode vbucket file\n");
    printf("    --view <view_file> decode view index file\n");
    printf("    --key <key>  dump only the specified document\n");
    printf("    --hex-body   convert document body data to hex (for binary data)\n");
    printf("    --no-body    don't retrieve document bodies (metadata only, faster)\n");
    printf("    --byid       sort output by document ID\n");
    printf("    --byseq      sort output by document sequence number (default)\n");
    printf("    --json       dump data as JSON objects (one per line)\n");
    printf("    --no-namespace  don't decode namespaces\n");
    printf("    --iterate-headers  Iterate through all headers\n");
    printf("    --dump-headers  Dump the file header structure\n");
    printf("    --header-offset <offset> Use the header at file offset\n");
    printf("\nAlternate modes:\n");
    printf("    --tree       show file b-tree structure instead of data\n");
    printf("    --local      dump local documents. Can be used in conjunction with --tree\n");
    printf("    --map        dump block map \n");
    exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{
    int error = 0;
    int count = 0;
    int ii = 1;

    if (argc < 2) {
        usage();
    }

    while (ii < argc && strncmp(argv[ii], "-", 1) == 0) {
        std::string_view command{argv[ii]};
        if (command == "--view") {
            decodeIndex = true;
        } else if (command == "--vbucket") {
            decodeVbucket = true;
        } else if (command == "--byid") {
            mode = DumpByID;
        } else if (command == "--byseq") {
            mode = DumpBySequence;
        } else if (command == "--tree") {
            dumpTree = true;
        } else if (command == "--json") {
            dumpJson = true;
        } else if (command == "--hex-body") {
            dumpHex = true;
        } else if (command == "--no-body") {
            dumpBody = false;
        } else if (command == "--no-namespace") {
            decodeNamespace = false;
        } else if (command == "--key") {
            if (argc < (ii + 1)) {
                usage();
            }
            oneKey = true;
            dumpKey.buf = argv[ii+1];
            dumpKey.size = strlen(argv[ii+1]);
            if (mode == DumpBySequence) {
                mode = DumpByID;
            }
            ii++;
        } else if (command == "--local") {
            mode = DumpLocals;
        } else if (command == "--map") {
            mode = DumpFileMap;
        } else if (command == "--iterate-headers") {
            iterateHeaders = true;
        } else if (command == "--dump-headers") {
            dumpHeaders = true;
        } else if (command == "--header-offset") {
            // read the header offset
            if (argc < (ii + 1)) {
                usage();
            }
            const std::string number{argv[ii + 1]};
            if (number.find("0x") == 0) {
                headerOffset = cb::from_hex(number);
            } else {
                headerOffset = std::stoull(number);
            }
            ii++;
        } else {
            usage();
        }
        ++ii;
    }

    if (ii >= argc) {
        usage();
    }

    for (; ii < argc; ++ii) {
        if (decodeIndex) {
            error += process_view_file(argv[ii], &count);
        } else if (decodeVbucket) {
            error += process_vbucket_file(argv[ii], &count);
        } else {
            usage();
        }
    }

    printf("\nTotal docs: %d\n", count);
    if (error) {
        exit(EXIT_FAILURE);
    } else {
        exit(EXIT_SUCCESS);
    }
}
