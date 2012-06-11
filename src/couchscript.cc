/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#include "couchstore_config.h"
#include <errno.h>
#include <iostream>

#include <string.h>
#include <sysexits.h>
#include <stdlib.h>
#include <unistd.h>
#include <sstream>
#include <string>
#include <platform/cb_malloc.h>
#include <platform/cbassert.h>
#include <libcouchstore/couch_db.h>
#include "internal.h"

// The number of bytes that is maximally needed to set the `LUA_PATH`
// environment variable. The `18` is the number of bytes of the `LUA_PATH=`
// prefix, the `/?.lua;;` postfix, plus the null-terminator.
#define LUA_PATH_MAX_SIZE (PATH_MAX + 18)

// For building against lua 5.2 and up. Also requires that lua was
// built with this define. Homebrew at least will build lua with this
// set.
#define LUA_COMPAT_ALL
// Copied from lua.hpp to allow us to use older versions of lua
// without that wrapper file.. (BTW this method is broken because
// it includes system headers within 'extern "C"' and that may not
// work very well...
extern "C" {
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
}

#define CHECK_NULL(db) \
    if(db == nullptr) { \
        lua_pushstring(ls, "The db instance is closed"); \
        lua_error(ls); \
        return 1; \
    }

typedef union {
    struct {
        uint64_t cas;
        uint32_t exp;
        uint32_t flags;
    } fields;
    char bytes[1];
} revbuf_t;

// Wrapper function while we're fixing up the namespace
static const char *couchstore_strerror(int code) {
    return couchstore_strerror((couchstore_error_t)code);
}

extern "C" {

    static void push_db(lua_State *ls, Db *db)
    {
        Db **d = static_cast<Db **>(lua_newuserdata(ls, sizeof(Db *)));
        cb_assert(d);
        *d = db;

        luaL_getmetatable(ls, "couch");
        lua_setmetatable(ls, -2);
    }

    static void push_docinfo(lua_State *ls, DocInfo *docinfo)
    {
        DocInfo **di = static_cast<DocInfo **>(lua_newuserdata(ls, sizeof(DocInfo *)));
        cb_assert(di);
        *di = docinfo;
        cb_assert(*di);

        luaL_getmetatable(ls, "docinfo");
        lua_setmetatable(ls, -2);
    }

    static DocInfo *getDocInfo(lua_State *ls)
    {
        DocInfo **d = static_cast<DocInfo **>(luaL_checkudata(ls, 1, "docinfo"));
        cb_assert(d);
        cb_assert(*d);
        return *d;
    }

    static int couch_open(lua_State *ls)
    {
        if (lua_gettop(ls) < 1) {
            lua_pushstring(ls, "couch.open takes at least one argument: "
                           "\"pathname\" [shouldCreate]");
            lua_error(ls);
            return 1;
        }

        const char *pathname = luaL_checkstring(ls, 1);
        uint64_t flags(0);

        if (lua_gettop(ls) > 1) {
            if (!lua_isboolean(ls, 2)) {
                lua_pushstring(ls, "Second arg must be a boolean, "
                               "true if allowed to create databases.");
                lua_error(ls);
                return 1;
            }
            flags = lua_toboolean(ls, 2) ? COUCHSTORE_OPEN_FLAG_CREATE : 0;
        }

        Db *db(NULL);

        couchstore_error_t rc = couchstore_open_db(pathname, flags, &db);
        if (rc != COUCHSTORE_SUCCESS) {
            char buf[256];
            snprintf(buf, sizeof(buf), "error opening DB: %s", couchstore_strerror(rc));
            lua_pushstring(ls, buf);
            lua_error(ls);
            return 1;
        }

        push_db(ls, db);

        return 1;
    }

    static Db *getDb(lua_State *ls)
    {
        Db **d = static_cast<Db **>(luaL_checkudata(ls, 1, "couch"));
        cb_assert(d);
        return *d;
    }

    static void nullDb(lua_State *ls)
    {
        Db **d = static_cast<Db **>(luaL_checkudata(ls, 1, "couch"));
        *d = nullptr;
    }

    static int couch_close(lua_State *ls)
    {
        Db *db = getDb(ls);
        CHECK_NULL(db)

        couchstore_error_t err = couchstore_close_file(db);
        couchstore_free_db(db);
        if (err != COUCHSTORE_SUCCESS) {
            lua_pushstring(ls, "error closing database");
            lua_error(ls);
            return 1;
        }
        nullDb(ls);
        return 0;
    }

    static int couch_commit(lua_State *ls)
    {
        Db *db = getDb(ls);
        CHECK_NULL(db)

        if (couchstore_commit(db) != COUCHSTORE_SUCCESS) {
            lua_pushstring(ls, "error committing");
            lua_error(ls);
            return 1;
        }
        return 0;
    }

    static int couch_get_from_docinfo(lua_State *ls)
    {
        if (lua_gettop(ls) < 2) {
            lua_pushstring(ls, "couch:get_from_docinfo takes one argument: \"docinfo\"");
            lua_error(ls);
            return 1;
        }

        Db *db = getDb(ls);
        CHECK_NULL(db)

        Doc *doc(NULL);
        lua_remove(ls, 1);
        DocInfo *docinfo = getDocInfo(ls);
        cb_assert(docinfo);

        int rc = couchstore_open_doc_with_docinfo(db, docinfo, &doc, 0);
        if (rc < 0) {
            char buf[256];
            couchstore_free_docinfo(docinfo);
            snprintf(buf, sizeof(buf), "error getting doc by docinfo: %s", couchstore_strerror(rc));
            lua_pushstring(ls, buf);
            lua_error(ls);
            return 1;
        }

        lua_pushlstring(ls, doc->data.buf, doc->data.size);

        couchstore_free_document(doc);

        return 1;
    }

    // couch:get(key) -> string, docinfo
    static int couch_get(lua_State *ls)
    {
        if (lua_gettop(ls) < 1) {
            lua_pushstring(ls, "couch:get takes one argument: \"key\"");
            lua_error(ls);
            return 1;
        }

        Doc *doc;
        DocInfo *docinfo;
        Db *db = getDb(ls);
        CHECK_NULL(db)

        size_t klen;
        const char *key = luaL_checklstring(ls, 2, &klen);

        int rc = couchstore_docinfo_by_id(db, key, klen, &docinfo);
        if (rc < 0) {
            char buf[256];
            snprintf(buf, sizeof(buf), "error get docinfo (key=\"%s\"): %s",
                     key, couchstore_strerror(rc));
            lua_pushstring(ls, buf);
            lua_error(ls);
            return 1;
        }

        rc = couchstore_open_doc_with_docinfo(db, docinfo, &doc, 0);
        if (rc < 0) {
            char buf[1024];
            snprintf(buf, sizeof(buf),
                     "error get doc by docinfo (key=\"%s\", bp=%llu, size=%llu): %s",
                     key, (unsigned long long) docinfo->bp,
                     (unsigned long long) docinfo->physical_size, couchstore_strerror(rc));
            couchstore_free_docinfo(docinfo);
            lua_pushstring(ls, buf);
            lua_error(ls);
            return 1;
        }

        lua_pushlstring(ls, doc->data.buf, doc->data.size);
        push_docinfo(ls, docinfo);

        couchstore_free_document(doc);

        return 2;
    }

    // couch:truncate(length)
    static int couch_truncate(lua_State *ls)
    {
        if (lua_gettop(ls) < 1) {
            lua_pushstring(ls, "couch:truncate takes one argument: length");
            lua_error(ls);
            return 1;
        }

        Db *db = getDb(ls);
        CHECK_NULL(db)

        int64_t arg = static_cast<int64_t>(luaL_checknumber(ls, 2));
        cs_off_t location(0);
        if (arg < 1) {
            location = db->file.pos + arg;
        } else {
            location = static_cast<cs_off_t>(arg);
        }

        const char* path = couchstore_get_db_filename(db);

        int rv = truncate(path, location);
        if (rv != 0) {
            char buf[1256];
            snprintf(buf, sizeof(buf), "error truncating DB %s to %lld: %s (%d)",
                     path, (long long) location, strerror(errno), errno);
            lua_pushstring(ls, buf);
            lua_error(ls);
            return 1;
        }

        db->file.pos = location;

        return 0;
    }

    // couch:delete(key, [rev])
    static int couch_delete(lua_State *ls)
    {
        if (lua_gettop(ls) < 1) {
            lua_pushstring(ls, "couch:delete takes at least one argument: "
                           "\"key\" [rev_seq]");
            lua_error(ls);
            return 1;
        }

        Doc doc = DOC_INITIALIZER;
        DocInfo docinfo = DOC_INFO_INITIALIZER;

        doc.id.buf = const_cast<char *>(luaL_checklstring(ls, 2, &doc.id.size));
        doc.data.size = 0;
        docinfo.id = doc.id;
        docinfo.deleted = 1;

        if (lua_gettop(ls) > 2) {
            docinfo.rev_seq = (uint64_t) luaL_checknumber(ls, 3);
        }

        Db *db = getDb(ls);
        CHECK_NULL(db)

        int rc = couchstore_save_document(db, &doc, &docinfo, 0);
        if (rc < 0) {
            char buf[256];
            snprintf(buf, sizeof(buf), "error deleting document: %s", couchstore_strerror(rc));
            lua_pushstring(ls, buf);
            lua_error(ls);
            return 1;
        }

        return 0;
    }

    class BulkData
    {
    public:
        BulkData(unsigned n) : size(n),
            docs(static_cast<Doc **>(cb_calloc(size, sizeof(Doc *)))),
            infos(static_cast<DocInfo **>(cb_calloc(size, sizeof(DocInfo *)))) {
            cb_assert(docs);
            cb_assert(infos);

            for (unsigned i = 0; i < size; ++i) {
                docs[i] = static_cast<Doc *>(cb_calloc(1, sizeof(Doc)));
                cb_assert(docs[i]);
                infos[i] = static_cast<DocInfo *>(cb_calloc(1, sizeof(DocInfo)));
                cb_assert(infos[i]);
            }
        }

        ~BulkData() {
            for (unsigned i = 0; i < size; ++i) {
                cb_free(docs[i]);
                cb_free(infos[i]);
            }
            cb_free(docs);
            cb_free(infos);
        }

        unsigned size;
        Doc **docs;
        DocInfo **infos;
    };

    static int couch_save_bulk(lua_State *ls)
    {
        if (lua_gettop(ls) < 2) {
            lua_pushstring(ls, "couch:save_bulk requires a table full of docs to save");
            lua_error(ls);
            return 1;
        }

        if (!lua_istable(ls, -1)) {
            lua_pushstring(ls, "argument must be a table.");
            lua_error(ls);
            return 1;
        }

        BulkData bs((unsigned)lua_objlen(ls, -1));

        int offset(0);
        for (lua_pushnil(ls); lua_next(ls, -2); lua_pop(ls, 1)) {

            int n = static_cast<int>(lua_objlen(ls, -1));

            if (n > 2) {
                Doc *doc(bs.docs[offset]);
                cb_assert(doc);
                DocInfo *docinfo(bs.infos[offset]);
                cb_assert(docinfo);
                ++offset;
                revbuf_t revbuf;
                memset(&revbuf, 0, sizeof(revbuf));

                lua_rawgeti(ls, -1, 1);
                doc->id.buf = const_cast<char *>(luaL_checklstring(ls, -1, &doc->id.size));
                lua_pop(ls, 1);

                lua_rawgeti(ls, -1, 2);
                doc->data.buf = const_cast<char *>(luaL_checklstring(ls, -1, &doc->data.size));
                docinfo->id = doc->id;
                lua_pop(ls, 1);

                lua_rawgeti(ls, -1, 3);
                docinfo->content_meta = static_cast<uint8_t>(luaL_checkint(ls, -1));
                lua_pop(ls, 1);

                if (n > 3) {
                    lua_rawgeti(ls, -1, 4);
                    docinfo->rev_seq = (uint64_t) luaL_checknumber(ls, -1);
                    lua_pop(ls, 1);
                }

                if (n > 4) {
                    lua_rawgeti(ls, -1, 5);
                    revbuf.fields.cas = (uint64_t) luaL_checknumber(ls, -1);
                    revbuf.fields.cas = ntohll(revbuf.fields.cas);
                    lua_pop(ls, 1);
                }

                if (n > 5) {
                    lua_rawgeti(ls, -1, 6);
                    revbuf.fields.exp = static_cast<uint32_t>(luaL_checklong(ls, -1));
                    revbuf.fields.exp = ntohl(revbuf.fields.exp);
                    lua_pop(ls, 1);
                }

                if (n > 6) {
                    lua_rawgeti(ls, -1, 7);
                    revbuf.fields.flags = static_cast<uint32_t>(luaL_checklong(ls, 8));
                    revbuf.fields.flags = ntohl(revbuf.fields.flags);
                    lua_pop(ls, 1);
                }

                docinfo->rev_meta.size = sizeof(revbuf);
                docinfo->rev_meta.buf = revbuf.bytes;

            }
        }

        Db *db = getDb(ls);
        CHECK_NULL(db)

        int rc = couchstore_save_documents(db, bs.docs, bs.infos,
                                           bs.size, COMPRESS_DOC_BODIES);
        if (rc < 0) {
            char buf[256];
            snprintf(buf, sizeof(buf), "error storing document: %s", couchstore_strerror(rc));
            lua_pushstring(ls, buf);
            lua_error(ls);
            return 1;
        }

        return 0;
    }

    // couch:save(key, value, content_meta, [rev_seq], [cas], [exp], [flags]
    static int couch_save(lua_State *ls)
    {

        if (lua_gettop(ls) < 4) {
            lua_pushstring(ls, "couch:save takes at least three arguments: "
                           "\"key\" \"value\" meta_flags [rev_seq] [cas] [exp] [flags]");
            lua_error(ls);
            return 1;
        }

        Doc doc;
        DocInfo docinfo = DOC_INFO_INITIALIZER;

        revbuf_t revbuf;
        memset(&revbuf, 0, sizeof(revbuf));

        // These really should be const char*
        doc.id.buf = const_cast<char *>(luaL_checklstring(ls, 2, &doc.id.size));
        doc.data.buf = const_cast<char *>(luaL_checklstring(ls, 3, &doc.data.size));
        docinfo.id = doc.id;

        docinfo.content_meta = static_cast<uint8_t>(luaL_checkint(ls, 4));

        if (lua_gettop(ls) > 4) {
            docinfo.rev_seq = (uint64_t) luaL_checknumber(ls, 5);
        }

        if (lua_gettop(ls) > 5) {
            revbuf.fields.cas = (uint64_t) luaL_checknumber(ls, 6);
            revbuf.fields.cas = ntohll(revbuf.fields.cas);
        }

        if (lua_gettop(ls) > 6) {
            revbuf.fields.exp = static_cast<uint32_t>(luaL_checklong(ls, 7));
            revbuf.fields.exp = ntohl(revbuf.fields.exp);
        }

        if (lua_gettop(ls) > 7) {
            revbuf.fields.flags = static_cast<uint32_t>(luaL_checklong(ls, 8));
            revbuf.fields.flags = ntohl(revbuf.fields.flags);
        }

        docinfo.rev_meta.size = sizeof(revbuf);
        docinfo.rev_meta.buf = revbuf.bytes;

        Db *db = getDb(ls);
        CHECK_NULL(db)

        int rc = couchstore_save_document(db, &doc, &docinfo,
                                          COMPRESS_DOC_BODIES);
        if (rc < 0) {
            char buf[256];
            snprintf(buf, sizeof(buf), "error storing document: %s", couchstore_strerror(rc));
            lua_pushstring(ls, buf);
            lua_error(ls);
            return 1;
        }

        return 0;
    }

    static int couch_save_local(lua_State *ls)
    {
        if (lua_gettop(ls) < 3) {
            lua_pushstring(ls, "couch:save_local takes two arguments: "
                           "\"key\" \"value\"");
            lua_error(ls);
            return 1;
        }

        LocalDoc doc;
        doc.id.buf = const_cast<char *>(luaL_checklstring(ls, 2, &doc.id.size));
        doc.json.buf = const_cast<char *>(luaL_checklstring(ls, 3, &doc.json.size));
        doc.deleted = 0;

        Db *db = getDb(ls);
        CHECK_NULL(db)

        int rc = couchstore_save_local_document(db, &doc);
        if (rc < 0) {
            char buf[256];
            snprintf(buf, sizeof(buf), "error storing local document: %s",
                     couchstore_strerror(rc));
            lua_pushstring(ls, buf);
            lua_error(ls);
            return 1;
        }
        return 0;
    }

    static int couch_delete_local(lua_State *ls)
    {
        if (lua_gettop(ls) < 2) {
            lua_pushstring(ls, "couch:delete_local takes one argument: \"key\"");
            lua_error(ls);
            return 1;
        }

        LocalDoc doc;
        doc.id.buf = const_cast<char *>(luaL_checklstring(ls, 2, &doc.id.size));
        doc.json.size = 0;
        doc.deleted = 1;

        Db *db = getDb(ls);
        CHECK_NULL(db)

        int rc = couchstore_save_local_document(db, &doc);
        if (rc < 0) {
            char buf[256];
            snprintf(buf, sizeof(buf), "error deleting local document: %s",
                     couchstore_strerror(rc));
            lua_pushstring(ls, buf);
            lua_error(ls);
            return 1;
        }
        return 0;
    }

    // couch:get_local(key) -> val
    static int couch_get_local(lua_State *ls)
    {
        if (lua_gettop(ls) < 1) {
            lua_pushstring(ls, "couch:get_local takes one argument: \"key\"");
            lua_error(ls);
            return 1;
        }

        LocalDoc *doc;
        Db *db = getDb(ls);
        CHECK_NULL(db)

        size_t klen;
        // Should be const :/
        const char *key = luaL_checklstring(ls, 2, &klen);

        int rc = couchstore_open_local_document(db, static_cast<const void*>(key), klen, &doc);
        if (rc < 0) {
            char buf[256];
            snprintf(buf, sizeof(buf), "error getting local doc: %s",
                     couchstore_strerror(rc));
            lua_pushstring(ls, buf);
            lua_error(ls);
            return 1;
        }

        lua_pushlstring(ls, doc->json.buf, doc->json.size);

        couchstore_free_local_document(doc);

        return 1;
    }

    class ChangesState
    {
    public:
        ChangesState(lua_State *s, const char *f) : ls(s), fun_name(f) {
            cb_assert(lua_isfunction(ls, -1));
            lua_setfield(ls, LUA_REGISTRYINDEX, fun_name);
        }

        ~ChangesState() {
            lua_pushnil(ls);
            lua_setfield(ls, LUA_REGISTRYINDEX, fun_name);
        }

        void invoke(DocInfo *di) {
            lua_getfield(ls, LUA_REGISTRYINDEX, fun_name);
            push_docinfo(ls, di);
            if (lua_pcall(ls, 1, 0, 0) != 0) {
                // Not *exactly* sure what to do here.
                std::cerr << "Error running function: "
                          << lua_tostring(ls, -1) << std::endl;
            }
        }

    private:
        lua_State *ls;
        const char *fun_name;
    };

    static int couch_changes_each(Db *, DocInfo *di, void *ctx)
    {
        ChangesState *st(static_cast<ChangesState *>(ctx));
        st->invoke(di);
        return 1;
    }

    static int couch_func_id(0);

    // db:changes(since, options, function(docinfo) something end)
    static int couch_changes(lua_State *ls)
    {
        if (lua_gettop(ls) < 4) {
            lua_pushstring(ls, "couch:changes takes three arguments: "
                           "rev_seq, options, function(docinfo)...");
            lua_error(ls);
            return 1;
        }

        Db *db = getDb(ls);
        CHECK_NULL(db)

        uint64_t since((uint64_t)luaL_checknumber(ls, 2));
        couchstore_docinfos_options options((uint64_t)luaL_checknumber(ls, 3));

        if (!lua_isfunction(ls, 4)) {
            lua_pushstring(ls, "I need a function to iterate over.");
            lua_error(ls);
            return 1;
        }

        char fun_buf[64];
        snprintf(fun_buf, sizeof(fun_buf), "couch_fun_%d", ++couch_func_id);
        ChangesState changes_state(ls, fun_buf);

        int rc = couchstore_changes_since(db, since, options,
                                          couch_changes_each, &changes_state);
        if (rc != 0) {
            char buf[128];
            snprintf(buf, sizeof(buf), "error iterating: %s", couchstore_strerror(rc));
            lua_pushstring(ls, buf);
            lua_error(ls);
            return 1;
        }

        return 0;
    }

    static int couch_gc(lua_State *ls) {
        Db *db = getDb(ls);
        if(db != nullptr) {
            // Not allowed to error during garbage collection.
            couchstore_close_file(db);
            couchstore_free_db(db);
            nullDb(ls);
        }
        return 1;
    }

    static const luaL_Reg couch_funcs[] = {
        {"open", couch_open},
        {NULL, NULL}
    };

    static const luaL_Reg couch_methods[] = {
        {"save", couch_save},
        {"save_bulk", couch_save_bulk},
        {"delete", couch_delete},
        {"get", couch_get},
        {"get_from_docinfo", couch_get_from_docinfo},
        {"changes", couch_changes},
        {"save_local", couch_save_local},
        {"delete_local", couch_delete_local},
        {"get_local", couch_get_local},
        {"commit", couch_commit},
        {"close", couch_close},
        {"truncate", couch_truncate},
        {"__gc", couch_gc},
        {NULL, NULL}
    };

    static int docinfo_id(lua_State *ls)
    {
        DocInfo *di = getDocInfo(ls);
        lua_pushlstring(ls, di->id.buf, di->id.size);
        return 1;
    }

    static int docinfo_db_seq(lua_State *ls)
    {
        DocInfo *di = getDocInfo(ls);
        lua_pushnumber(ls, di->db_seq);
        return 1;
    }

    static int docinfo_rev_seq(lua_State *ls)
    {
        DocInfo *di = getDocInfo(ls);
        lua_pushnumber(ls, di->rev_seq);
        return 1;
    }

    static int docinfo_deleted(lua_State *ls)
    {
        DocInfo *di = getDocInfo(ls);
        lua_pushinteger(ls, di->deleted);
        return 1;
    }

    static int docinfo_content_meta(lua_State *ls)
    {
        DocInfo *di = getDocInfo(ls);
        lua_pushinteger(ls, di->content_meta);
        return 1;
    }

    static int docinfo_len(lua_State *ls)
    {
        DocInfo *di = getDocInfo(ls);
        lua_pushinteger(ls, di->physical_size);
        return 1;
    }

    static int docinfo_cas(lua_State *ls)
    {
        DocInfo *di = getDocInfo(ls);
        if (di->rev_meta.size >= sizeof(revbuf_t)) {
            revbuf_t *rbt(reinterpret_cast<revbuf_t *>(di->rev_meta.buf));
            lua_pushnumber(ls, ntohll(rbt->fields.cas));
        } else {
            lua_pushnumber(ls, 0);
        }
        return 1;
    }

    static int docinfo_exp(lua_State *ls)
    {
        DocInfo *di = getDocInfo(ls);
        if (di->rev_meta.size >= sizeof(revbuf_t)) {
            revbuf_t *rbt(reinterpret_cast<revbuf_t *>(di->rev_meta.buf));
            lua_pushnumber(ls, ntohl(rbt->fields.exp));
        } else {
            lua_pushnumber(ls, 0);
        }
        return 1;
    }

    static int docinfo_flags(lua_State *ls)
    {
        DocInfo *di = getDocInfo(ls);
        if (di->rev_meta.size >= sizeof(revbuf_t)) {
            revbuf_t *rbt(reinterpret_cast<revbuf_t *>(di->rev_meta.buf));
            lua_pushnumber(ls, ntohl(rbt->fields.flags));
        } else {
            lua_pushnumber(ls, 0);
        }
        return 1;
    }

    static int docinfo_gc(lua_State *ls)
    {
        DocInfo *di = getDocInfo(ls);
        couchstore_free_docinfo(di);
        return 1;
    }

    static const luaL_Reg docinfo_methods[] = {
        {"id", docinfo_id},
        {"rev", docinfo_rev_seq},
        {"db_seq", docinfo_db_seq},
        {"cas", docinfo_cas},
        {"exp", docinfo_exp},
        {"flags", docinfo_flags},
        {"deleted", docinfo_deleted},
        {"content_meta", docinfo_content_meta},
        {"size", docinfo_len},
        {"__len", docinfo_len},
        {"__gc", docinfo_gc},
        {NULL, NULL}
    };

}

static void initCouch(lua_State *ls)
{
    luaL_newmetatable(ls, "couch");

    lua_pushstring(ls, "__index");
    lua_pushvalue(ls, -2);  /* pushes the metatable */
    lua_settable(ls, -3);  /* metatable.__index = metatable */

    luaL_openlib(ls, NULL, couch_methods, 0);

    luaL_openlib(ls, "couch", couch_funcs, 0);
}

static void initDocInfo(lua_State *ls)
{
    luaL_newmetatable(ls, "docinfo");

    lua_pushstring(ls, "__index");
    lua_pushvalue(ls, -2);  /* pushes the metatable */
    lua_settable(ls, -3);  /* metatable.__index = metatable */

    luaL_openlib(ls, NULL, docinfo_methods, 0);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        std::cerr << "Give me a filename or give me death." << std::endl;
        exit(EX_USAGE);
    }

    if (getenv("LUA_PATH") == NULL) {
        std::string path = argv[1];
        static char lua_path[LUA_PATH_MAX_SIZE];
        size_t pos = path.find_last_of("/\\");
        if (pos != std::string::npos) {
            path.resize(pos);
            std::stringstream ss;
            ss << "LUA_PATH=" << path << "/?.lua;;";
            memcpy(lua_path, ss.str().c_str(), ss.str().length() + 1);
            putenv(lua_path);
        }
    }

    lua_State *ls = luaL_newstate();
    luaL_openlibs(ls);

    initCouch(ls);
    initDocInfo(ls);

    int rv(luaL_dofile(ls, argv[1]));
    if (rv != 0) {
        std::cerr << "Error running stuff:  " << lua_tostring(ls, -1) << std::endl;
        return rv;
    }

    int top = lua_gettop(ls);
    int rc = 1;
    if (top && lua_isnumber(ls, top)) {
        rc = static_cast<int>(lua_tonumber(ls, top));
    }
    lua_close(ls);
    return rc;
}
