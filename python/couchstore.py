# Python interface to CouchStore library

import errno
import os
import sys
import traceback

import ctypes


# Load the couchstore library. For PyInstaller compatibility, we
# must pass explicit bare library names to ctypes.CDLL(), not a
# variable name, so we can't do this in a loop.
_lib = None
try:
    _lib = ctypes.CDLL("libcouchstore.so")
except OSError as err:
    pass

if _lib is None:
    try:
        _lib = ctypes.CDLL("couchstore.dll")
    except OSError as err:
        pass

if _lib is None:
    try:
        _lib = ctypes.CDLL("libcouchstore.dylib")
    except OSError as err:
        pass

if _lib is None:
    raise ImportError("Failed to locate suitable couchstore shared library")

# Customize return types
_lib.couchstore_strerror.restype = ctypes.c_char_p


class CouchStoreException(Exception):
    """Exceptions raised by CouchStore APIs."""
    def __init__(self, errcode):
        Exception.__init__(self, _lib.couchstore_strerror(errcode))
        self.code = errcode


### INTERNAL FUNCTIONS:

def _check(err):
    if err == 0:
        return
    elif err == -3:
        raise MemoryError()
    elif err == -5:
        raise KeyError()
    elif err == -11:
        raise OSError(errno.ENOENT)
    else:
        raise CouchStoreException(err)


def _toString(key):
    if not isinstance(key, str):
        raise TypeError(key)
    return str(key)


### INTERNAL STRUCTS:

class SizedBuf(ctypes.Structure):
    _fields_ = [("buf", ctypes.POINTER(ctypes.c_char)), ("size", ctypes.c_size_t)]

    def __init__(self, string):
        if string is not None:
            if isinstance(string, bytes):
                length= len(string)
                buf = ctypes.create_string_buffer(string, length)
                ctypes.Structure.__init__(self, buf, length)
            else:
                string = _toString(string)
                length = len(string)
                buf = ctypes.create_string_buffer(string.encode(), length)
                ctypes.Structure.__init__(self, buf, length)
        else:
            ctypes.Structure.__init__(self, None, 0)

    def __str__(self):
        return ctypes.string_at(self.buf, self.size).decode()

    def get_bytes(self):
        return ctypes.string_at(self.buf, self.size)


class DocStruct(ctypes.Structure):
    _fields_ = [("id", SizedBuf), ("data", SizedBuf)]


class DocInfoStruct(ctypes.Structure):
    _fields_ = [("id", SizedBuf),
                ("db_seq", ctypes.c_ulonglong),
                ("rev_seq", ctypes.c_ulonglong),
                ("rev_meta", SizedBuf),
                ("deleted", ctypes.c_int),
                ("content_meta", ctypes.c_ubyte),
                ("bp", ctypes.c_ulonglong),
                ("size", ctypes.c_size_t)]


class LocalDocStruct(ctypes.Structure):
    _fields_ = [("id", SizedBuf),
                ("json", SizedBuf),
                ("deleted", ctypes.c_int)]


class DbInfoStruct(ctypes.Structure):
    _fields_ = [("filename", ctypes.c_char_p),
                ("last_sequence", ctypes.c_ulonglong),
                ("doc_count", ctypes.c_ulonglong),
                ("deleted_count", ctypes.c_ulonglong),
                ("space_used", ctypes.c_ulonglong),
                ("header_position", ctypes.c_ulonglong)]


class CounterStruct(ctypes.Structure):
    _fields_ = [("count", ctypes.c_ulonglong)]


class DocumentInfo(object):
    """Metadata of a document in a CouchStore database."""

    # Values for contentType:
    IS_JSON = 0
    INVALID_JSON = 1
    INVALID_JSON_KEY = 2
    NON_JSON = 3

    def __init__(self, id):
        self.id = id
        self.deleted = False
        self.contentType = DocumentInfo.NON_JSON
        self.revSequence = 0

    @staticmethod
    def _fromStruct(info, store=None):
        self = DocumentInfo(str(info.id))
        self.store = store
        self.sequence = info.db_seq
        self.revSequence = info.rev_seq
        self.revMeta = info.rev_meta
        self.deleted = (info.deleted != 0)
        self.contentType = info.content_meta & 0x0F
        self.compressed = (info.content_meta & 0x80) != 0
        self._bp = info.bp
        self.physSize = info.size
        return self

    def _asStruct(self):
        struct = DocInfoStruct(SizedBuf(self.id))
        if hasattr(self, "sequence"):
            struct.db_seq = self.sequence
        if hasattr(self, "revMeta"):
            if isinstance(self.revMeta, SizedBuf):
                struct.rev_meta = self.revMeta
            else:
                struct.rev_meta = SizedBuf(self.revMeta)
        struct.rev_seq = self.revSequence
        struct.deleted = self.deleted
        struct.content_meta = self.contentType & 0x0F
        if hasattr(self, "compressed") and self.compressed:
            struct.content_meta |= 0x80
        if hasattr(self, "_bp"):
            struct.bp = self._bp
        if hasattr(self, "physSize"):
            struct.size = self.physSize
        return struct

    def __str__(self):
        return "DocumentInfo('%s', %d bytes)" % (self.id, self.physSize)

    def __repr__(self):
        return "DocumentInfo('%s', %d bytes)" % (self.id, self.physSize)

    def dump(self):
        return "DocumentInfo('%s', %d bytes, seq=%d, revSeq=%d, deleted=%s, " \
               "contentType=%d, compressed=%d, bp=%d)" % \
            (self.id, self.physSize, self.sequence, self.revSequence,
             self.deleted, self.contentType, self.compressed, self._bp)

    def getContents(self, options=0):
        """Fetches and returns the contents of a DocumentInfo returned from
        CouchStore's getInfo or getInfoBySequence methods."""
        if not hasattr(self, "store") or not hasattr(self, "_bp"):
            raise Exception("Contents unknown")
        info = self._asStruct()
        docptr = ctypes.pointer(DocStruct())
        _check(_lib.couchstore_open_doc_with_docinfo(self.store,
                                                     ctypes.byref(info),
                                                     ctypes.byref(docptr),
                                                     ctypes.c_uint64(options)))
        contents = docptr.contents.data.get_bytes()
        _lib.couchstore_free_document(docptr)
        return contents


class LocalDocs(object):
    """Collection that represents the local documents of a CouchStore."""

    def __init__(self, couchstore):
        self.couchstore = couchstore

    def __getitem__(self, key):
        """Returns the contents of a local document (as a string) given its ID.
        """
        id = _toString(key)
        docptr = ctypes.pointer(LocalDocStruct())
        err = _lib.couchstore_open_local_document(self.couchstore,
                                                  ctypes.c_char_p(id.encode()),
                                                  ctypes.c_size_t(len(id)),
                                                  ctypes.byref(docptr))
        if err == -5 or (err == 0 and docptr.contents.deleted):
            raise KeyError(id)
        _check(err)
        value = str(docptr.contents.json)
        _lib.couchstore_free_document(docptr)
        return value

    def __setitem__(self, key, value):
        """Saves a local document with the given ID, or deletes it if the value
        is None."""
        idbuf = SizedBuf(key)
        doc = LocalDocStruct(idbuf)
        if value is not None:
            doc.json = SizedBuf(value)
        else:
            doc.deleted = True
        _check(_lib.couchstore_save_local_document(self.couchstore,
                                                   ctypes.byref(doc)))

    def __delitem__(self, key):
        self.__setitem__(key, None)


class CouchStore(object):
    """Interface to a CouchStore database."""

    def __init__(self, path, mode=None, unbuffered=False):
        """Creates a CouchStore at a given path. The option mode parameter can
        be 'r' for read-only access, or 'c' to create the file if it doesn't
        already exist."""
        if mode == 'r':
            flags = 2  # RDONLY
        elif mode == 'c':
            flags = 1  # CREATE
        else:
            flags = 0

        if unbuffered:
            flags |= 8 ## UNBUFFERED

        db = ctypes.c_void_p()
        _check(_lib.couchstore_open_db(ctypes.c_char_p(path.encode()),
                                       ctypes.c_uint64(flags),
                                       ctypes.byref(db)))
        self._as_parameter_ = db
        self.path = path

    def __del__(self):
        self.close()

    def close(self):
        """Closes the CouchStore."""
        if hasattr(self, "_as_parameter_"):
            _lib.couchstore_close_file(self)
            _lib.couchstore_free_db(self)
            del self._as_parameter_

    def __str__(self):
        return "CouchStore(%s)" % self.path

    def getDbInfo(self):
        """Returns an object with information about the database. Its
        properties are filename, last_sequence, doc_count, deleted_count,
        space_used, header_position."""
        info = DbInfoStruct()
        _check(_lib.couchstore_db_info(self, ctypes.byref(info)))
        return info

    def rewindHeader(self):
        """Rewinds the database handle to the next-oldest committed header.
        Closes the handle if none can be found"""
        if hasattr(self, "_as_parameter_"):
            err = _lib.couchstore_rewind_db_header(self)
            if err != 0:
                del self._as_parameter_
            _check(err)

    COMPRESS = 1

    def save(self, id, data, options=0):
        """Saves a document with the given ID. Returns the sequence number."""
        if isinstance(id, DocumentInfo):
            infoStruct = id._asStruct()
            idbuf = infoStruct.id
        else:
            idbuf = SizedBuf(id)
            infoStruct = DocInfoStruct(idbuf)
        if data is not None:
            doc = DocStruct(idbuf, SizedBuf(data))
            docref = ctypes.byref(doc)
            if options & CouchStore.COMPRESS:
                infoStruct.content_meta |= 0x80
        else:
            docref = None
        _check(_lib.couchstore_save_document(self, docref,
                                             ctypes.byref(infoStruct),
                                             ctypes.c_uint64(options)))
        if isinstance(id, DocumentInfo):
            id.sequence = infoStruct.db_seq
        return infoStruct.db_seq

    def saveMultiple(self, ids, datas, options=0):
        """Saves multiple documents. 'ids' is an array of either strings or
        DocumentInfo objects. 'datas' is a parallel array of value strings (or
        None, in which case the documents will be deleted.) Returns an array of
        new sequence numbers."""
        n = len(ids)
        docStructs = (ctypes.POINTER(DocStruct) * n)()
        infoStructs = (ctypes.POINTER(DocInfoStruct) * n)()
        for i in range(0, n):
            id = ids[i]
            if isinstance(id, DocumentInfo):
                info = id._asStruct()
            else:
                info = DocInfoStruct(SizedBuf(id))
            doc = DocStruct(info.id)
            if datas and datas[i]:
                doc.data = SizedBuf(datas[i])
            else:
                info.deleted = True
            infoStructs[i] = ctypes.pointer(info)
            docStructs[i] = ctypes.pointer(doc)
        _check(_lib.couchstore_save_documents(self,
                                              ctypes.byref(docStructs),
                                              ctypes.byref(infoStructs),
                                              ctypes.c_uint(n),
                                              ctypes.c_uint64(options)))
        return [info.contents.db_seq for info in infoStructs]
    pass

    def commit(self):
        """Ensures all saved data is flushed to disk."""
        _check(_lib.couchstore_commit(self))

    DECOMPRESS = 1

    def get(self, id, options=0):
        """Returns the contents of a document (as a string) given its ID."""
        id = _toString(id)
        docptr = ctypes.pointer(DocStruct())
        err = _lib.couchstore_open_document(self,
                                            id,
                                            ctypes.c_size_t(len(id)),
                                            ctypes.byref(docptr),
                                            options)
        if err == -5:
            raise KeyError(id)
        _check(err)
        data = str(docptr.contents.data)
        _lib.couchstore_free_document(docptr)
        return data

    def __getitem__(self, key):
        return self.get(key)

    def __setitem__(self, key, value):
        self.save(key, value)

    def __delitem__(self, key):
        self.save(key, None)

    # Getting document info:

    def _infoPtrToDoc(self, key, infoptr, err):
        if err == -5:
            raise KeyError(key)
        _check(err)
        info = infoptr.contents
        if info is None:
            return None
        doc = DocumentInfo._fromStruct(info, self)
        _lib.couchstore_free_docinfo(infoptr)
        return doc

    def getInfo(self, id):
        """Returns the DocumentInfo object with the given ID."""
        id = _toString(id)
        infoptr = ctypes.pointer(DocInfoStruct())
        err = _lib.couchstore_docinfo_by_id(self,
                                            id,
                                            ctypes.c_size_t(len(id)),
                                            ctypes.byref(infoptr))
        return self._infoPtrToDoc(id, infoptr, err)

    def getInfoBySequence(self, sequence):
        """Returns the DocumentInfo object with the given sequence number."""
        infoptr = ctypes.pointer(DocInfoStruct())
        err = _lib.couchstore_docinfo_by_sequence(self,
                                                  ctypes.c_ulonglong(sequence),
                                                  ctypes.byref(infoptr))
        return self._infoPtrToDoc(sequence, infoptr, err)

    # Iterating:

    ITERATORFUNC = ctypes.CFUNCTYPE(ctypes.c_int,
                                    ctypes.c_void_p,
                                    ctypes.POINTER(DocInfoStruct),
                                    ctypes.c_void_p)

    def forEachChange(self, since, fn):
        """Calls the function "fn" once for every document sequence since the
        "since" parameter. The single parameter to "fn" will be a DocumentInfo
        object. You can call getContents() on it to get the document contents.
        """
        def callback(dbPtr, docInfoPtr, context):
            fn(DocumentInfo._fromStruct(docInfoPtr.contents, self))
            return 0

        _check(_lib.couchstore_changes_since(self,
                                             ctypes.c_uint64(since),
                                             ctypes.c_uint64(0),
                                             CouchStore.ITERATORFUNC(callback),
                                             ctypes.c_void_p(0)))

    def changesSince(self, since):
        """Returns an array of DocumentInfo objects, for every document that's
        changed since the sequence number "since"."""
        changes = []
        self.forEachChange(since, lambda docInfo: changes.append(docInfo))
        return changes

    def forEachDoc(self, startKey, endKey, fn):
        def callback(dbPtr, docInfoPtr, context):
            fn(DocumentInfo._fromStruct(docInfoPtr.contents, self))
            return 0

        ids = (SizedBuf * 2)()
        numIDs = 1
        if startKey:
            ids[0] = SizedBuf(startKey)
        if endKey:
            ids[1] = SizedBuf(endKey)
            numIDs = 2
        _check(_lib.couchstore_docinfos_by_id(self,
                                              ids,
                                              ctypes.c_uint(numIDs),
                                              ctypes.c_uint64(1),
                                              CouchStore.ITERATORFUNC(callback),
                                              ctypes.c_void_p(0)))

    def changesCount(self, minimum, maximum):
        cstruct = CounterStruct()
        err = _lib.couchstore_changes_count(self,
                                            ctypes.c_uint64(minimum),
                                            ctypes.c_uint64(maximum),
                                            ctypes.pointer(cstruct))
        _check(err)
        return cstruct.count

    @property
    def localDocs(self):
        """A simple dictionary-like object that accesses the CouchStore's local
        documents."""
        return LocalDocs(self)
