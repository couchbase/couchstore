#!/usr/bin/env python2.7

# Simple example program to create a Couchstore file with a given
# number of keys.

from couchstore import CouchStore, DocumentInfo, SizedBuf
import os
import struct
import sys

BATCH_SIZE = 10000
REV_META_PACK = ">QII"

def insert(db, key, rev, value):
    info = DocumentInfo(key)
    info.revSequence = rev
    # cas, exp, flags
    info.revMeta = str(struct.pack(REV_META_PACK, 1, 2, 3))
    info.deleted = False
    return db.save(info, value)


def insert_multi(db, keys, values):
    """Inserts multiple keys / values."""

    ids = []
    for k in keys:
        info = DocumentInfo(k)
        info.revSequence = 1
        # cas, exp, flags
        info.revMeta = str(struct.pack(REV_META_PACK, 1, 2, 3))
        info.deleted = False
        ids.append(info)
    return db.saveMultiple(ids, values)


def chunks(l, n):
    """Yield successive n-sized chunks from l."""
    for i in range(0, len(l), n):
        yield l[i:i+n]


def main():
    if len(sys.argv) != 3:
        print("Usage: example1 <doc count> <file>")
        exit(1)
    db = CouchStore(sys.argv[2], 'c')
    for batch in chunks(list(range(0, int(sys.argv[1]))), BATCH_SIZE):
        insert_multi(db,
                     ["key_" + str(x) for x in batch],
                     [str(x) for x in batch])
        db.commit()
    db.close()

if __name__ == "__main__":
    main()
