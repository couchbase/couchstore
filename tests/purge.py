#!/usr/bin/env python3

from couchstore import CouchStore, DocumentInfo
from tempfile import mkdtemp
import os
import os.path as path
import struct
import unittest

REV_META_PACK = ">QII"

def deleteAt(db, key, time):
    info = db.getInfo(key)
    # cas, exp, flags
    info.revMeta = struct.pack(REV_META_PACK, 0, time, 0)
    info.deleted = True
    return db.save(info, None)

class PurgeTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = mkdtemp()
        self.origname = path.join(self.tmpdir, "orig.couch")
        self.purgedname = path.join(self.tmpdir, "purged.couch")
        self.origdb = CouchStore(self.origname, 'c');

    def tearDown(self):
        try:
            self.origdb.close()
        except:
            pass
        try:
            self.newdb.close()
        except:
            pass
        try:
            os.remove(self.origname)
        except:
            pass
        try:
            os.remove(self.purgedname)
        except:
            pass
        try:
            os.rmdir(self.tmpdir)
        except:
            pass

    def testPurgeCompact(self):
        # Save some docs
        self.origdb.save("foo1", "bar")
        self.origdb.save("foo2", "baz")
        self.origdb.save("foo3", "bell")
        self.origdb.save("foo4", "a")

        # Delete some
        seqPurged = deleteAt(self.origdb, "foo2", 10)
        seqKept = deleteAt(self.origdb, "foo3", 20)
        seqLateDelete = deleteAt(self.origdb, "foo4", 11)
        self.origdb.commit()

        os.system(path.join(os.getcwd(), "couch_compact") + " --purge-before 15 " +
                  self.origname + " " + self.purgedname)
        self.newdb = CouchStore(self.purgedname)

        # Check purged item is not present in key tree and kept item is
        self.assertRaises(KeyError, self.newdb.getInfo, "foo2")
        self.assertIsNotNone(self.newdb.getInfo("foo3"))
        self.assertRaises(KeyError, self.newdb.getInfo, "foo4")

        self.newdb.close()

        os.system(path.join(os.getcwd(), "couch_compact") +
                  " --purge-before 15 --purge-only-upto-seq " + str(seqKept) +
                  " " + self.origname + " " + self.purgedname)
        self.newdb = CouchStore(self.purgedname)

        # Check purged item is not present in key tree and kept item is
        self.assertRaises(KeyError, self.newdb.getInfo, "foo2")
        self.assertIsNotNone(self.newdb.getInfo("foo3"))
        # with purge-only-upto-seq just before deletion of foo4 we
        # must find it after compaction
        self.assertIsNotNone(self.newdb.getInfo("foo4"))

        self.newdb.close()

        os.system(path.join(os.getcwd(), "couch_compact") +
                  " --purge-before 15 --purge-only-upto-seq " + str(seqLateDelete) +
                  " " + self.origname + " " + self.purgedname)
        self.newdb = CouchStore(self.purgedname)

        # Check purged item is not present in key tree and kept item is
        self.assertRaises(KeyError, self.newdb.getInfo, "foo2")
        self.assertIsNotNone(self.newdb.getInfo("foo3"))
        # with purge-only-upto-seq just at deletion of foo4 we
        # must not find it after compaction
        self.assertRaises(KeyError, self.newdb.getInfo, "foo4")

        # Check purged item is not present in seq tree and kept item is
        self.assertRaises(KeyError, self.newdb.getInfoBySequence, seqPurged)
        self.assertIsNotNone(self.newdb.getInfoBySequence(seqKept))


if __name__ == '__main__':
    unittest.main()
