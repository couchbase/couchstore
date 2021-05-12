#!/usr/bin/env python3

from couchstore import CouchStore, DocumentInfo
from tempfile import mkdtemp
import os
import os.path as path
import struct
import unittest

class ChangeCountTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = mkdtemp()
        self.dbname = path.join(self.tmpdir, "testing.couch")
        self.db = CouchStore(self.dbname, 'c');

    def tearDown(self):
        try:
            self.db.commit()
            self.db.close()
        except:
            pass
        try:
            os.remove(self.dbname)
        except:
            pass
        try:
            os.rmdir(self.tmpdir)
        except:
            pass

    def bulkSet(self, prefix, n):
        ids = [prefix + str(x) for x in range(n)]
        datas = ["val" + str(x) for x in range(n)]
        self.db.saveMultiple(ids, datas)

    def testRewind(self):
        # Save some docs
        self.db.save("foo1", "bar")
        self.db.save("foo2", "baz")
        self.db.save("foo3", "bell")
        self.db.save("foo4", "a")
        self.assertEqual(self.db.changesCount(0,100), 4)

        self.db.save("foo1", "new_bar")
        self.db.save("foo2", "new_baz")
        self.db.save("foo3", "new_bell")
        self.db.save("foo4", "new_a")
        self.assertEqual(self.db.changesCount(0,100), 4)

        self.bulkSet("foo", 100)
        self.assertEqual(self.db.changesCount(0, 108), 100)
        self.assertEqual(self.db.changesCount(0, 100), 92)
        self.assertEqual(self.db.changesCount(1, 100), 92)
        self.assertNotEqual(self.db.changesCount(12, 100), 92)
        self.assertEqual(self.db.changesCount(50, 99), 50)
        self.assertEqual(self.db.changesCount(50, 100), 51)
        self.assertEqual(self.db.changesCount(50, 108), 59)
        self.assertEqual(self.db.changesCount(51, 100), 50)
        self.assertEqual(self.db.changesCount(91, 1000), 18)
        self.db.save("foo88", "tval")
        self.assertEqual(self.db.changesCount(50, 108), 58)
        self.assertEqual(self.db.changesCount(50, 109), 59)


if __name__ == '__main__':
    unittest.main()
