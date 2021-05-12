#!/usr/bin/env python3

from couchstore import CouchStore, DocumentInfo
from tempfile import mkdtemp
import os
import os.path as path
import struct
import unittest

class RewindTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = mkdtemp()
        self.dbname = path.join(self.tmpdir, "testing.couch")
        self.db = CouchStore(self.dbname, 'c');

    def tearDown(self):
        try:
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

    def testRewind(self):
        # Save some docs
        self.db.save("foo1", "bar")
        self.db.save("foo2", "baz")
        self.db.save("foo3", "bell")
        self.db.save("foo4", "a")
        self.db.commit()

        # Edit some docs
        self.db.save("foo1", "new_bar")
        self.db.save("foo2", "new_baz")
        self.db.save("foo3", "new_bell")
        self.db.save("foo4", "new_a")
        self.db.commit()

        # The edits happened...
        self.assertNotEqual(self.db["foo3"], "bell");
        self.assertEqual(self.db["foo4"], "new_a");

        # rewind
        self.db.rewindHeader()

        # did we go back in time?
        self.assertEqual(self.db["foo3"], "bell");
        self.assertNotEqual(self.db["foo4"], "new_a");


if __name__ == '__main__':
    unittest.main()
