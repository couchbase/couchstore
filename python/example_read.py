#!/usr/bin/env python2.7

# Simple program to read the given keys from a Couchstore file.

from couchstore import CouchStore, DocumentInfo, SizedBuf
import argparse
import os
import struct
import sys

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("file")
    parser.add_argument("keys", help="Key(s) to print", nargs="+")
    parser.add_argument("--unbuffered", help="Disable couchstore io buffering", action="store_true")
    args = parser.parse_args()

    db = CouchStore(args.file, 'r', unbuffered=args.unbuffered)
    for key in args.keys:
        print(db.get(key))
    db.close()


if __name__ == "__main__":
    main()
