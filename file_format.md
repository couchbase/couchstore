# Couchstore Database File Format

### Compiled by Aaron Miller and Jens Alfke, with help from Damien Katz

This is the current database file format used by Couchbase Server 2.0.
It's similar, but not identical, to the format used by [Apache
CouchDB][COUCHDB] 1.2. It is implemented in a Couchbase 2.0 fork of
CouchDB (in Erlang), and also by [Couchstore][COUCHSTORE] in C.

## How A File Is Written

The most important thing to understand about a CouchDB file is that it
is **append-only**.  The only way the file is modified is to append new
data at the end; bytes written are never overwritten.  As a consequence,
the critical file "header" data actually lives at the tail end of the
file, since it has to be re-appended every time the file is changed.

This has several advantages:

* The data format is extremely robust, since the file is never in an
  inconsistent state. Even if the process crashes or the kernel panics
  partway through writing an update, the software can recover simply by
  scanning back from the end of the file to the last valid header.
* Writers don't disturb readers at all, allowing concurrent access
  without read locks.
* By default, earlier versions of a record remain in the file, making it
  easy to implement a version history and multi-version concurrency
  control (as exposed in the CouchDB API.)

The disadvantage, of course, is that the file grows without bound as
it's modified. To work around this, the file is periodically compacted
by writing the live data to a new file, then replacing the old file with
the new one.  This can be done in the background without locking out
either readers or writers.

## Numbers And Alignment

 * Numbers are in big-endian byte order (most significant byte first).
 * All values are tightly packed; there is no padding or multi-byte
   alignment.
 * Some values occupy partial bytes and have lengths that are not a
   multiple of 8 bits.  These are stored in most-significant to
   least-significant bit order. So for example, if a 1-bit field is
   followed by a 47-bit field, the first field occupies the MSB of the
   first byte, and the second occupies the rest of the first byte and
   the entirety of the next five bytes.

## File Blocks

For purposes of locating the current file header (q.v.), the file is
organized into 4096-byte blocks. The first byte of every block is
reserved and identifies whether it's a data block (zero) or a header
block (nonzero). Therefore only 4095 of the bytes are available for
storing data.

Above the block level, these prefix bytes are invisible and simply
skipped. So a data value that spans a block boundary will be written out
with a zero byte inserted at the boundary, and this byte will be removed
when reading the value.

## Data Chunks

The data in the file (above the block level) is grouped into
variable-length **chunks**.  All chunks are prefixed with their length
as a 32-bit big endian integer, followed by the [CRC32][CRC32] checksum
of the data. The CRC32 is *not* included in the length. The data chunk
length has its highest bit set.

length   | content
---------|--------
 32 bits | body length (highest bit set)
 32 bits | CRC32 checksum of body

followed by the body data

## Encrypted Data Chunks

Similarly to plain data chunks, encrypted chunks are prefixed with the
ciphertext length as a 32-bit big endian integer. The highest bit is
*not* set. The length is followed by the ciphertext, which includes
the MAC tag. No extra checksum is included.

A per-file random key is used, which is generated when creating the
file.

### AES-256-GCM cipher

GCM is used with a 96-bit (12-byte) nonce/IV. The ciphertext is suffixed
by a 16-byte MAC tag.

As data chunks are always appended to the end of the file, we use the
offset in the file as a unique value for the nonce. A chunk that appears
at the beginning of a block may be read from the block boundary or one
byte ahead, as the first byte of a block is the block type which will be
skipped over. To ensure that the same nonce is used for encryption and
decryption, we need to adjust the nonce such that it is the same in
those two cases. If the offset is at the block boundary, we increment
the nonce by one.

## File Header

A file header always appears on a 4096-byte block boundary, and the
first byte of the block is 0x01 to signal that it contains a header.
A file will contain many headers as it grows, since a new updated one is
appended whenever data is saved; the current header is the _last_ one in
the file. So the algorithm to find the header when opening the file is
to seek to the last block boundary, read one byte, and keep skipping
back 4096 bytes until the byte read is nonzero.

The file header is prefixed with a 32 bit length and a checksum,
similarly to other data chunks, but the length field **does** include
the length of the hash.

File headers are not encrypted.

The CRC32 variant in header and data chunks depends on the file version.
Since version 12, CRC32C (Castagnoli) is used, as some processors
provide instructions for accelerating its computation.

Support for encryption is introduced in version 14. The file header
format is the same as in version 13.

Values in the body of a file header:

length  | content
--------|--------
8 bits  | File format version (currently 14)
48 bits | Sequence number of next update.
48 bits | Purge counter.
48 bits | Purged documents pointer. (unused)
16 bits | Size of by-sequence B-tree root
16 bits | Size of by-ID B-tree root
16 bits | Size of local documents B-tree root
64 bits | Timestamp (present from version 13)

 * The B-tree roots, in the order of the sizes, are B-tree node pointers as
   described in the "Node Pointers" section.

## Metadata Header

When encryption is used, the master key ID and encrypted file key is
stored in a metadata header. This appears as the first chunk of the
first block. The first block then has type 0x02.

length  | content
--------|--------
32 bits | Length of the following (including checksum)
32 bits | CRC32C checksum of the following
8 bits  | Version (currently 0)
8 bits  | Key ID length
...     | Key ID
8 bits  | Encrypted File Key length
...     | Encrypted File Key

The encrypted file key is prefixed by a random nonce and suffixed by
the MAC tag (all included in length). The key ID is Authenticated as
Associated Data.

## B-Tree Format

The B-trees used in CouchDB files are a bit different than in a typical
implementation, because the file is append-only.  A tree node is never
updated in place; instead, a new copy of the updated node is written at
the end of the file.  Of course this means that the node's parent also
has to be updated to point at the updated node, so the effect is that
every modification has to rewrite all the nodes from the affected leaf
up to the root. In practice this isn't too expensive, especially if
multiple writes are batched together into one update.

CouchDB's B-trees also have to forgo the sibling-node chaining that's
typically used to speed up sequential access. The reason is that
updating a node would invalidate the pointers to it in its siblings,
forcing those nodes to be updated as well, resulting in a huge cascade
of updates. Instead, the iteration algorithm remembers the path back to
the root and periodically backtracks to find the next sibling node.

### Nodes On Disk

All B-tree nodes are compressed using the [Snappy][SNAPPY] algorithm.
The descriptions following all refer to the uncompressed form.

 * First byte -- 1 if a leaf (key/value) node, 0 if an interior
   (key/pointer) node
 * A list of key-value or key-pointer pairs, each of which is:
	* 12 bits -- Key size
	* 28 bits -- Value size
	* Followed by the Key data,
	* then the Value or Pointer data

In interior nodes the Value parts of these pairs are pointers to another
B-tree node, where keys less than or equal to that pair's Key will be.

In leaf nodes the values are interpreted differently by each index; see
the Indexes section below.

### Node Pointers

 * 48 bits -- Node position in file
 * 48 bits -- Sub tree size, or disk size of B-tree data below this node. For
   pointers to leaf nodes this is the size on disk of the pointed to node,
   otherwise it is the sum of the size of the pointed to node and all
   the values of this field on the pointers in that node.
 * 16 bits -- Reduce value size (**NOT** present in the root pointers
   embedded in the file header, as it can be inferred from the lengths
   in the header)
 * Reduce value -- Stores statistics about the subtree beneath this
   node. The exact data format is different in each type of B-tree, and
   is detailed below.

## Indexes

A CouchDB file contains three B-trees:

 * The **by-ID** index, which maps document IDs to values.
 * The **by-sequence** index, which maps sequence numbers (database
   change numbers, which increase monotonically with every change) to
   document IDs and values.
 * The **local-documents** index, which is conceptually the same as the
   by-ID index except that the documents in it do not appear in the
   by-sequence index, and by CouchDB convention the document IDs all
   begin with the ASCII sequence `_local/`.

### The By-ID Index

This B-tree is an index of documents by their IDs.  The keys are simply
the document IDs, ordered lexicographically by raw bytes (as by the
`memcmp` function.)

The values are:


length  | content
--------|--------
48 bits | The sequence number this document was last modified at. If another revision of this document is later saved, this sequence number should be *removed* from the by-sequence index.
32 bits | Size of the document data
1 bit   | Deleted flag. If this is set this document should be ignored in indexing.
47 bits | Position of the document content on disk
1 bit   | 1 if the value is compressed using the Snappy algorithm
7 bits  | Content type code (q.v.)
48 bits | Document revision number (rev\_seq)

Followed by

 * Revision Metadata (q.v.)

Couchstore does not react to the content type code, document revision
number, or revision metadata.  These values are used by CouchDB and
Couchbase Server.

Couchstore can optionally handle the deleted flag when asked to (users
can read the sequence index without deleted records, or run a "purge"
compaction that drops deleted items.)

The reduce value in interior nodes of this B-tree is:

length  | content
--------|--------
40 bits | Number of documents that are *not* flagged as deleted.
40 bits | Number of documents that *are* flagged as deleted
48 bits | Total disk size of document content

#### Content Type Code

CouchDB uses this to identify the type of the document data.

 *  0 -- JSON data
 *  1 -- BLOB data (Attempted to parse as JSON but failed)
 *  2 -- BLOB data (Parsed as syntactically valid JSON, but illegally
	contains reserved keys) There are no longer reserved keys in
	Couchbase, so this content-type code should never be seen. It should
	be okay to repurpose it at some point

 *  3 -- BLOB data (No attempt to parse as JSON)

#### Revision Metadata

This is identifying information about a document revision that should be
small enough to be kept in the indexes. This value is not interpreted by
Couchstore.

It's currently used by Couchbase as

length   | content
---------|--------
64 bits  | Memcached CAS value (unique cookie used by memcache to allow atomic writes)
32 bits  | Expiration time of a value
32 bits  | User flags as specified by Memcache protocol


### The By-Sequence Index

The keys in this B-tree are 48-bit numbers representing the sequence
number of a change to the database. This number is strictly increasing.

The values are:

length  | content
--------|-------
12 bits | Size of the document ID
28 bits | Size of the document data
1 bit   | Deleted flag (this item in the by-sequence index represents a deletion action if this is set)
47 bits | Position of the document content on disk
1 bit   | 1 if the value is compressed using the Snappy algorithm
7 bits  | Content type code
48 bits | Document revision number (rev\_seq)

Followed by

 * Document ID
 * Revision Metadata (variable size; extends to the end of the value
   record)

The reduce value in interior nodes of this B-tree is a 40 bit number of records

### The Local Documents Index

Local documents are used for file-level configuration and metadata.

The keys in the local document b-tree are the document IDs, including
the `_local/` prefix, and as in the ID tree sorted by `memcmp`.

The value in the local document b-tree is the raw JSON body of the local
document.

[COUCHDB]: 		http://couchdb.apache.org
[COUCHSTORE]:	https://github.com/couchbaselabs/couchstore
[CRC32]:		https://en.wikipedia.org/wiki/Cyclic\_redundancy\_check
[SNAPPY]:		http://code.google.com/p/snappy/

