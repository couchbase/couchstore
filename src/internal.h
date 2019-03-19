/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#ifndef LIBCOUCHSTORE_INTERNAL_H
#define LIBCOUCHSTORE_INTERNAL_H 1

/*
 * This file contains datastructures and prototypes for functions only to
 * be used by the internal workings of libcoucstore. If you for some reason
 * need access to them from outside the library, you should write a
 * function to give you what you need.
 */

#include <libcouchstore/couch_db.h>
#include "config.h"
#include "crc32.h"

#define COUCH_BLOCK_SIZE 4096
#define COUCH_DISK_VERSION_11 11
#define COUCH_DISK_VERSION_12 12
#define COUCH_DISK_VERSION COUCH_DISK_VERSION_12
#define COUCH_SNAPPY_THRESHOLD 64
#define MAX_DB_HEADER_SIZE 1024    /* Conservative estimate; just for sanity check */

// Default values for buffered IO
#define MAX_READ_BUFFERS 16
#define WRITE_BUFFER_CAPACITY (128*1024)
#define READ_BUFFER_CAPACITY (4*1024)

#ifdef WIN32
#define PATH_MAX MAX_PATH
#endif

#ifndef PATH_MAX
#define PATH_MAX 1024
#endif

typedef struct {
    uint64_t purge_before_ts;
    uint64_t purge_before_seq;
    uint64_t max_purged_seq;
} time_purge_ctx;

#ifdef __cplusplus
extern "C" {
#endif

    /* Configurations for an open file */
    struct tree_file_options {
        tree_file_options()
            : buf_io_enabled(true),
              buf_io_read_unit_size(READ_BUFFER_CAPACITY),
              buf_io_read_buffers(MAX_READ_BUFFERS),
              kp_nodesize(0),
              kv_nodesize(0),
              periodic_sync_bytes(0),
              tracing_enabled(false),
              write_validation_enabled(false),
              mprotect_enabled(false) {
        }

        // Flag indicating whether or not buffered IO is enabled.
        bool buf_io_enabled;
        // Read buffer capacity, if buffered IO is enabled.
        // Set to zero for the default value.
        uint32_t buf_io_read_unit_size;
        // Max count of read buffers, if buffered IO is enabled.
        // Set to zero for the default value.
        uint32_t buf_io_read_buffers;
        // Threshold of key-pointer (intermediate) node size.
        uint32_t kp_nodesize;
        // Threshold of key-value (leaf) node size.
        uint32_t kv_nodesize;
        // Automatically issue an sync() operation after every N bytes written.
        // 0 means don't automatically sync.
        uint64_t periodic_sync_bytes;
        /* tracing and validation options  */
        bool tracing_enabled;
        bool write_validation_enabled;
        bool mprotect_enabled;
    };

     /* Structure representing an open file; "superclass" of Db */
    typedef struct _treefile {
        uint64_t pos;
        FileOpsInterface* ops;
        couch_file_handle handle;
        const char* path;
        couchstore_error_info_t lastError;
        crc_mode_e crc_mode;
        tree_file_options options;
    } tree_file;

    typedef struct _nodepointer {
        sized_buf key;
        uint64_t pointer;
        sized_buf reduce_value;
        uint64_t subtreesize;
    } node_pointer;

    typedef struct _db_header {
        uint64_t disk_version;
        uint64_t update_seq;
        node_pointer *by_id_root;
        node_pointer *by_seq_root;
        node_pointer *local_docs_root;
        uint64_t purge_seq;
        uint64_t purge_ptr;
        uint64_t position;
    } db_header;

    struct _db {
        tree_file file;
        db_header header;
        int dropped;
        void *userdata;
    };

    /**
     * Returns a newed FileOpsInterface implementation
     * instance.
     *
     * Useful for assuming that a FileOpsInterface object
     * is heap-allocated.
     */
    LIBCOUCHSTORE_API
    FileOpsInterface* create_default_file_ops(void);

    /** Opens or creates a tree_file.
        @param file  Pointer to tree_file struct to initialize.
        @param filename  Path to the file
        @param flags  POSIX open-mode flags
        @param crc_mode CRC the file should use.
        @param ops  File I/O operations to use
        @param buffered Should the file operations be
               wrapped by an IO buffer */
    couchstore_error_t tree_file_open(tree_file* file,
                                      const char *filename,
                                      int openflags,
                                      crc_mode_e crc_mode,
                                      FileOpsInterface* ops,
                                      tree_file_options options);
    /** Closes a tree_file.
        @param file  Pointer to open tree_file. Does not free this pointer! */
    couchstore_error_t tree_file_close(tree_file* file);

    /** Reads a chunk from the file at a given position.
        @param file The tree_file to read from
        @param pos The byte position to read from
        @param ret_ptr On success, will be set to a malloced buffer containing the chunk data,
                or to NULL if the length is zero. Caller is responsible for freeing this buffer!
                On failure, value pointed to is unaltered.
        @return The length of the chunk (zero is a valid length!), or a negative error code */
    int pread_bin(tree_file *file, cs_off_t pos, char **ret_ptr);

    /** Reads a compressed chunk from the file at a given position.
        Parameters and return value are the same as for pread_bin. */
    int pread_compressed(tree_file *file, cs_off_t pos, char **ret_ptr);

    /** Reads a file header from the file at a given position.
        Parameters and return value are the same as for pread_bin. */
    int pread_header(tree_file *file,
                     cs_off_t pos,
                     char **ret_ptr,
                     uint32_t max_header_size);

    couchstore_error_t write_header(tree_file *file, sized_buf *buf, cs_off_t *pos);
    int db_write_buf(tree_file *file, const sized_buf *buf, cs_off_t *pos, size_t *disk_size);
    couchstore_error_t db_write_buf_compressed(tree_file *file, const sized_buf *buf, cs_off_t *pos, size_t *disk_size);
    struct _os_error *get_os_error_store(void);
    couchstore_error_t by_seq_read_docinfo(DocInfo **pInfo,
                                           const sized_buf *k,
                                           const sized_buf *v);

    couchstore_error_t precommit(Db *db);
    couchstore_error_t db_write_header(Db *db);

#ifdef __cplusplus
}
#endif

#endif
