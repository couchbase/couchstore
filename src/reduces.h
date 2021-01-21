#pragma once

#include "bitfield.h"
#include "couch_btree.h"
#include <libcouchstore/couch_common.h>
#include <libcouchstore/couch_db.h>

struct raw_by_seq_reduce {
    raw_40 count;
};

struct raw_by_id_reduce {
    raw_40 notdeleted;
    raw_40 deleted;
    raw_48 size;
};

couchstore_error_t by_seq_reduce(char* dst,
                                 size_t* size_r,
                                 const nodelist* leaflist,
                                 int count,
                                 void* ctx);
couchstore_error_t by_seq_rereduce(char* dst,
                                   size_t* size_r,
                                   const nodelist* leaflist,
                                   int count,
                                   void* ctx);

couchstore_error_t by_id_rereduce(char* dst,
                                  size_t* size_r,
                                  const nodelist* leaflist,
                                  int count,
                                  void* ctx);
couchstore_error_t by_id_reduce(char* dst,
                                size_t* size_r,
                                const nodelist* leaflist,
                                int count,
                                void* ctx);
