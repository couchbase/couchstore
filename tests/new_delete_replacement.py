#!/usr/bin/env python3

# MB-54297 regression test - If:

# 1. libcouchstore.so has overriden the C++ operator new/delete
#    symbols (by linking global_new_replacement.cc from platform) to
#    use an alternative heap (jemalloc).
# 2. libcouchstore.so is dlopen()ed into a binary which does not
#    itself override operator new / delete (such as python3).
# 3. Another C++ library (e.g. snappy) has already been dlopen()ed
#    before libcouchstore.so and has called at least one operator new
#    function which is bound to the system heap.
#
# Then if libcouchstore.so calls a symbol in libstdc++.so.6 which in
# turn calls operator new (already bound at 3); then that operator new
# call will end up in the system heap, and if later deleted directly
# via libcouchstore.so we will attempt to free via jemalloc and crash.


# Import snappy, which depends on libstdc++.so and will call operator
# new at least once.
import snappy

# Attempt to import couchstore - this results in the heap mismatch
# described above and a segfault before the bug was fixed.
import couchstore

print("Package 'couchstore' loaded successfully.")
