PROJECT(Couchstore)
CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

IF (${CMAKE_MAJOR_VERSION} GREATER 2)
    CMAKE_POLICY(SET CMP0042 NEW)
ENDIF (${CMAKE_MAJOR_VERSION} GREATER 2)

INCLUDE(CheckFunctionExists)
INCLUDE(CheckIncludeFile)
INCLUDE(CheckIncludeFiles)
INCLUDE(CheckLibraryExists)
INCLUDE(CheckSymbolExists)
INCLUDE(CheckTypeSize)
INCLUDE(CTest)

INCLUDE_DIRECTORIES(BEFORE ${CMAKE_INSTALL_PREFIX}/include
                           ${CMAKE_CURRENT_SOURCE_DIR}/include
                           ${CMAKE_CURRENT_SOURCE_DIR}/src
                           ${CMAKE_CURRENT_BINARY_DIR}
                           ${CMAKE_CURRENT_SOURCE_DIR}
                           ${BOOST_INCLUDE_DIR}
                           ${Platform_SOURCE_DIR}/include
                           ${phosphor_SOURCE_DIR}/include)

IF (LUA_FOUND)
   INCLUDE_DIRECTORIES(AFTER {LUA_INCLUDE_DIR})
ENDIF (LUA_FOUND)

INCLUDE_DIRECTORIES(AFTER
                    ${KVEngineAPI_SOURCE_DIR}
                    ${KVEngineAPI_BINARY_DIR})

INCLUDE_DIRECTORIES(AFTER ${ICU_INCLUDE_DIR}
                          ${V8_INCLUDE_DIR}
                          ${SNAPPY_INCLUDE_DIR})

CHECK_INCLUDE_FILES("netinet/in.h" HAVE_NETINET_IN_H)
CHECK_INCLUDE_FILES("inttypes.h" HAVE_INTTYPES_H)
CHECK_INCLUDE_FILES("unistd.h" HAVE_UNISTD_H)
CHECK_SYMBOL_EXISTS(fdatasync "unistd.h" HAVE_FDATASYNC)
CHECK_SYMBOL_EXISTS(qsort_r "stdlib.h" HAVE_QSORT_R)

IF (WIN32)
  SET(COUCHSTORE_FILE_OPS "src/os_win.cc")
ELSE(WIN32)
  SET(COUCHSTORE_FILE_OPS "src/os.cc")
ENDIF(WIN32)

SET(COUCHSTORE_SOURCES src/arena.cc
                       src/bitfield.cc
                       src/btree_modify.cc
                       src/btree_read.cc
                       src/couch_db.cc
                       src/couch_file_read.cc
                       src/couch_file_write.cc
                       src/couch_latency.cc
                       src/couch_save.cc
                       src/crc32.cc
                       src/db_compact.cc
                       src/file_merger.cc
                       src/file_name_utils.c
                       src/file_sorter.cc
                       src/iobuffer.cc
                       src/llmsort.cc
                       src/mergesort.cc
                       src/node_types.cc
                       src/reduces.cc
                       src/strerror.cc
                       src/tree_writer.cc
                       src/util.cc
                       src/views/bitmap.c
                       src/views/collate_json.cc
                       src/views/file_merger.cc
                       src/views/file_sorter.cc
                       src/views/index_header.cc
                       src/views/keys.cc
                       src/views/mapreduce/mapreduce.cc
                       src/views/mapreduce/mapreduce_c.cc
                       src/views/reducers.cc
                       src/views/reductions.cc
                       src/views/sorted_list.c
                       src/views/spatial.cc
                       src/views/spatial_modify.cc
                       src/views/util.cc
                       src/views/values.cc
                       src/views/view_group.cc
                       src/views/purgers.cc
                       src/views/compaction.cc
                       src/quicksort.c
                       ${COUCHSTORE_FILE_OPS})
SET(COUCHSTORE_LIBRARIES ${V8_LIBRARIES} ${ICU_LIBRARIES} ${SNAPPY_LIBRARIES} platform phosphor)

SET(COUCHSTORE_GTEST_LIBRARIES gtest gtest_main gmock phosphor)
SET(COUCHSTORE_GTEST_INCLUDES ${gtest_SOURCE_DIR}/include ${gmock_SOURCE_DIR}/include)

ADD_LIBRARY(couchstore SHARED ${COUCHSTORE_SOURCES})
SET_TARGET_PROPERTIES(couchstore PROPERTIES COMPILE_FLAGS "-DLIBCOUCHSTORE_INTERNAL=1 -DLIBMAPREDUCE_INTERNAL=1")
TARGET_LINK_LIBRARIES(couchstore ${COUCHSTORE_LIBRARIES})

ADD_EXECUTABLE(couch_dbdump
               src/dbdump.cc
               src/tracking_file_ops.cc
               ${COUCHSTORE_SOURCES}
               ${KVEngineAPI_BINARY_DIR}/xattr/visibility.h)

ADD_DEPENDENCIES(couch_dbdump xattr)
SET_TARGET_PROPERTIES(couch_dbdump PROPERTIES COMPILE_FLAGS "-DLIBCOUCHSTORE_NO_VISIBILITY=1")
TARGET_LINK_LIBRARIES(couch_dbdump ${COUCHSTORE_LIBRARIES} xattr)

ADD_EXECUTABLE(couch_dbck src/dbck.cc)
TARGET_LINK_LIBRARIES(couch_dbck couchstore platform)

ADD_EXECUTABLE(couch_dbinfo src/dbinfo.cc)
TARGET_LINK_LIBRARIES(couch_dbinfo couchstore platform)

ADD_EXECUTABLE(couch_compact src/compactor.cc)
TARGET_LINK_LIBRARIES(couch_compact couchstore)

ADD_EXECUTABLE(couch_view_file_merger src/views/bin/couch_view_file_merger.cc src/views/bin/util.c)
TARGET_LINK_LIBRARIES(couch_view_file_merger couchstore)

ADD_EXECUTABLE(couch_view_index_builder src/views/bin/couch_view_index_builder.cc src/views/bin/util.c)
TARGET_LINK_LIBRARIES(couch_view_index_builder couchstore)

ADD_EXECUTABLE(couch_view_group_cleanup src/views/bin/couch_view_group_cleanup.cc src/views/bin/util.c)
TARGET_LINK_LIBRARIES(couch_view_group_cleanup couchstore)

ADD_EXECUTABLE(couch_view_index_updater src/views/bin/couch_view_index_updater.cc src/views/bin/util.c)
TARGET_LINK_LIBRARIES(couch_view_index_updater couchstore)

ADD_EXECUTABLE(couch_view_group_compactor src/views/bin/couch_view_group_compactor.cc src/views/bin/util.c)
TARGET_LINK_LIBRARIES(couch_view_group_compactor couchstore)

ADD_EXECUTABLE(couch_create src/couch_create.cc src/crc32.cc)
TARGET_LINK_LIBRARIES(couch_create couchstore platform)


IF (INSTALL_HEADER_FILES)
   INSTALL(FILES
           include/libcouchstore/couch_db.h
           include/libcouchstore/couch_index.h
           include/libcouchstore/couch_common.h
           include/libcouchstore/error.h
           include/libcouchstore/file_ops.h
           include/libcouchstore/visibility.h
           DESTINATION include/libcouchstore)
ENDIF(INSTALL_HEADER_FILES)

INSTALL(TARGETS couchstore
        RUNTIME DESTINATION bin
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib)

IF (APPLE)
    SET_TARGET_PROPERTIES(couchstore
                          PROPERTIES
                          INSTALL_RPATH "@loader_path")
ENDIF (APPLE)

INSTALL(TARGETS couch_dbdump
                couch_dbinfo
                couch_dbck
                couch_compact
                couch_view_file_merger
                couch_view_index_builder
                couch_view_group_cleanup
                couch_view_index_updater
                couch_view_group_compactor
        RUNTIME DESTINATION bin)

INSTALL(FILES
        python/couchstore.py
        DESTINATION lib/python)

CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/config.cmake.h.in
               ${CMAKE_CURRENT_BINARY_DIR}/config.h)

# Tests:

IF (LUA_FOUND)
   ADD_EXECUTABLE(couchscript src/couchscript.cc)
   SET_TARGET_PROPERTIES(couchscript PROPERTIES COMPILE_FLAGS
                         -I${LUA_INCLUDE_DIR})
   TARGET_LINK_LIBRARIES(couchscript couchstore ${LUA_LIBRARIES})

   ADD_TEST(couchstore-localdoc
            couchscript ${CMAKE_CURRENT_SOURCE_DIR}/tests/localdoc.lua)
   ADD_TEST(couchstore-corrupt
            couchscript ${CMAKE_CURRENT_SOURCE_DIR}/tests/corrupt.lua)
   ADD_TEST(couchstore-bulk
            couchscript ${CMAKE_CURRENT_SOURCE_DIR}/tests/bulk.lua)
   ADD_TEST(couchstore-changes-since-filter
           couchscript ${CMAKE_CURRENT_SOURCE_DIR}/tests/changessincefilter.lua)
   ADD_TEST(couchstore-compact
            couchscript ${CMAKE_CURRENT_SOURCE_DIR}/tests/compact.lua)
   ADD_TEST(couchstore-dropdel
            couchscript ${CMAKE_CURRENT_SOURCE_DIR}/tests/dropdel.lua)
   ADD_TEST(couchstore-largefile
            couchscript ${CMAKE_CURRENT_SOURCE_DIR}/tests/largefile.lua)
   ADD_TEST(couchstore-large
            couchscript ${CMAKE_CURRENT_SOURCE_DIR}/tests/large.lua)
ENDIF(LUA_FOUND)

MACRO (M_ADD_PYTHON_TEST name pyfile)
  ADD_TEST(${name} python ${pyfile})
  SET_PROPERTY(TEST ${name} PROPERTY ENVIRONMENT
    "PYTHONPATH=${CMAKE_CURRENT_SOURCE_DIR}/python"
    "LD_LIBRARY_PATH=${CMAKE_CURRENT_BINARY_DIR}")
ENDMACRO()

M_ADD_PYTHON_TEST(couchstore-purge ${CMAKE_CURRENT_SOURCE_DIR}/tests/purge.py)
M_ADD_PYTHON_TEST(couchstore-rewind ${CMAKE_CURRENT_SOURCE_DIR}/tests/rewind.py)
M_ADD_PYTHON_TEST(couchstore-changecount ${CMAKE_CURRENT_SOURCE_DIR}/tests/changecount.py)

MACRO (M_MAKE_LEGACY_TEST name)
    ADD_EXECUTABLE(${name} ${ARGN})
    SET_TARGET_PROPERTIES(${name} PROPERTIES
            COMPILE_FLAGS "-DLIBCOUCHSTORE_NO_VISIBILITY=1 -DTESTAPP=1")
    TARGET_LINK_LIBRARIES(${name} couchstore)
ENDMACRO()

M_MAKE_LEGACY_TEST(couchstore_file-deduper-test
        src/file_merger.cc
        tests/file_deduper_tests.c)

M_MAKE_LEGACY_TEST(couchstore_file-merger-test
        src/file_merger.cc
        tests/file_merger_tests.c)

M_MAKE_LEGACY_TEST(couchstore_file-sorter-test
        src/file_merger.cc
        src/file_name_utils.c
        src/file_sorter.cc
        src/quicksort.c
        tests/file_sorter_tests.c)

SET(MAP_REDUCE_SOURCES
        src/views/mapreduce/mapreduce.cc
        src/views/mapreduce/mapreduce_c.cc)

M_MAKE_LEGACY_TEST(couchstore_mapreduce-builtin-test
        ${MAP_REDUCE_SOURCES}
        tests/mapreduce/builtin.c)

M_MAKE_LEGACY_TEST(couchstore_mapreduce-map-test
        ${MAP_REDUCE_SOURCES}
        tests/mapreduce/map.c)

M_MAKE_LEGACY_TEST(couchstore_mapreduce-reduce-test
        ${MAP_REDUCE_SOURCES}
        tests/mapreduce/reduce.c)

ADD_EXECUTABLE(couchstore_testapp
               tests/testapp.c
               tests/views/tests.cc
               tests/views/collate_json_test.cc
               tests/views/index_headers.cc
               tests/views/bitmaps.cc
               tests/views/sorted_lists.cc
               tests/views/reductions.cc
               tests/views/keys.cc
               tests/views/values.cc
               tests/views/reducers.cc
               tests/views/cleanup.cc
               tests/views/spatial.cc
               tests/btree_purge/purge_tests.h
               tests/btree_purge/tests.cc
               tests/btree_purge/purge.cc
               ${COUCHSTORE_SOURCES})
SET_TARGET_PROPERTIES(couchstore_testapp PROPERTIES
        COMPILE_FLAGS "-DLIBCOUCHSTORE_NO_VISIBILITY=1 -DTESTAPP=1")
TARGET_LINK_LIBRARIES(couchstore_testapp ${COUCHSTORE_LIBRARIES})

ADD_EXECUTABLE(couchstore_gtest
               tests/couchstoretest.cc
               tests/documents.cc
               tests/gtest_tests.cc
               tests/test_fileops.cc
               src/node_types.cc
               src/crc32.cc
               ${COUCHSTORE_FILE_OPS})
SET_TARGET_PROPERTIES(couchstore_gtest PROPERTIES
                      COMPILE_FLAGS "-DLIBCOUCHSTORE_NO_VISIBILITY=1 -DTESTAPP=1")
TARGET_INCLUDE_DIRECTORIES(couchstore_gtest PRIVATE ${COUCHSTORE_GTEST_INCLUDES})
TARGET_LINK_LIBRARIES(couchstore_gtest couchstore ${COUCHSTORE_GTEST_LIBRARIES})

ADD_EXECUTABLE(couchstore_internal_gtest
        tests/couchstoretest.cc
        tests/documents.cc
        tests/gtest_internal_tests.cc
        tests/test_fileops.cc
        ${COUCHSTORE_SOURCES}
        )
SET_TARGET_PROPERTIES(couchstore_internal_gtest PROPERTIES
        COMPILE_FLAGS "-DLIBCOUCHSTORE_NO_VISIBILITY=1 -DTESTAPP=1")
TARGET_INCLUDE_DIRECTORIES(couchstore_internal_gtest PRIVATE ${COUCHSTORE_GTEST_INCLUDES})
TARGET_LINK_LIBRARIES(couchstore_internal_gtest
        ${COUCHSTORE_GTEST_LIBRARIES}
        ${COUCHSTORE_LIBRARIES})

# This is an object library and can be used for verifying
# FileOpsInterface implementations that wrap other FileOps
# propogate errors correctly.
#
# Example usage can be found in tests/wrapped_fileops_test.cc
ADD_LIBRARY(couchstore_wrapped_fileops_test_framework OBJECT
        tests/test_fileops.cc
        ${COUCHSTORE_FILE_OPS})
SET_TARGET_PROPERTIES(couchstore_wrapped_fileops_test_framework PROPERTIES
        COMPILE_FLAGS "-DLIBCOUCHSTORE_NO_VISIBILITY=1 -DTESTAPP=1")
TARGET_INCLUDE_DIRECTORIES(couchstore_wrapped_fileops_test_framework
        PRIVATE
        ${COUCHSTORE_GTEST_INCLUDES})

ADD_EXECUTABLE(couchstore_wrapped_fileops_test
               src/crc32.cc
               src/iobuffer.cc
               tests/wrapped_fileops_test.cc
               $<TARGET_OBJECTS:couchstore_wrapped_fileops_test_framework>
               )
SET_TARGET_PROPERTIES(couchstore_wrapped_fileops_test PROPERTIES
        COMPILE_FLAGS "-DLIBCOUCHSTORE_NO_VISIBILITY=1 -DTESTAPP=1")
TARGET_LINK_LIBRARIES(couchstore_wrapped_fileops_test ${COUCHSTORE_GTEST_LIBRARIES} platform)

ADD_LIBRARY(couchstore_test_fileops OBJECT
        tests/test_fileops.cc)
TARGET_INCLUDE_DIRECTORIES(couchstore_test_fileops
        PRIVATE
        ${COUCHSTORE_GTEST_INCLUDES})

ADD_TEST(couchstore-file-deduper-test couchstore_file-deduper-test)
ADD_TEST(couchstore-file-merge-test couchstore_file-merger-test)
ADD_TEST(couchstore-file-sorter-test couchstore_file-sorter-test)
ADD_TEST(couchstore-gtest couchstore_gtest)
ADD_TEST(couchstore-internal-gtest couchstore_internal_gtest)
ADD_TEST(couchstore-mapreduce-builtin-test couchstore_mapreduce-builtin-test)
ADD_TEST(couchstore-mapreduce-map-test couchstore_mapreduce-map-test)
ADD_TEST(couchstore-mapreduce-reduce-test couchstore_mapreduce-reduce-test)
ADD_TEST(couchstore-testapp couchstore_testapp)
ADD_TEST(couchstore-wrapped_fileops-test couchstore_wrapped_fileops_test)



ADD_SUBDIRECTORY(programs)

ENABLE_CODE_COVERAGE_REPORT()
