PROJECT(Couchstore)
CMAKE_MINIMUM_REQUIRED(VERSION 3.12)

INCLUDE(CheckFunctionExists)
INCLUDE(CheckIncludeFile)
INCLUDE(CheckIncludeFiles)
INCLUDE(CheckLibraryExists)
INCLUDE(CheckSymbolExists)
INCLUDE(CheckTypeSize)
INCLUDE(CTest)
INCLUDE(GenerateExportHeader)

INCLUDE_DIRECTORIES(BEFORE ${CMAKE_INSTALL_PREFIX}/include
                           ${CMAKE_CURRENT_SOURCE_DIR}/include
                           ${CMAKE_CURRENT_SOURCE_DIR}/src
                           ${CMAKE_CURRENT_BINARY_DIR}
                           ${CMAKE_CURRENT_SOURCE_DIR}
                           ${BOOST_INCLUDE_DIR}
                           ${Platform_SOURCE_DIR}/include
                           ${phosphor_SOURCE_DIR}/include)

INCLUDE_DIRECTORIES(AFTER ${gsl_lite_SOURCE_DIR}/include)

if (LUA_FOUND)
   include_directories(AFTER SYSTEM {LUA_INCLUDE_DIR})
endif (LUA_FOUND)

INCLUDE_DIRECTORIES(AFTER
                    ${KVEngineAPI_SOURCE_DIR}
                    ${KVEngineAPI_BINARY_DIR})

INCLUDE_DIRECTORIES(AFTER SYSTEM ${ICU_INCLUDE_DIR}
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

# Disabling Undefined sanitize checks for the file mapreduce.cc since v8::Platform was wrapped in unique_ptr
# and UBSan was unable to lookup symbols for it, thus leading to undefined-behaviour errors
IF(DEFINED UNDEFINED_SANITIZER_FLAG_DISABLE)
  SEPARATE_ARGUMENTS(ubsan_disable_list UNIX_COMMAND ${UNDEFINED_SANITIZER_FLAG_DISABLE})
  SET_PROPERTY(SOURCE src/views/mapreduce/mapreduce.cc
    APPEND
    PROPERTY COMPILE_OPTIONS ${ubsan_disable_list})
ENDIF()

# Create two object libraries, one for the core couchstore code
ADD_LIBRARY(couchstore_objs OBJECT
        src/arena.cc
        src/bitfield.cc
        src/btree_modify.cc
        src/btree_read.cc
        src/couch_cxx_util.cc
        src/couch_db.cc
        src/couch_file_read.cc
        src/couch_file_write.cc
        src/couch_latency.cc
        src/couch_save.cc
        src/crc32.cc
        src/db_compact.cc
        src/file_merger.cc
        src/file_sorter.cc
        src/iobuffer.cc
        src/llmsort.cc
        src/mergesort.cc
        src/node_types.cc
        src/quicksort.c
        src/reduces.cc
        src/strerror.cc
        src/tree_writer.cc
        src/util.cc
        ${COUCHSTORE_FILE_OPS})
TARGET_COMPILE_DEFINITIONS(couchstore_objs PUBLIC -Dcouchstore_EXPORTS)
TARGET_LINK_LIBRARIES(couchstore_objs PUBLIC Folly::headers nlohmann_json::nlohmann_json)
SET_PROPERTY(TARGET couchstore_objs PROPERTY POSITION_INDEPENDENT_CODE 1)
cb_enable_unity_build(couchstore_objs)

# second object library is for the view specific code
ADD_LIBRARY(couchstore_view_objs OBJECT
        src/views/bitmap.cc
        src/views/collate_json.cc
        src/views/encoding.cc
        src/views/file_merger.cc
        src/views/file_sorter.cc
        src/views/index_header.cc
        src/views/keys.cc
        src/views/mapreduce/mapreduce.cc
        src/views/mapreduce/mapreduce_c.cc
        src/views/reducers.cc
        src/views/reductions.cc
        src/views/sorted_list.cc
        src/views/spatial.cc
        src/views/spatial_modify.cc
        src/views/util.cc
        src/views/values.cc
        src/views/view_group.cc
        src/views/purgers.cc
        src/views/compaction.cc
        $<TARGET_OBJECTS:couchstore_objs>)
TARGET_COMPILE_DEFINITIONS(couchstore_view_objs PUBLIC -Dcouchstore_EXPORTS)
TARGET_LINK_LIBRARIES(couchstore_view_objs PUBLIC Folly::headers)
SET_PROPERTY(TARGET couchstore_view_objs PROPERTY POSITION_INDEPENDENT_CODE 1)
cb_enable_unity_build(couchstore_view_objs)

# libcouchstore, core couchstore library
ADD_LIBRARY(couchstore SHARED $<TARGET_OBJECTS:couchstore_objs>)
SET(COUCHSTORE_LIBS cbcompress platform phosphor)
TARGET_LINK_LIBRARIES(couchstore ${COUCHSTORE_LIBS})

GENERATE_EXPORT_HEADER(couchstore
                       EXPORT_MACRO_NAME LIBCOUCHSTORE_API
                       EXPORT_FILE_NAME ${CMAKE_CURRENT_BINARY_DIR}/include/libcouchstore/visibility.h
                       NO_EXPORT_MACRO_NAME STATIC
                       STATIC_DEFINE LIBCOUCHSTORE_NO_VISIBILITY)

ADD_LIBRARY(couchstore_static STATIC $<TARGET_OBJECTS:couchstore_objs>)
TARGET_LINK_LIBRARIES(couchstore_static ${COUCHSTORE_LIBS})
target_compile_definitions(couchstore_static PUBLIC LIBCOUCHSTORE_NO_VISIBILITY)

TARGET_INCLUDE_DIRECTORIES(couchstore_objs PUBLIC ${CMAKE_CURRENT_BINARY_DIR}/include)
TARGET_INCLUDE_DIRECTORIES(couchstore_view_objs PUBLIC ${CMAKE_CURRENT_BINARY_DIR}/include)
TARGET_INCLUDE_DIRECTORIES(couchstore PUBLIC ${CMAKE_CURRENT_BINARY_DIR}/include)
TARGET_INCLUDE_DIRECTORIES(couchstore_static PUBLIC ${CMAKE_CURRENT_BINARY_DIR}/include)

# libcouchstore_views - core couchstore library + view code and is dependent on
# v8 and icu libraries
ADD_LIBRARY(couchstore_views SHARED
            $<TARGET_OBJECTS:couchstore_objs>
            $<TARGET_OBJECTS:couchstore_view_objs>)
SET(COUCHSTORE_VIEW_LIBS ${COUCHSTORE_LIBS} ${V8_LIBRARIES} ${ICU_LIBRARIES})
TARGET_LINK_LIBRARIES(couchstore_views ${COUCHSTORE_VIEW_LIBS})
TARGET_INCLUDE_DIRECTORIES(couchstore_views PUBLIC ${CMAKE_CURRENT_BINARY_DIR}/include)

ADD_EXECUTABLE(couch_dbdump
               src/dbdump.cc
               src/tracking_file_ops.cc
               $<TARGET_OBJECTS:couchstore_objs>
               $<TARGET_OBJECTS:couchstore_view_objs>)

SET_TARGET_PROPERTIES(couch_dbdump PROPERTIES COMPILE_FLAGS "-DLIBCOUCHSTORE_NO_VISIBILITY=1")
TARGET_INCLUDE_DIRECTORIES(couch_dbdump
                           PRIVATE
                           ${CMAKE_CURRENT_BINARY_DIR}/include
                           ${FLATBUFFERS_INCLUDE_DIR})

TARGET_LINK_LIBRARIES(couch_dbdump
                      mcbp
                      xattr
                      ep-engine_collections
        ep-engine_storage_common
                      ${COUCHSTORE_VIEW_LIBS})

ADD_EXECUTABLE(couch_dbck src/dbck.cc)
TARGET_LINK_LIBRARIES(couch_dbck couchstore platform)

ADD_EXECUTABLE(couch_dbinfo src/dbinfo.cc)
TARGET_LINK_LIBRARIES(couch_dbinfo couchstore mcd_time platform)

ADD_EXECUTABLE(couch_compact src/compactor.cc)
TARGET_LINK_LIBRARIES(couch_compact couchstore platform)

ADD_EXECUTABLE(couch_view_file_merger src/views/bin/couch_view_file_merger.cc src/views/bin/util.cc)
TARGET_LINK_LIBRARIES(couch_view_file_merger couchstore_views platform)

ADD_EXECUTABLE(couch_view_index_builder src/views/bin/couch_view_index_builder.cc src/views/bin/util.cc)
TARGET_LINK_LIBRARIES(couch_view_index_builder couchstore_views platform)
TARGET_INCLUDE_DIRECTORIES(couch_view_index_builder PUBLIC ${CMAKE_CURRENT_BINARY_DIR}/include)

ADD_EXECUTABLE(couch_view_group_cleanup src/views/bin/couch_view_group_cleanup.cc src/views/bin/util.cc)
TARGET_LINK_LIBRARIES(couch_view_group_cleanup couchstore_views platform)
TARGET_INCLUDE_DIRECTORIES(couch_view_group_cleanup PUBLIC ${CMAKE_CURRENT_BINARY_DIR}/include)

ADD_EXECUTABLE(couch_view_index_updater src/views/bin/couch_view_index_updater.cc src/views/bin/util.cc)
TARGET_LINK_LIBRARIES(couch_view_index_updater couchstore_views platform)
TARGET_INCLUDE_DIRECTORIES(couch_view_index_updater PUBLIC ${CMAKE_CURRENT_BINARY_DIR}/include)

ADD_EXECUTABLE(couch_view_group_compactor src/views/bin/couch_view_group_compactor.cc src/views/bin/util.cc)
TARGET_LINK_LIBRARIES(couch_view_group_compactor couchstore_views platform)
TARGET_INCLUDE_DIRECTORIES(couch_view_group_compactor PUBLIC ${CMAKE_CURRENT_BINARY_DIR}/include)

cb_add_test_executable(couch_create src/couch_create.cc src/crc32.cc)
TARGET_LINK_LIBRARIES(couch_create couchstore platform)
TARGET_INCLUDE_DIRECTORIES(couch_create PUBLIC ${CMAKE_CURRENT_BINARY_DIR}/include)

IF (INSTALL_HEADER_FILES)
   INSTALL(FILES
           include/libcouchstore/couch_db.h
           include/libcouchstore/couch_common.h
           include/libcouchstore/error.h
           include/libcouchstore/file_ops.h
           include/libcouchstore/visibility.h
           DESTINATION include/libcouchstore)
ENDIF(INSTALL_HEADER_FILES)

INSTALL(TARGETS couchstore
                couchstore_views
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

CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/config.cmake.h.in
               ${CMAKE_CURRENT_BINARY_DIR}/couchstore_config.h)

# Tests:
IF (LUA_FOUND)
    cb_add_test_executable(couchscript src/couchscript.cc)
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
ENDIF (LUA_FOUND)

MACRO(M_ADD_PYTHON_TEST name pyfile)
    ADD_TEST(${name} python3 ${pyfile})
    SET_PROPERTY(TEST ${name} PROPERTY ENVIRONMENT
                 "PYTHONPATH=${CMAKE_CURRENT_SOURCE_DIR}/python"
                 "LD_LIBRARY_PATH=${CMAKE_CURRENT_BINARY_DIR}")
ENDMACRO()

M_ADD_PYTHON_TEST(couchstore-purge ${CMAKE_CURRENT_SOURCE_DIR}/tests/purge.py)
M_ADD_PYTHON_TEST(couchstore-rewind ${CMAKE_CURRENT_SOURCE_DIR}/tests/rewind.py)
M_ADD_PYTHON_TEST(couchstore-changecount ${CMAKE_CURRENT_SOURCE_DIR}/tests/changecount.py)

MACRO(M_MAKE_LEGACY_TEST name)
    cb_add_test_executable(${name} ${ARGN})
    SET_TARGET_PROPERTIES(${name} PROPERTIES
                          COMPILE_FLAGS "-DLIBCOUCHSTORE_NO_VISIBILITY=1")
    TARGET_LINK_LIBRARIES(${name} couchstore_views platform)
    TARGET_INCLUDE_DIRECTORIES(${name} PUBLIC ${CMAKE_CURRENT_BINARY_DIR}/include)
ENDMACRO()

M_MAKE_LEGACY_TEST(couchstore_file-deduper-test
                   src/file_merger.cc
                   tests/file_deduper_tests.cc)

M_MAKE_LEGACY_TEST(couchstore_file-merger-test
                   src/file_merger.cc
                   tests/file_merger_tests.cc)

M_MAKE_LEGACY_TEST(couchstore_file-sorter-test
                   src/file_merger.cc
                   src/file_sorter.cc
                   src/quicksort.c
                   tests/file_sorter_tests.cc)

SET(MAP_REDUCE_SOURCES
    src/views/mapreduce/mapreduce.cc
    src/views/mapreduce/mapreduce_c.cc)

M_MAKE_LEGACY_TEST(couchstore_mapreduce-builtin-test
                   ${MAP_REDUCE_SOURCES}
                   tests/mapreduce/builtin.cc)

M_MAKE_LEGACY_TEST(couchstore_mapreduce-map-test
                   ${MAP_REDUCE_SOURCES}
                   tests/mapreduce/map.cc)

M_MAKE_LEGACY_TEST(couchstore_mapreduce-reduce-test
                   ${MAP_REDUCE_SOURCES}
                   tests/mapreduce/reduce.cc)

cb_add_test_executable(couchstore_testapp
               tests/testapp.cc
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
               $<TARGET_OBJECTS:couchstore_objs>
               $<TARGET_OBJECTS:couchstore_view_objs>)
SET_TARGET_PROPERTIES(couchstore_testapp PROPERTIES
                     COMPILE_FLAGS "-DLIBCOUCHSTORE_NO_VISIBILITY=1")
TARGET_INCLUDE_DIRECTORIES(couchstore_testapp
                           PRIVATE
                           ${CMAKE_CURRENT_BINARY_DIR}/include)
TARGET_LINK_LIBRARIES(couchstore_testapp ${COUCHSTORE_VIEW_LIBS})
cb_enable_unity_build(couchstore_testapp)
SET(COUCHSTORE_GTEST_LIBRARIES gtest gtest_main gmock phosphor)
SET(COUCHSTORE_GTEST_INCLUDES ${gtest_SOURCE_DIR}/include ${gmock_SOURCE_DIR}/include)
cb_add_test_executable(couchstore_gtest
               tests/couchstoretest.cc
               tests/documents.cc
               tests/gtest_tests.cc
               tests/test_compact.cc
               tests/test_cxx_util.cc
               tests/test_fileops.cc
               tests/test_seek.cc
               src/node_types.cc
               src/crc32.cc
               )
SET_TARGET_PROPERTIES(couchstore_gtest PROPERTIES
                      COMPILE_FLAGS "-DLIBCOUCHSTORE_NO_VISIBILITY=1")
TARGET_INCLUDE_DIRECTORIES(couchstore_gtest PRIVATE ${COUCHSTORE_GTEST_INCLUDES})
TARGET_LINK_LIBRARIES(couchstore_gtest couchstore platform ${COUCHSTORE_GTEST_LIBRARIES})
cb_enable_unity_build(couchstore_gtest)

cb_add_test_executable(couchstore_internal_gtest
               tests/couchstoretest.cc
               tests/documents.cc
               tests/gtest_internal_tests.cc
               tests/test_fileops.cc
               $<TARGET_OBJECTS:couchstore_objs>)
SET_TARGET_PROPERTIES(couchstore_internal_gtest PROPERTIES
                      COMPILE_FLAGS "-DLIBCOUCHSTORE_NO_VISIBILITY=1")
TARGET_INCLUDE_DIRECTORIES(couchstore_internal_gtest
                           PRIVATE
                           ${CMAKE_CURRENT_BINARY_DIR}/include)

TARGET_LINK_LIBRARIES(couchstore_internal_gtest
                      ${COUCHSTORE_GTEST_LIBRARIES}
                      ${COUCHSTORE_LIBS})

# This is an object library and can be used for verifying
# FileOpsInterface implementations that wrap other FileOps
# propogate errors correctly.
#
# Example usage can be found in tests/wrapped_fileops_test.cc
ADD_LIBRARY(couchstore_wrapped_fileops_test_framework OBJECT
            tests/test_fileops.cc
            ${COUCHSTORE_FILE_OPS})
SET_TARGET_PROPERTIES(couchstore_wrapped_fileops_test_framework PROPERTIES
                      COMPILE_FLAGS "-DLIBCOUCHSTORE_NO_VISIBILITY=1")
TARGET_INCLUDE_DIRECTORIES(couchstore_wrapped_fileops_test_framework
                           PRIVATE
                           ${COUCHSTORE_GTEST_INCLUDES}
                           ${CMAKE_CURRENT_BINARY_DIR}/include)
TARGET_LINK_LIBRARIES(couchstore_wrapped_fileops_test_framework platform)

cb_add_test_executable(couchstore_wrapped_fileops_test
               src/iobuffer.cc
               src/crc32.cc
               tests/wrapped_fileops_test.cc
               $<TARGET_OBJECTS:couchstore_wrapped_fileops_test_framework>)
SET_TARGET_PROPERTIES(couchstore_wrapped_fileops_test PROPERTIES
                      COMPILE_FLAGS "-DLIBCOUCHSTORE_NO_VISIBILITY=1")
TARGET_INCLUDE_DIRECTORIES(couchstore_wrapped_fileops_test
                           PRIVATE
                           ${CMAKE_CURRENT_BINARY_DIR}/include)
TARGET_LINK_LIBRARIES(couchstore_wrapped_fileops_test ${COUCHSTORE_GTEST_LIBRARIES} platform)

ADD_LIBRARY(couchstore_test_fileops OBJECT
            tests/test_fileops.cc)
TARGET_INCLUDE_DIRECTORIES(couchstore_test_fileops
                           PRIVATE
                           ${COUCHSTORE_GTEST_INCLUDES}
                           ${CMAKE_CURRENT_BINARY_DIR}/include)
TARGET_LINK_LIBRARIES(couchstore_test_fileops platform)

ADD_TEST(couchstore-file-deduper-test couchstore_file-deduper-test)
ADD_TEST(couchstore-file-merge-test couchstore_file-merger-test)
ADD_TEST(couchstore-file-sorter-test couchstore_file-sorter-test)
ADD_TEST(couchstore-gtest couchstore_gtest)
ADD_TEST(couchstore-internal-gtest couchstore_internal_gtest)
ADD_TEST(NAME couchstore-mapreduce-builtin-test COMMAND couchstore_mapreduce-builtin-test ${CMAKE_INSTALL_PREFIX}/bin/)
ADD_TEST(NAME couchstore-mapreduce-map-test COMMAND couchstore_mapreduce-map-test ${CMAKE_INSTALL_PREFIX}/bin/)
ADD_TEST(NAME couchstore-mapreduce-reduce-test COMMAND couchstore_mapreduce-reduce-test ${CMAKE_INSTALL_PREFIX}/bin/)
ADD_TEST(NAME couchstore-testapp COMMAND couchstore_testapp ${CMAKE_INSTALL_PREFIX}/bin/)
ADD_TEST(couchstore-wrapped_fileops-test couchstore_wrapped_fileops_test)

ADD_SUBDIRECTORY(programs)

ENABLE_CODE_COVERAGE_REPORT()
