ADD_EXECUTABLE(dbdiff dbdiff.cc)
TARGET_LINK_LIBRARIES(dbdiff couchstore_views)

INSTALL(TARGETS dbdiff
        RUNTIME DESTINATION bin)
