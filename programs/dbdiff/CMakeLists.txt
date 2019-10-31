ADD_EXECUTABLE(dbdiff dbdiff.cc)
TARGET_LINK_LIBRARIES(dbdiff couchstore couchstore_views)

INSTALL(TARGETS dbdiff
        RUNTIME DESTINATION bin)
