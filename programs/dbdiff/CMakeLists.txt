ADD_EXECUTABLE(dbdiff dbdiff.cc)
TARGET_LINK_LIBRARIES(dbdiff couchstore_views couchstore_program_utilities)

INSTALL(TARGETS dbdiff
        RUNTIME DESTINATION bin)
