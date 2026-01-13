if ( HAVE_SAFEC )
    LIST(APPEND EXTERNAL_LIBRARIES ${SAFEC_LIBRARIES})
endif ()

add_cpputest( file_mime_log_test
    SOURCES
        ../file_mime_log.cc
        file_mime_log_test.cc
    LIBS
        ${EXTERNAL_LIBRARIES}
)
