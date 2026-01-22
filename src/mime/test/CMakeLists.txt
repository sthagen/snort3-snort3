if ( HAVE_SAFEC )
    SET(EXTRA_LIBRARIES ${SAFEC_LIBRARIES})
endif ()

add_cpputest( file_mime_log_test
    SOURCES
        ../file_mime_log.cc
        file_mime_log_test.cc
    LIBS
        ${EXTRA_LIBRARIES}
)
