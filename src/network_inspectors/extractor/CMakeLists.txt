set ( INCLUDES
    extractor_enums.h
)

install ( FILES ${INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/network_inspectors/extractor"
)

set( FILE_LIST
    extractor.cc
    extractor.h
    extractor_conn.cc
    extractor_csv_logger.cc
    extractor_csv_logger.h
    extractor_detection.cc
    extractor_detection.h
    extractor_dns.cc
    extractor_enums.h
    extractor_flow_data.cc
    extractor_flow_data.h
    extractor_ftp.cc
    extractor_http.cc
    extractor_json_logger.cc
    extractor_json_logger.h
    extractor_logger.cc
    extractor_logger.h
    extractor_null_conn.h
    extractor_service.cc
    extractor_service.h
    extractors.cc
    extractors.h
)

add_library(extractor OBJECT ${FILE_LIST})

add_subdirectory(test)
