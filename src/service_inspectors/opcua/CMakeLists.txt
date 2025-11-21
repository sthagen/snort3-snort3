add_subdirectory(test)

set( FILE_LIST
    opcua.cc
    opcua_session.h
    opcua_decode.cc
    opcua_decode.h
    opcua_module.cc
    opcua_module.h
    opcua_msg_service.h
    opcua_splitter.cc
    opcua_splitter.h
    ips_opcua_msg_type.cc
    ips_opcua_msg_service.cc
    ips_opcua_node_id.cc
    ips_opcua_node_namespace_index.cc
)

if (STATIC_INSPECTORS)
    add_library(opcua OBJECT ${FILE_LIST})

else (STATIC_INSPECTORS)
    add_dynamic_module(opcua inspectors ${FILE_LIST})

endif (STATIC_INSPECTORS)

