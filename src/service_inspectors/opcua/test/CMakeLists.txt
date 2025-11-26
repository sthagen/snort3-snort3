add_cpputest( opcua_splitter_test
    SOURCES ../opcua_splitter.cc
)

add_cpputest( opcua_decode_test
    SOURCES ../opcua_decode.cc
)

add_cpputest( ips_opcua_msg_service_test )
add_cpputest( ips_opcua_msg_type_test )
add_cpputest( ips_opcua_node_id_test )
add_cpputest( ips_opcua_node_namespace_index_test )