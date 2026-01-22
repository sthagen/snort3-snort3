set (FLOW_INCLUDES
    deferred_trust.h
    dump_flows.h
    dump_flows_descriptor.h
    dump_flows_serializer.h
    expect_flow.h
    flow.h
    flow_data.h
    flow_key.h
    flow_stash.h
    ha.h
    prune_stats.h
    session.h
    stream_flow.h
)

add_library (flow OBJECT
    ${FLOW_INCLUDES}
    deferred_trust.cc
    dump_flows.cc
    dump_flows_serializer.cc
    expect_cache.cc
    flow.cc
    flow_cache.cc
    expect_cache.h
    flow_cache.h
    flow_config.h
    flow_control.cc
    flow_control.h
    flow_data.cc
    flow_key.cc
    flow_stash.cc
    flow_stash.h
    flow_uni_list.h
    ha.cc
    ha_module.cc
    ha_module.h
    prune_stats.h
)

install(FILES ${FLOW_INCLUDES}
    DESTINATION ${INCLUDE_INSTALL_PATH}/flow
)

add_subdirectory(test)
