
add_cpputest( data_bus_test
    SOURCES ../data_bus.cc
)

add_cpputest( mp_data_bus_test
    SOURCES ../mp_data_bus.cc
)

# libapi_def.a is actually a text file with the preprocessed header source

if ( ENABLE_UNIT_TESTS )
    add_library(api_def api_def.cc)
    target_compile_options(api_def PRIVATE -E)
    install(TARGETS api_def)
endif ()

SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")
