#-----------------------------------------------------------------------------
#
# example
#
#-----------------------------------------------------------------------------
ADD_EXECUTABLE(example_registry example_registry.c)
TARGET_LINK_LIBRARIES(example_registry
        mdns_registry_static
        netty_static
        tiny_string_util_static
        tiny_container_static
        tiny_log_static
        tiny_portable_static
        tiny_base_static
        ${OS_LIB}
        )

ADD_EXECUTABLE(example_discovery example_discovery.c)
TARGET_LINK_LIBRARIES(example_discovery
        mdns_registry_static
        netty_static
        tiny_string_util_static
        tiny_container_static
        tiny_log_static
        tiny_portable_static
        tiny_base_static
        ${OS_LIB}
        )