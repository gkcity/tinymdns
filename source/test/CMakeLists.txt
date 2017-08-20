#-----------------------------------------------------------------------------
#
# example
#
#-----------------------------------------------------------------------------
ADD_EXECUTABLE(example_registry example_registry.c)
TARGET_LINK_LIBRARIES(example_registry mdns_static ${DEPENDENCE_LIB})

ADD_EXECUTABLE(example_discovery example_discovery.c)
TARGET_LINK_LIBRARIES(example_discovery mdns_static ${DEPENDENCE_LIB})