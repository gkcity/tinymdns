#-----------------------------------------------------------------------------
#
# mdns
#
#-----------------------------------------------------------------------------


SET(Mdns_Header
        MdnsConstant.h
        MdnsHandler.h
        MdnsHandlerContext.h
        ServiceObserver.h
        ServiceListener.h
        )

SET(Mdns_Source
        MdnsHandler.c
        MdnsHandlerContext.c
        ServiceObserver.c
        )

#----------------------------------------------------------------------------
# source
#----------------------------------------------------------------------------
SET(SRC
        ${Mdns_Header}
        ${Mdns_Source}
        )

#----------------------------------------------------------------------------
# static library
#----------------------------------------------------------------------------
ADD_LIBRARY(mdns_static STATIC ${SRC})
SET_TARGET_PROPERTIES(mdns_static PROPERTIES OUTPUT_NAME "mdns_static")
SET_TARGET_PROPERTIES(mdns_static PROPERTIES LINKER_LANGUAGE C)

#----------------------------------------------------------------------------
# test
#----------------------------------------------------------------------------
ADD_SUBDIRECTORY(test)
