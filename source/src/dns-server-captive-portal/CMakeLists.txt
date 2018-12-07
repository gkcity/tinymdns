#-----------------------------------------------------------------------------
#
# dns-server-captive-portal
#
#-----------------------------------------------------------------------------


SET(Dns_Header
        DnsConstant.h
        DnsServerHandler.h
        DnsServerHandlerContext.h
        )

SET(Dns_Source
        DnsServerHandler.c
        DnsServerHandlerContext.c
        )

#----------------------------------------------------------------------------
# source
#----------------------------------------------------------------------------
SET(SRC
        ${Dns_Header}
        ${Dns_Source}
        )

#----------------------------------------------------------------------------
# static library
#----------------------------------------------------------------------------
ADD_LIBRARY(dns_static STATIC ${SRC})
SET_TARGET_PROPERTIES(dns_static PROPERTIES OUTPUT_NAME "dns_static")
SET_TARGET_PROPERTIES(dns_static PROPERTIES LINKER_LANGUAGE C)