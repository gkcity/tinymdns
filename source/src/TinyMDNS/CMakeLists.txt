#-----------------------------------------------------------------------------
#
# TinyMdns
#
#-----------------------------------------------------------------------------


SET(Mdns_Header
        mdns_api.h
        MdnsConstant.h
        ServiceInfo.h
        MdnsHandler.h
        MdnsHandlerContext.h
        ServiceObserver.h
        ServiceListener.h
        codec/DnsMessageCodec.h
        message/DnsTypedef.h
        message/DnsName.h
        message/DnsQuestion.h
        message/DnsRecord.h
        message/DnsMessage.h
        )

SET(Mdns_Source
        ServiceInfo.c
        MdnsHandler.c
        MdnsHandlerContext.c
        ServiceObserver.c
        codec/DnsMessageCodec.c
        message/DnsTypedef.c
        message/DnsName.c
        message/DnsQuestion.c
        message/DnsRecord.c
        message/DnsMessage.c
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
