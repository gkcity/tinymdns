#-----------------------------------------------------------------------------
#
# dns-common
#
#-----------------------------------------------------------------------------


SET(Common_Header
        api/mdns_api.h
        codec/DnsMessageCodec.h
        message/ServiceInfo.h
        message/DnsTypedef.h
        message/DnsName.h
        message/DnsQuestion.h
        message/DnsRecord.h
        message/DnsMessage.h
        )

SET(Common_Source
        codec/DnsMessageCodec.c
        message/ServiceInfo.c
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
        ${Common_Header}
        ${Common_Source}
        )

#----------------------------------------------------------------------------
# static library
#----------------------------------------------------------------------------
ADD_LIBRARY(dns_common_static STATIC ${SRC})
SET_TARGET_PROPERTIES(dns_common_static PROPERTIES OUTPUT_NAME "dns_common_static")
SET_TARGET_PROPERTIES(dns_common_static PROPERTIES LINKER_LANGUAGE C)