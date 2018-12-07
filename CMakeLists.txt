CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
PROJECT(TinyMDNS C)

SET(PROJ_NAME "TinyMDNS")

#---------------------------------------------------------------------------------------
#
# include dir
#
#---------------------------------------------------------------------------------------
SET(SOURCE_ROOT ${PROJECT_SOURCE_DIR}/source/src)
SET(TINY_ROOT ${PROJECT_SOURCE_DIR}/../tiny)

INCLUDE_DIRECTORIES(${SOURCE_ROOT}/dns-common)
INCLUDE_DIRECTORIES(${SOURCE_ROOT}/dns-server)
INCLUDE_DIRECTORIES(${SOURCE_ROOT}/mdns)

INCLUDE_DIRECTORIES(${TINY_ROOT}/source/src/TinyBase)
INCLUDE_DIRECTORIES(${TINY_ROOT}/source/src/TinyPortable)
INCLUDE_DIRECTORIES(${TINY_ROOT}/source/src/TinyContainer)
INCLUDE_DIRECTORIES(${TINY_ROOT}/source/src/TinyLog)
INCLUDE_DIRECTORIES(${TINY_ROOT}/source/src/TinyStringUtil)
INCLUDE_DIRECTORIES(${TINY_ROOT}/source/src/TinyRandom)
INCLUDE_DIRECTORIES(${TINY_ROOT}/source/src/Netty)
INCLUDE_DIRECTORIES(${TINY_ROOT}/source/src/TinyUmm)
INCLUDE_DIRECTORIES(${TINY_ROOT}/source/src/TinyMd5)
INCLUDE_DIRECTORIES(${TINY_ROOT}/source/src/TinyThread)
INCLUDE_DIRECTORIES(${TINY_ROOT}/source/src/TinyUuid)
INCLUDE_DIRECTORIES(${TINY_ROOT}/source/src/TinyWorker)

#---------------------------------------------------------------------------------------
#
# link dir
#
#---------------------------------------------------------------------------------------
LINK_DIRECTORIES(${TINY_ROOT}/target)

#-------------------------------------------------------------------------------------
# output dir
#-------------------------------------------------------------------------------------
SET(LIBRARY_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/target)
SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/target)
MESSAGE(STATUS "executable output:  ${EXECUTABLE_OUTPUT_PATH}")
MESSAGE(STATUS "library output: ${LIBRARY_OUTPUT_PATH}")

#-------------------------------------------------------------------------------------
#
# Source
#
#-------------------------------------------------------------------------------------

SET(Mdns_Header
        ${SOURCE_ROOT}/dns-common/api/mdns_api.h
        ${SOURCE_ROOT}/dns-common/codec/DnsMessageCodec.h
        ${SOURCE_ROOT}/dns-common/message/DnsTypedef.h
        ${SOURCE_ROOT}/dns-common/message/DnsName.h
        ${SOURCE_ROOT}/dns-common/message/DnsQuestion.h
        ${SOURCE_ROOT}/dns-common/message/DnsRecord.h
        ${SOURCE_ROOT}/dns-common/message/DnsMessage.h
        ${SOURCE_ROOT}/dns-common/message/ServiceInfo.h
        ${SOURCE_ROOT}/mdns/MdnsConstant.h
        ${SOURCE_ROOT}/mdns/MdnsHandler.h
        ${SOURCE_ROOT}/mdns/MdnsHandlerContext.h
        ${SOURCE_ROOT}/mdns/ServiceObserver.h
        ${SOURCE_ROOT}/mdns/ServiceListener.h
        ${SOURCE_ROOT}/dns-server/DnsConstant.h
        ${SOURCE_ROOT}/dns-server/DnsServerHandler.h
        ${SOURCE_ROOT}/dns-server/DnsServerHandlerContext.h
        )

SET(Mdns_Source
        ${SOURCE_ROOT}/dns-common/codec/DnsMessageCodec.c
        ${SOURCE_ROOT}/dns-common/message/DnsTypedef.c
        ${SOURCE_ROOT}/dns-common/message/DnsName.c
        ${SOURCE_ROOT}/dns-common/message/DnsQuestion.c
        ${SOURCE_ROOT}/dns-common/message/DnsRecord.c
        ${SOURCE_ROOT}/dns-common/message/DnsMessage.c
        ${SOURCE_ROOT}/dns-common/message/ServiceInfo.c
        ${SOURCE_ROOT}/mdns/MdnsHandler.c
        ${SOURCE_ROOT}/mdns/MdnsHandlerContext.c
        ${SOURCE_ROOT}/mdns/ServiceObserver.c
        ${SOURCE_ROOT}/dns-server/DnsServerHandler.c
        ${SOURCE_ROOT}/dns-server/DnsServerHandlerContext.c
        )

SET(SRC
        ${Mdns_Header}
        ${Mdns_Source}
        )

#----------------------------------------------------------------------------
# static library
#----------------------------------------------------------------------------
IF (EXPORT_STATIC_LIBRARY EQUAL 1)
ADD_LIBRARY(tinymdns_static STATIC ${SRC})
SET_TARGET_PROPERTIES(tinymdns_static PROPERTIES OUTPUT_NAME "tinymdns_static")
SET_TARGET_PROPERTIES(tinymdns_static PROPERTIES LINKER_LANGUAGE C)
ENDIF ()

#----------------------------------------------------------------------------
# shared library
#----------------------------------------------------------------------------
IF (EXPORT_SHARED_LIBRARY EQUAL 1)
ADD_LIBRARY(tinymdns SHARED ${SRC})
SET_TARGET_PROPERTIES(tinymdns PROPERTIES OUTPUT_NAME "tinymdns")
SET_TARGET_PROPERTIES(tinymdns PROPERTIES LINKER_LANGUAGE C)
TARGET_LINK_LIBRARIES(tinymdns ${DEPENDENCE_LIB})
ENDIF ()
