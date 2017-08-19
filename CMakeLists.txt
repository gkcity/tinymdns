CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
PROJECT(TinyMDNS C)

SET(PROJ_NAME "TinyMDNS")

#---------------------------------------------------------------------------------------
#
# include dir
#
#---------------------------------------------------------------------------------------
SET(SOURCE_ROOT ${PROJECT_SOURCE_DIR}/source)
INCLUDE_DIRECTORIES(${SOURCE_ROOT})

SET(TINY_ROOT ${PROJECT_SOURCE_DIR}/tiny/source/src)
INCLUDE_DIRECTORIES(${TINY_ROOT}/TinyBase)
INCLUDE_DIRECTORIES(${TINY_ROOT}/TinyPortable)
INCLUDE_DIRECTORIES(${TINY_ROOT}/TinyContainer)
INCLUDE_DIRECTORIES(${TINY_ROOT}/TinyLog)
INCLUDE_DIRECTORIES(${TINY_ROOT}/TinyStringUtil)
INCLUDE_DIRECTORIES(${TINY_ROOT}/TinyJson)
INCLUDE_DIRECTORIES(${TINY_ROOT}/Netty)
INCLUDE_DIRECTORIES(${TINY_ROOT}/TinyUmm)
INCLUDE_DIRECTORIES(${TINY_ROOT}/TinyMd5)
INCLUDE_DIRECTORIES(${TINY_ROOT}/TinyThread)
INCLUDE_DIRECTORIES(${TINY_ROOT}/TinyUuid)
INCLUDE_DIRECTORIES(${TINY_ROOT}/TinyWorker)

#-------------------------------------------------------------------------------------
# output dir
#-------------------------------------------------------------------------------------
SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/output)
SET(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}/output)
MESSAGE(STATUS "executable output:  ${EXECUTABLE_OUTPUT_PATH}")
MESSAGE(STATUS "library output: ${LIBRARY_OUTPUT_PATH}")

#-------------------------------------------------------------------------------------
#
# Source
#
#-------------------------------------------------------------------------------------
ADD_SUBDIRECTORY(source)
