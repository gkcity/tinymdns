/**
 * Copyright (C) 2013-2015
 *
 * @author jxfengzi@gmail.com
 * @date   2013-11-19
 *
 * @file   DnsServerHandler.c
 *
 * @remark
 *      set tabstop=4
 *      set shiftwidth=4
 *      set expandtab
 */

#include <tiny_malloc.h>
#include <tiny_log.h>
#include <message/DnsMessage.h>
#include <channel/multicast/MulticastChannel.h>
#include "DnsServerHandler.h"
#include "DnsServerHandlerContext.h"

#define TAG "DnsServerHandler"

TINY_LOR
static TinyRet DnsServerHandler_Construct(ChannelHandler *thiz);

TINY_LOR
static TinyRet DnsServerHandler_Dispose(ChannelHandler *thiz);

TINY_LOR
static void DnsServerHandler_Delete(ChannelHandler *thiz);

TINY_LOR
static void _channelActive(ChannelHandler *thiz, Channel *channel);

TINY_LOR
static void _channelInactive(ChannelHandler *thiz, Channel *channel);

TINY_LOR
static bool _channelRead(ChannelHandler *thiz, Channel *channel, ChannelDataType type, const void *data, uint32_t len);

TINY_LOR
static void _channelEvent(ChannelHandler *thiz, Channel *channel, ChannelTimer *timer);

TINY_LOR
static TinyRet _channelGetNextTimeout(Channel *channel, ChannelTimer *timer, void *ctx);

TINY_LOR
ChannelHandler * DnsServerHandler(void)
{
    ChannelHandler *thiz = NULL;

    do
    {
        thiz = (ChannelHandler *)tiny_malloc(sizeof(ChannelHandler));
        if (thiz == NULL)
        {
            break;
        }

        if (RET_FAILED(DnsServerHandler_Construct(thiz)))
        {
            DnsServerHandler_Delete(thiz);
            thiz = NULL;
            break;
        }
    } while (0);

    return thiz;
}

TINY_LOR
static void DnsServerHandler_Delete(ChannelHandler *thiz)
{
    LOG_D(TAG, "DnsServerHandler_Delete");

    DnsServerHandler_Dispose(thiz);
    tiny_free(thiz);
}

TINY_LOR
static TinyRet DnsServerHandler_Construct(ChannelHandler *thiz)
{
    LOG_D(TAG, "DnsServerHandler_Construct");

    RETURN_VAL_IF_FAIL(thiz, TINY_RET_E_ARG_NULL);

    memset(thiz, 0, sizeof(ChannelHandler));

    strncpy(thiz->name, DnsServerHandler_Name, CHANNEL_HANDLER_NAME_LEN);
    thiz->onRemove = DnsServerHandler_Delete;
    thiz->inType = DATA_MDNS_MESSAGE;
    thiz->outType = DATA_MDNS_MESSAGE;
    thiz->channelActive = _channelActive;
    thiz->channelInactive = _channelInactive;
    thiz->channelRead = _channelRead;
    thiz->channelWrite = NULL;
    thiz->channelEvent = _channelEvent;
    thiz->getTimeout = _channelGetNextTimeout;
    thiz->context = DnsServerHandlerContext_New();
    if (thiz->context == NULL)
    {
        return TINY_RET_E_NEW;
    }

    return TINY_RET_OK;
}

TINY_LOR
static TinyRet DnsServerHandler_Dispose(ChannelHandler *thiz)
{
    RETURN_VAL_IF_FAIL(thiz, TINY_RET_E_ARG_NULL);

    DnsServerHandlerContext_Delete((DnsServerHandlerContext *) (thiz->context));
    memset(thiz, 0, sizeof(ChannelHandler));

    return TINY_RET_OK;
}

TINY_LOR
static void _handleQuery(ChannelHandler *thiz, Channel *channel, DnsMessage *query)
{
    LOG_D(TAG, "_handleQuery");

    DnsMessage *response = DnsServerHandlerContext_MakeResponse( (DnsServerHandlerContext *) (thiz->context), query);
    if (response != NULL)
    {
        uint8_t buf[1024];
        uint32_t length = DnsMessage_ToBytes(response, buf, 1024, 0);
        if (length > 0)
        {
            if (query != NULL)
            {
                if (query->unicast)
                {
                    LOG_D(TAG, "MulticastChannel_WriteTo: %x:%d", channel->remote.socket.address, channel->remote.socket.port);

                    if (RET_FAILED(MulticastChannel_WriteTo(channel, buf, length, channel->remote.socket.address, channel->remote.socket.port)))
                    {
                        LOG_E(TAG, "MulticastChannel_WriteTo FAILED!");
                    }
                }
                else
                {
                    if (RET_FAILED(MulticastChannel_Write(channel, buf, length)))
                    {
                        LOG_E(TAG, "MulticastChannel_Write FAILED!");
                    }
                }
            }
            else
            {
                if (RET_FAILED(MulticastChannel_Write(channel, buf, length)))
                {
                    LOG_E(TAG, "MulticastChannel_Write FAILED!");
                }
            }
        }

        DnsMessage_Delete(response);
    }
}

TINY_LOR
static void _handleRequest(ChannelHandler *thiz, Channel *channel, DnsMessage *request)
{
    switch (request->header.FLAG.bits.Opcode)
    {
        case QPCODE_QUERY:
            _handleQuery(thiz, channel, request);
            break;

        default:
            LOG_D(TAG, "ignore opcode: %d", request->header.FLAG.bits.Opcode);
            break;
    }
}

TINY_LOR
static void _channelActive(ChannelHandler *thiz, Channel *channel)
{
    LOG_D(TAG, "_channelActive");

    _handleQuery(thiz, channel, NULL);
}

TINY_LOR
static void _channelInactive(ChannelHandler *thiz, Channel *channel)
{
    LOG_D(TAG, "_channelInactive");
}

TINY_LOR
static bool _channelRead(ChannelHandler *thiz, Channel *channel, ChannelDataType type, const void *data, uint32_t len)
{
    DnsMessage *message = (DnsMessage *)data;

    LOG_D(TAG, "_channelRead: %d type: %d, len: %d from: %s: %d", channel->fd, type, len, channel->remote.socket.ip, channel->remote.socket.port);

    if (STR_EQUAL(channel->remote.socket.ip, "127.0.0.1"))
    {
        return true;
    }

    if (message->header.FLAG.bits.QR == QR_QUERY)
    {
        _handleRequest(thiz, channel, message);
    }

    return true;
}

TINY_LOR
static void _channelEvent(ChannelHandler *thiz, Channel *channel, ChannelTimer *timer)
{
    LOG_D(TAG, "_channelEvent");
}

TINY_LOR
static TinyRet _channelGetNextTimeout(Channel *channel, ChannelTimer *timer, void *ctx)
{
    return TINY_RET_OK;
}