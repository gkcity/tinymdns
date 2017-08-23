/**
 * Copyright (C) 2013-2015
 *
 * @author jxfengzi@gmail.com
 * @date   2013-11-19
 *
 * @file   MdnsHandler.c
 *
 * @remark
 *      set tabstop=4
 *      set shiftwidth=4
 *      set expandtab
 */

#include <tiny_log.h>
#include <tiny_malloc.h>
#include <tiny_time.h>
#include <channel/ChannelTimer.h>
#include <channel/SocketChannel.h>
#include <channel/multicast/MulticastChannel.h>
#include "message/DnsMessage.h"
#include "message/DnsRecord.h"
#include "MdnsHandler.h"
#include "MdnsHandlerContext.h"
#include "ServiceObserver.h"

#define TAG "MdnsHandler"

TINY_LOR
static TinyRet MdnsHandler_Construct(ChannelHandler *thiz);

TINY_LOR
static TinyRet MdnsHandler_Dispose(ChannelHandler *thiz);

TINY_LOR
static void MdnsHandler_Delete(ChannelHandler *thiz);

TINY_LOR
static void _channelActive(ChannelHandler *thiz, Channel *channel);

TINY_LOR
static void _channelInactive(ChannelHandler *thiz, Channel *channel);

TINY_LOR
static bool _channelRead(ChannelHandler *thiz, Channel *channel, ChannelDataType type, const void *data, uint32_t len);

TINY_LOR
static void _channelEvent(ChannelHandler *thiz, Channel *channel, void *event);

TINY_LOR
TinyRet _channelGetNextTimeout(Channel *thiz, ChannelTimer *timer, void *ctx);

TINY_LOR
ChannelHandler * MdnsHandler(void)
{
    ChannelHandler *thiz = NULL;

    do
    {
        thiz = (ChannelHandler *)tiny_malloc(sizeof(ChannelHandler));
        if (thiz == NULL)
        {
            break;
        }

        if (RET_FAILED(MdnsHandler_Construct(thiz)))
        {
            MdnsHandler_Delete(thiz);
            thiz = NULL;
            break;
        }
    } while (0);

    return thiz;
}

TINY_LOR
static void MdnsHandler_Delete(ChannelHandler *thiz)
{
    LOG_D(TAG, "MdnsHandler_Delete");

    MdnsHandler_Dispose(thiz);
    tiny_free(thiz);
}

TINY_LOR
static TinyRet MdnsHandler_Construct(ChannelHandler *thiz)
{
    printf("MdnsHandler_Construct\n");

    RETURN_VAL_IF_FAIL(thiz, TINY_RET_E_ARG_NULL);

    memset(thiz, 0, sizeof(ChannelHandler));

    strncpy(thiz->name, MdnsHandler_Name, CHANNEL_HANDLER_NAME_LEN);
    thiz->onRemove = MdnsHandler_Delete;
    thiz->inType = DATA_MDNS_MESSAGE;
    thiz->outType = DATA_MDNS_MESSAGE;
    thiz->channelActive = _channelActive;
    thiz->channelInactive = _channelInactive;
    thiz->channelRead = _channelRead;
    thiz->channelWrite = NULL;
    thiz->channelEvent = _channelEvent;
    thiz->getTimeout = _channelGetNextTimeout;
    thiz->data = MdnsHandlerContext_New();
    if (thiz->data == NULL)
    {
        return TINY_RET_E_NEW;
    }

    return TINY_RET_OK;
}

TINY_LOR
static TinyRet MdnsHandler_Dispose(ChannelHandler *thiz)
{
    RETURN_VAL_IF_FAIL(thiz, TINY_RET_E_ARG_NULL);

    MdnsHandlerContext_Delete((MdnsHandlerContext *) (thiz->data));
    memset(thiz, 0, sizeof(ChannelHandler));

    return TINY_RET_OK;
}

TINY_LOR
TinyRet MdnsHandler_Register(ChannelHandler *thiz, ServiceInfo *info)
{
    return MdnsHandlerContext_Register((MdnsHandlerContext *)(thiz->data), info);
}

TINY_LOR
TinyRet MdnsHandler_Unregister(ChannelHandler *thiz, ServiceInfo *info)
{
    return MdnsHandlerContext_Unregister((MdnsHandlerContext *)(thiz->data), info);
}

#ifdef MDNS_DISCOVERY
TINY_LOR
TinyRet MdnsHandler_AddListener(ChannelHandler *thiz, const char *type, ServiceListener listener, void *ctx)
{
    ServiceObserver * observer = NULL;

    LOG_D(TAG, "MdnsHandler_AddListener");

    RETURN_VAL_IF_FAIL(thiz, TINY_RET_E_ARG_NULL);
    RETURN_VAL_IF_FAIL(type, TINY_RET_E_ARG_NULL);
    RETURN_VAL_IF_FAIL(listener, TINY_RET_E_ARG_NULL);

    observer = ServiceObserver_New(type, listener, ctx);
    if (observer == NULL)
    {
        return TINY_RET_E_NEW;
    }

    return TinyList_AddTail(& ((MdnsHandlerContext *)(thiz->data))->observers, observer);
}
#endif

TINY_LOR
static void _handleNotify(ChannelHandler *thiz, Channel *channel, DnsMessage *notify)
{
    LOG_D(TAG, "_handleNotify");
}

TINY_LOR
static void _handleUpdate(ChannelHandler *thiz, Channel *channel, DnsMessage *notify)
{
    LOG_D(TAG, "_handleUpdate");
}

TINY_LOR
static void _handleRecord(ChannelHandler *thiz, Channel *channel, DnsMessage *message)
{
    LOG_D(TAG, "_handleRecord");

#ifdef MDNS_DISCOVERY
    DnsMessage * request = MdnsHandlerContext_MakeRequestByAnswers((MdnsHandlerContext *) (thiz->data), &message->answers);
    if (request != NULL)
    {
        uint8_t buf[1024];
        uint32_t length = DnsMessage_ToBytes(request, buf, 1024, 0);
        if (length > 0)
        {
//            LOG_I(TAG, "request length: %d", length);
//            DnsMessage test;
//            DnsMessage_Construct(&test);
//            DnsMessage_Parse(&test, buf, length);
//            DnsMessage_Dispose(&test);
            if (RET_FAILED(MulticastChannel_Write(channel, buf, length)))
            {
                LOG_E(TAG, "MulticastChannel_Write FAILED!");
            }
        }

        DnsMessage_Delete(request);
    }
#endif
}

TINY_LOR
static void _handleQuery(ChannelHandler *thiz, Channel *channel, DnsMessage *query)
{
    LOG_D(TAG, "_handleQuery");

    DnsMessage *response = MdnsHandlerContext_MakeResponse( (MdnsHandlerContext *) (thiz->data), query);
    if (response != NULL)
    {
        uint8_t buf[1024];
        uint32_t length = DnsMessage_ToBytes(response, buf, 1024, 0);
        if (length > 0)
        {
#if 0
            printf("test: %d\n", length);
            DnsMessage test;
            DnsMessage_Construct(&test);
            DnsMessage_Parse(&test, buf, length);
            DnsMessage_Dispose(&test);
#endif

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

//    _handleRecord(thiz, channel, query);
}

TINY_LOR
static void _handleRequest(ChannelHandler *thiz, Channel *channel, DnsMessage *request)
{
    LOG_E(TAG, "_handleRequest");

    switch (request->header.FLAG.bits.Opcode)
    {
        case QPCODE_QUERY:
            _handleQuery(thiz, channel, request);
            break;

        case OPCODE_NOTIFY:
            _handleNotify(thiz, channel, request);
            break;

        case OPCODE_UPDATE:
            _handleUpdate(thiz, channel, request);
            break;

        default:
            break;
    }
}

TINY_LOR
static void _handleResponse(ChannelHandler *thiz, Channel *channel, DnsMessage *response)
{
    LOG_E(TAG, "_handleResponse");

    _handleRecord(thiz, channel, response);
}

TINY_LOR
static void _channelActive(ChannelHandler *thiz, Channel *channel)
{
    LOG_D(TAG, "_channelActive");

#ifdef MDNS_DISCOVERY
    do
    {
        DnsMessage * request = MdnsHandlerContext_MakeRequest((MdnsHandlerContext *)thiz->data);
        if (request != NULL)
        {
            uint8_t buf[1024];
            uint32_t length = DnsMessage_ToBytes(request, buf, 1024, 0);
            if (length > 0)
            {
//                LOG_I(TAG, "request length: %d", length);
//                DnsMessage test;
//                DnsMessage_Construct(&test);
//                DnsMessage_Parse(&test, buf, length);
//                DnsMessage_Dispose(&test);

                if (RET_FAILED(MulticastChannel_Write(channel, buf, length)))
                {
                    LOG_E(TAG, "MulticastChannel_Write FAILED!");
                }
            }

            DnsMessage_Delete(request);
        }
    } while (0);
#endif

    _handleQuery(thiz, channel, NULL);
}

TINY_LOR
static void _channelInactive(ChannelHandler *thiz, Channel *channel)
{
    LOG_D(TAG, "_channelInactive");

    DnsMessage *response = MdnsHandlerContext_MakeResponse( (MdnsHandlerContext *) (thiz->data), NULL);
    if (response != NULL)
    {
        uint8_t buf[1024];
        uint32_t length = DnsMessage_ToBytes(response, buf, 1024, 0);
        if (length > 0)
        {
            for (int i = 0; i < 3; ++i)
            {
                if (RET_FAILED(MulticastChannel_Write(channel, buf, length)))
                {
                    LOG_E(TAG, "MulticastChannel_Write FAILED!");
                    break;
                }
            }
        }

        DnsMessage_Delete(response);
    }
}

TINY_LOR
static bool _channelRead(ChannelHandler *thiz, Channel *channel, ChannelDataType type, const void *data, uint32_t len)
{
    DnsMessage *message = (DnsMessage *)data;

    LOG_D(TAG, "_channelRead: %d type: %d, len: %d from: %s: %d", channel->fd, type, len,
          channel->remote.socket.ip, channel->remote.socket.port);

    if (message->header.FLAG.bits.QR == QR_QUERY)
    {
        _handleRequest(thiz, channel, message);
    }
    else
    {
        _handleResponse(thiz, channel, message);
    }

    return true;
}

TINY_LOR
static void _channelEvent(ChannelHandler *thiz, Channel *channel, void *event)
{
    LOG_D(TAG, "_channelEvent");
    _handleQuery(thiz, channel, NULL);
}

TINY_LOR
TinyRet _channelGetNextTimeout(Channel *channel, ChannelTimer *timer, void *ctx)
{
    // return (1000 * 1000 * ((MdnsHandlerContext *) (((ChannelHandler *)ctx)->data))->ttl);

    uint64_t current = tiny_current_microsecond();
    ChannelHandler *thiz = (ChannelHandler *)ctx;
    MdnsHandlerContext * context = (MdnsHandlerContext *)(thiz->data);
    int64_t timeout = context->ttl * 1000000;

    timer->valid = true;
    timer->type = CHANNEL_TIMER_OTHER;
    timer->timeout = timeout;

    return TINY_RET_OK;
}