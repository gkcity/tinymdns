/**
 * Copyright (C) 2013-2015
 *
 * @author jxfengzi@gmail.com
 * @date   2013-11-19
 *
 * @file   DnsMessageCodec.c
 *
 * @remark
 *      set tabstop=4
 *      set shiftwidth=4
 *      set expandtab
 */

#include <channel/SocketChannel.h>
#include <tiny_log.h>
#include <tiny_malloc.h>
#include "DnsMessageCodec.h"
#include "message/DnsMessage.h"

#define TAG     "DnsMessageCodec"


TINY_LOR
static bool _channelRead(ChannelHandler *thiz, Channel *channel, ChannelDataType type, const void *data, uint32_t len)
{
    DnsMessage message;

//    tiny_print_stack_info(TAG, "_channelRead");

    if (type != DATA_RAW)
    {
        LOG_D(TAG, "_channelRead inType error: %d", type);
        return true;
    }

    if (RET_SUCCEEDED(DnsMessage_Construct(&message)))
    {
        if (RET_SUCCEEDED(DnsMessage_Parse(&message, data, len)))
        {
            SocketChannel_NextRead(channel, DATA_MDNS_MESSAGE, &message, len);
        }

        DnsMessage_Dispose(&message);
    }

    return true;
}

TINY_LOR
static TinyRet DnsMessageCodec_Dispose(ChannelHandler *thiz)
{
    RETURN_VAL_IF_FAIL(thiz, TINY_RET_E_ARG_NULL);
    memset(thiz, 0, sizeof(ChannelHandler));
    return TINY_RET_OK;
}

TINY_LOR
static void DnsMessageCodec_Delete(ChannelHandler *thiz)
{
    DnsMessageCodec_Dispose(thiz);
    tiny_free(thiz);
}

TINY_LOR
static TinyRet DnsMessageCodec_Construct(ChannelHandler *thiz)
{
    memset(thiz, 0, sizeof(ChannelHandler));

    strncpy(thiz->name, DnsMessageCodec_Name, CHANNEL_HANDLER_NAME_LEN);
    thiz->onRemove = DnsMessageCodec_Delete;
    thiz->inType = DATA_RAW;
    thiz->outType = DATA_MDNS_MESSAGE;
    thiz->channelRead = _channelRead;
    thiz->channelWrite = NULL;
    thiz->data = NULL;

    return TINY_RET_OK;
}

TINY_LOR
ChannelHandler * DnsMessageCodec(void)
{
    ChannelHandler *thiz = NULL;

    do
    {
        thiz = (ChannelHandler *)tiny_malloc(sizeof(ChannelHandler));
        if (thiz == NULL)
        {
            break;
        }

        if (RET_FAILED(DnsMessageCodec_Construct(thiz)))
        {
            DnsMessageCodec_Delete(thiz);
            thiz = NULL;
            break;
        }
    } while (0);

    return thiz;
}