/**
 * Copyright (C) 2013-2015
 *
 * @author jxfengzi@gmail.com
 * @date   2013-11-19
 *
 * @file   DnsServerHandlerContext.h
 *
 * @remark
 *      set tabstop=4
 *      set shiftwidth=4
 *      set expandtab
 */

#ifndef __DNS_SERVER_HANDLER_CONTEXT_H__
#define __DNS_SERVER_HANDLER_CONTEXT_H__

#include <tiny_base.h>
#include <message/DnsTypedef.h>
#include <message/DnsMessage.h>

TINY_BEGIN_DECLS


typedef struct _DnsServerHandlerContext
{
    uint32_t            ip;
} DnsServerHandlerContext;

TINY_LOR
DnsServerHandlerContext * DnsServerHandlerContext_New(uint32_t ip);

TINY_LOR
TinyRet DnsServerHandlerContext_Construct(DnsServerHandlerContext *thiz, uint32_t ip);

TINY_LOR
void DnsServerHandlerContext_Dispose(DnsServerHandlerContext *thiz);

TINY_LOR
void DnsServerHandlerContext_Delete(DnsServerHandlerContext *thiz);

TINY_LOR
DnsMessage * DnsServerHandlerContext_MakeResponse(DnsServerHandlerContext *thiz, DnsMessage *request);


TINY_END_DECLS

#endif /* __DNS_SERVER_HANDLER_CONTEXT_H__ */