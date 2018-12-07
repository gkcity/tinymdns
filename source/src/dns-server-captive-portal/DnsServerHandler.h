/**
 * Copyright (C) 2013-2015
 *
 * @author jxfengzi@gmail.com
 * @date   2013-11-19
 *
 * @file   DnsServerHandler.h
 *
 * @remark
 *      set tabstop=4
 *      set shiftwidth=4
 *      set expandtab
 */

#ifndef __DNS_SERVER_HANDLER_H__
#define __DNS_SERVER_HANDLER_H__

#include <channel/ChannelHandler.h>
#include <api/mdns_api.h>

TINY_BEGIN_DECLS


#define DnsServerHandler_Name "DnsServerHandler"


MDNS_API
TINY_LOR
ChannelHandler * DnsServerHandler(void);


TINY_END_DECLS

#endif /* __DNS_SERVER_HANDLER_H__ */