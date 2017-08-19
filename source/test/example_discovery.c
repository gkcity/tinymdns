/**
 * Copyright (C) 2013-2015
 *
 * @author jxfengzi@gmail.com
 * @date   2013-11-19
 *
 * @file   example_discovery.c
 *
 * @remark
 *
 */

#include <bootstrap/Bootstrap.h>
#include <channel/multicast/MulticastChannel.h>
#include <channel/SocketChannel.h>
#include <tiny_log.h>
#include <codec/DnsMessageCodec.h>
#include <MdnsConstant.h>
#include <MdnsHandler.h>

#define TAG             "example_discovery"

void tiny_print_stack_info(const char *tag, const char *function)
{
}

static void _ServiceListener(ServiceInfo *info, ServiceEvent event, void *ctx)
{
    LOG_D(TAG, "_ServiceListener: %d", event);
}

static void BonjourInitializer(Channel *channel, void *ctx)
{
    ChannelHandler * discovery = MdnsHandler();
    MdnsHandler_AddListener(discovery, SERVICE_TYPE_HAP, _ServiceListener, ctx);

    LOG_D(TAG, "BonjourInitializer: %s", channel->id);

    SocketChannel_AddLast(channel, DnsMessageCodec());
    SocketChannel_AddLast(channel, discovery);
}

int main(void)
{
    Bootstrap sb;
    Channel *channel = NULL;

    tiny_socket_initialize();

    channel = MulticastChannel_New();
    MulticastChannel_Initialize(channel, BonjourInitializer, NULL);
    MulticastChannel_Join(channel, "10.0.1.9", MDNS_GROUP, MDNS_PORT, true);
    Bootstrap_Construct(&sb);
    Bootstrap_AddChannel(&sb, channel);
    Bootstrap_Sync(&sb);
    Bootstrap_Shutdown(&sb);
    Bootstrap_Dispose(&sb);

    tiny_socket_finalize();

    return 0;
}