/**
 * Copyright (C) 2013-2015
 *
 * @author jxfengzi@gmail.com
 * @date   2013-11-19
 *
 * @file   sample_registry.c
 *
 * @remark
 *
 */

#include <bootstrap/Bootstrap.h>
#include <channel/multicast/MulticastChannel.h>
#include <channel/SocketChannel.h>
#include <tiny_log.h>
#include <codec/DnsMessageCodec.h>
#include "../../../../source/src/multicast-dns/MdnsHandler.h"
#include "../../../../source/src/multicast-dns/MdnsConstant.h"

static void BonjourInitializer(Channel *channel, void *ctx)
{
    ChannelHandler *registry = MdnsHandler();
    MdnsHandler_Register(registry, (ServiceInfo *) ctx);
    SocketChannel_AddLast(channel, DnsMessageCodec());
    SocketChannel_AddLast(channel, registry);
}

void sample_registry(void *pvParameters)
{
    Bootstrap sb;
    ServiceInfo info;
    Channel *channel = NULL;

    tiny_socket_initialize();

    ServiceInfo_Construct(&info);
    ServiceInfo_Initialize(&info, "hello123456abc", SERVICE_TYPE_HAP, "10.0.1.9", 8080);
    TinyMap_Insert(&info.txt, "pv", "1.0");                 // protocol version
    TinyMap_Insert(&info.txt, "sf", "1");                   // discoverable ? "1" : "0"
    TinyMap_Insert(&info.txt, "id", "AA:BB:CC:00:11:22");
    TinyMap_Insert(&info.txt, "md", "test");
    TinyMap_Insert(&info.txt, "c#", "2");                   // configurationNumber
    TinyMap_Insert(&info.txt, "s#", "1");                   // currentStateNumber
    TinyMap_Insert(&info.txt, "ff", "0");                   // featureFlags
    TinyMap_Insert(&info.txt, "ci", "8");                   // switch

    channel = MulticastChannel_New();
    MulticastChannel_Initialize(channel, BonjourInitializer, &info);
    MulticastChannel_Join(channel, "10.0.1.33", MDNS_GROUP, MDNS_PORT, false);
    Bootstrap_Construct(&sb);
    Bootstrap_AddChannel(&sb, channel);
    Bootstrap_Sync(&sb);
    Bootstrap_Shutdown(&sb);
    Bootstrap_Dispose(&sb);

    tiny_socket_finalize();
}
