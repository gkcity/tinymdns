/**
 * Copyright (C) 2013-2015
 *
 * @author jxfengzi@gmail.com
 * @date   2013-11-19
 *
 * @file   example_registry.c
 *
 * @remark
 *
 */

#include <bootstrap/Bootstrap.h>
#include <channel/multicast/MulticastChannel.h>
#include <channel/SocketChannel.h>
#include <tiny_log.h>
#include <codec/DnsMessageCodec.h>
#include "../MdnsHandler.h"
#include "../MdnsConstant.h"

#define TAG             "example_registry"

void tiny_sleep(int ms)
{
    printf("tiny_sleep: %d\n", ms);
}

void tiny_print_mem(const char *tag, const char *function)
{
}

static void BonjourInitializer(Channel *channel, void *ctx)
{
    ChannelHandler *registry = MdnsHandler();
    MdnsHandler_Register(registry, (ServiceInfo *) ctx);

    LOG_D(TAG, "BonjourInitializer: %s", channel->id);

    SocketChannel_AddLast(channel, DnsMessageCodec());
    SocketChannel_AddLast(channel, registry);
}

int main(void)
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
    MulticastChannel_Join(channel, "10.0.1.9", MDNS_GROUP, MDNS_PORT, true);
    Bootstrap_Construct(&sb, NULL, NULL);
    Bootstrap_AddChannel(&sb, channel);
    Bootstrap_Sync(&sb);
    Bootstrap_Shutdown(&sb);
    Bootstrap_Dispose(&sb);

    tiny_socket_finalize();

    return 0;
}
