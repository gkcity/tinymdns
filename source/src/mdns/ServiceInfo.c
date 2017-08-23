/**
 * Copyright (C) 2013-2015
 *
 * @author jxfengzi@gmail.com
 * @date   2013-11-19
 *
 * @file   ServiceInfo.c
 *
 * @remark
 *
 */

#include <tiny_malloc.h>
#include <tiny_snprintf.h>
#include "ServiceInfo.h"

TINY_LOR
TinyRet ServiceInfo_Construct(ServiceInfo *thiz)
{
    memset(thiz, 0, sizeof(ServiceInfo));
    return TinyMap_Construct(&thiz->txt);
}

TINY_LOR
void ServiceInfo_Dispose(ServiceInfo *thiz)
{
    TinyMap_Dispose(&thiz->txt);
}

TINY_LOR
void ServiceInfo_Delete(ServiceInfo *thiz)
{
    ServiceInfo_Dispose(thiz);
    tiny_free(thiz);
}

TINY_LOR
ServiceInfo * ServiceInfo_New(void)
{
    ServiceInfo *thiz = NULL;

    do
    {
        thiz = (ServiceInfo *)tiny_malloc(sizeof(ServiceInfo));
        if (thiz == NULL)
        {
            break;
        }

        if (RET_FAILED(ServiceInfo_Construct(thiz)))
        {
            ServiceInfo_Delete(thiz);
            thiz = NULL;
            break;
        }
    } while (0);

    return thiz;
}

TINY_LOR
void ServiceInfo_Initialize(ServiceInfo *thiz, const char *name, const char *type, const char *ip, uint16_t port)
{
    strncpy(thiz->name, name, MDNS_NAME_LEN);
    strncpy(thiz->type, type, MDNS_TYPE_LEN);
    strncpy(thiz->ip, ip, MDNS_IP_LEN);
    thiz->port = port;
}