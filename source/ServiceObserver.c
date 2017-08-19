/**
 * Copyright (C) 2013-2015
 *
 * @author jxfengzi@gmail.com
 * @date   2013-11-19
 *
 * @file   ServiceObserver.c
 *
 * @remark
 *      set tabstop=4
 *      set shiftwidth=4
 *      set expandtab
 */

#include <tiny_malloc.h>
#include "ServiceObserver.h"

#ifdef MDNS_DISCOVERY

TINY_LOR
static TinyRet ServiceObserver_Construct(ServiceObserver *thiz, const char *type, ServiceListener listener, void *ctx)
{
    memset(thiz, 0, sizeof(ServiceObserver));
    strncpy(thiz->type, type, MDNS_SERVICE_TYPE_LEN);
    thiz->listener = listener;
    thiz->ctx = ctx;

    return TINY_RET_OK;
}

TINY_LOR
static void ServiceObserver_Dispose(ServiceObserver *thiz)
{
    memset(thiz, 0, sizeof(ServiceObserver));
}

TINY_LOR
ServiceObserver * ServiceObserver_New(const char *type, ServiceListener listener, void *ctx)
{
    ServiceObserver *thiz = NULL;

    do
    {
        thiz = tiny_malloc(sizeof(ServiceObserver));
        if (thiz == NULL)
        {
            printf("tiny_malloc failed!\n");
            break;
        }

        if (RET_FAILED(ServiceObserver_Construct(thiz, type, listener, ctx)))
        {
            ServiceObserver_Delete(thiz);
            thiz = NULL;
            break;
        }
    } while (0);

    return thiz;
}

TINY_LOR
void ServiceObserver_Delete(ServiceObserver *thiz)
{
    ServiceObserver_Dispose(thiz);
    tiny_free(thiz);
}

#endif