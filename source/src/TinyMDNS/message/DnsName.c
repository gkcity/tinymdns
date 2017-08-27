/**
 * Copyright (C) 2013-2015
 *
 * @author jxfengzi@gmail.com
 * @date   2013-11-19
 *
 * @file   DnsName.c
 *
 * @remark
 *      set tabstop=4
 *      set shiftwidth=4
 *      set expandtab
 */

#include <tiny_log.h>
#include <tiny_malloc.h>
#include <tiny_log_binary.h>
#include <tiny_snprintf.h>
#include "DnsName.h"

#define TAG         "DnsName"

TINY_LOR
TinyRet DnsName_Construct(DnsName *thiz)
{
    memset(thiz, 0, sizeof(DnsName));
    return TINY_RET_OK;
}

TINY_LOR
void DnsName_Dispose(DnsName *thiz)
{
    if (thiz->bytes != NULL)
    {
        tiny_free(thiz->bytes);
    }

    if (thiz->string != NULL)
    {
        tiny_free(thiz->string);
    }

    memset(thiz, 0, sizeof(DnsName));
}

typedef void (* DomainDnsNameIDVisitor)(const uint8_t *start, uint16_t length, void *ctx);

TINY_LOR
static uint32_t foreachDomainDnsNameIDs(const uint8_t *buf, uint32_t len, uint32_t offset, DomainDnsNameIDVisitor visitor, void *ctx)
{
    const uint8_t *p = buf + offset;

    if ((offset + 1) > len)
    {
        return 0;
    }

    while (true)
    {
        uint16_t length = *p;

        if ((length & 0xC0) == 0xC0)
        {
            uint32_t newOffset = (uint32_t) (((length << 8) + p[1]) & ~0xC000);

            if (foreachDomainDnsNameIDs(buf, len, newOffset, visitor, ctx) == 0)
            {
                return 0;
            }

            // skip 16 bits length
            p += 2;
            break;
        }

        if ((offset + length) > len)
        {
            return 0;
        }

        visitor(p + 1, length, ctx);
        p += length;
        p++;

        if (*p == 0)
        {
            // skip '\0'
            p++;
            break;
        }
    }

    return (uint32_t) (p - (buf + offset));
}

TINY_LOR
static void _OnGetDomainDnsNameIDLength(const uint8_t *start, uint16_t length, void *ctx)
{
    DnsName *name = (DnsName *)ctx;
    name->length += length + 1;
    name->count++;
}

TINY_LOR
static void _OnGetDomainDnsNameID(const uint8_t *start, uint16_t length, void *ctx)
{
    DnsName *name = (DnsName *)ctx;
    int offset = name->offset;

    /**
     * string
     */
    name->string[offset++] = '.';
    memcpy(name->string + offset, start, length);

    /**
     * bytes
     */
    name->bytes[name->offset++] = (uint8_t)length;
    memcpy(name->bytes + name->offset, start, length);
    name->offset += length;
}

TINY_LOR
uint32_t DnsName_Parse(DnsName *thiz, const uint8_t *buf, uint32_t len, uint32_t offset)
{
//    LOG_BINARY("DnsName", buf + offset, len - offset, true);

    uint32_t parsed = 0;

    if (*(buf + offset) == 0)
    {
        LOG_E(TAG, "length is 0");
        return 0;
    }

    if (foreachDomainDnsNameIDs(buf, len, offset, _OnGetDomainDnsNameIDLength, thiz) == 0)
    {
        return 0;
    }

    if (thiz->length == 0)
    {
        return 0;
    }

    thiz->length ++;

    /**
     * bytes
     */
    thiz->bytes = tiny_malloc(thiz->length);
    if (thiz->bytes == NULL)
    {
        LOG_E(TAG, "tiny_malloc failed");
        return 0;
    }
    memset(thiz->bytes, 0, thiz->length);

    /**
     * string
     */
    thiz->string = tiny_malloc(thiz->length);
    if (thiz->string == NULL)
    {
        LOG_E(TAG, "tiny_malloc failed");
        return 0;
    }
    memset(thiz->string, 0, thiz->length);

    parsed = foreachDomainDnsNameIDs(buf, len, offset, _OnGetDomainDnsNameID, thiz);

    return parsed;
}

TINY_LOR
TinyRet DnsName_Copy(DnsName *thiz, const DnsName *other)
{
    if (thiz != other)
    {
        if (thiz->string != NULL)
        {
            tiny_free(thiz->string);
            thiz->string = NULL;
        }

        if (thiz->bytes != NULL)
        {
            tiny_free(thiz->bytes);
            thiz->bytes = NULL;
        }

        thiz->length = other->length;
        if (thiz->length == 0)
        {
            return TINY_RET_OK;
        }

        /**
         * string
         */
        thiz->string = tiny_malloc(thiz->length);
        if (thiz->string == NULL)
        {
            return TINY_RET_E_NEW;
        }
        memcpy(thiz->string, other->string, thiz->length);

        /**
         * bytes
         */
        thiz->bytes = tiny_malloc(thiz->length);
        if (thiz->bytes == NULL)
        {
            return TINY_RET_E_NEW;
        }
        memcpy(thiz->bytes, other->bytes, thiz->length);
    }

    return TINY_RET_OK;
}

#define SERVICE_DNSSD       "._services._dns-sd._udp.local"

TINY_LOR
static TinyRet DnsName_Initialize(DnsName *thiz, const char *string, char x)
{
    TinyRet ret = TINY_RET_OK;

    do
    {
        thiz->length = (uint32_t) (1 + strlen(string));
        thiz->string = tiny_malloc(thiz->length);
        if (thiz->string == NULL)
        {
            ret = TINY_RET_E_NEW;
            break;
        }

        thiz->bytes = tiny_malloc(thiz->length);
        if (thiz->bytes == NULL)
        {
            ret = TINY_RET_E_NEW;
            break;
        }

        memset(thiz->string, 0, thiz->length);
        memset(thiz->bytes, 0, thiz->length);

        strncpy(thiz->string, string, thiz->length - 1);
        strncpy(thiz->bytes, string, thiz->length - 1);

        printf("DNSName: %s\n", thiz->string);

        /**
         * update: [x] = length
         *         #     P
         * [][][][][][][][]0
         * 0 1 2 3 4 5 6 7
         *
         * lastOffset = 7
         * offset = 4
         * length = lastOffset - offset
         */
        int lastOffset = thiz->length - 2;
        for (thiz->offset = thiz->length - 1; thiz->offset >= 0; thiz->offset--)
        {
            if (thiz->bytes[thiz->offset] == x)
            {
                thiz->bytes[thiz->offset] = (uint8_t) (lastOffset - thiz->offset);
                lastOffset = thiz->offset - 1;
            }
        }
    } while (0);

    return ret;
}

TINY_LOR
TinyRet DnsName_InitializeHost(DnsName *thiz, const char *name)
{
    char buf[64];
    tiny_snprintf(buf, 32, ".%s.local", name);
    return DnsName_Initialize(thiz, buf, '.');
}

TINY_LOR
TinyRet DnsName_InitializeReverseIpv4Host(DnsName *thiz, uint32_t ip)
{
    char buf[64];
    uint8_t *a = (uint8_t *) &ip;
    tiny_snprintf(buf, 32, "#%d.%d.%d.%d#in-addr#arpa", a[0], a[1], a[2], a[3]);
    return DnsName_Initialize(thiz, buf, '#');
}

TINY_LOR
TinyRet DnsName_InitializeServiceHost(DnsName *thiz, const char *name)
{
    char buf[64];
    tiny_snprintf(buf, 32, ".%s.local", name);
    return DnsName_Initialize(thiz, buf, '.');
}

TINY_LOR
TinyRet DnsName_InitializeServiceInstance(DnsName *thiz, const char *name, const char *type)
{
    char buf[64];
    tiny_snprintf(buf, 32, ".%s%s", name, type);
    return DnsName_Initialize(thiz, buf, '.');
}

TINY_LOR
TinyRet DnsName_InitializeServiceType(DnsName *thiz, const char *type)
{
    return DnsName_Initialize(thiz, type, '.');
}

TINY_LOR
TinyRet DnsName_InitializeServiceDnssd(DnsName *thiz)
{
    return DnsName_Initialize(thiz, SERVICE_DNSSD, '.');
}

TINY_LOR
bool DnsName_IsServiceDnssd(DnsName *thiz)
{
    return STR_EQUAL(thiz->string, SERVICE_DNSSD);
}

TINY_LOR
uint32_t DnsName_ToBytes(DnsName *thiz, uint8_t *buf, uint32_t length, uint32_t offset)
{
    if ((offset + thiz->length) > length)
    {
        return 0;
    }

    memcpy(buf + offset, thiz->bytes, thiz->length);

    return thiz->length;
}