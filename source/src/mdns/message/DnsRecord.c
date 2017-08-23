/**
 * Copyright (C) 2013-2015
 *
 * @author jxfengzi@gmail.com
 * @date   2013-11-19
 *
 * @file   DnsRecord.h
 *
 * @remark
 *      set tabstop=4
 *      set shiftwidth=4
 *      set expandtab
 */

#include <tiny_malloc.h>
#include <tiny_log.h>
#include <tiny_log_binary.h>
#include <tiny_inet.h>
#include <tiny_snprintf.h>
#include <tiny_str_split.h>
#include "DnsRecord.h"

#define TAG         "DnsRecord"

TINY_LOR
TinyRet DnsRecord_Construct(DnsRecord *thiz)
{
    memset(thiz, 0, sizeof(DnsRecord));

    DnsName_Construct(&thiz->name);

    return TINY_RET_OK;
}

TINY_LOR
void DnsRecord_Dispose(DnsRecord *thiz)
{
    DnsName_Dispose(&thiz->name);

    switch (thiz->type)
    {
        case TYPE_NS:
            DnsName_Dispose(&thiz->data.ns);
            break;

        case TYPE_CNAME:
            DnsName_Dispose(&thiz->data.cname);
            break;

        case TYPE_PTR:
            DnsName_Dispose(&thiz->data.ptr);
            break;

        case TYPE_SRV:
            DnsName_Dispose(&thiz->data.srv.name);
            break;

        case TYPE_A:
            break;

        case TYPE_TXT:
            if (thiz->data.txt.value != NULL)
            {
                tiny_free(thiz->data.txt.value);
            }
            break;

        case TYPE_AAAA:
            break;

        case TYPE_ANY:
            break;
    }
}

TINY_LOR
DnsRecord * DnsRecord_New(void)
{
    DnsRecord *thiz = NULL;

    do
    {
        thiz = (DnsRecord *)tiny_malloc(sizeof(DnsRecord));
        if (thiz == NULL)
        {
            break;
        }

        if (RET_FAILED(DnsRecord_Construct(thiz)))
        {
            DnsRecord_Dispose(thiz);
            thiz = NULL;
            break;
        }
    } while (0);

    return thiz;
}

TINY_LOR
TinyRet DnsRecord_Copy(DnsRecord *dst, DnsRecord *src)
{
    TinyRet ret = TINY_RET_OK;

    do
    {
        ret = DnsName_Copy(&dst->name, &src->name);
        if (RET_FAILED(ret))
        {
            break;
        }

        dst->type = src->type;
        dst->clazz = src->clazz;
        dst->ttl = src->ttl;

        switch (src->type)
        {
            case TYPE_A:
                dst->data.a.address = src->data.a.address;
                strncpy(dst->data.a.ip, src->data.a.ip, TINY_IP_LEN);
                break;

            case TYPE_NS:
                DnsName_Construct(&dst->data.ns);
                DnsName_Copy(&dst->data.ns, &src->data.ns);
                break;

            case TYPE_CNAME:
                DnsName_Construct(&dst->data.cname);
                DnsName_Copy(&dst->data.cname, &src->data.cname);
                break;

            case TYPE_PTR:
                DnsName_Construct(&dst->data.ptr);
                DnsName_Copy(&dst->data.ptr, &src->data.ptr);
                break;

            case TYPE_TXT:
                dst->data.txt.length = src->data.txt.length;
                dst->data.txt.offset = src->data.txt.offset;
                dst->data.txt.value = tiny_malloc(dst->data.txt.length);
                if (dst->data.txt.value != NULL)
                {
                    memcpy(dst->data.txt.value, src->data.txt.value, dst->data.txt.length);
                }
                break;

            case TYPE_AAAA:
                break;

            case TYPE_SRV:
                dst->data.srv.priority = src->data.srv.priority;
                dst->data.srv.weight = src->data.srv.weight;
                dst->data.srv.port = src->data.srv.port;
                DnsName_Construct(&dst->data.srv.name);
                DnsName_Copy(&dst->data.srv.name, &src->data.srv.name);
                break;

            case TYPE_ANY:
                break;
        }
    } while (0);

    return ret;
}

TINY_LOR
void DnsRecord_Delete(DnsRecord *thiz)
{
    DnsRecord_Dispose(thiz);
    tiny_free(thiz);
}

TINY_LOR
DnsRecord * DnsRecord_NewPTR(DnsName *name, DnsRecordClass clazz, uint32_t ttl, DnsName *ptr)
{
    DnsRecord *thiz = NULL;

    do
    {
        thiz = DnsRecord_New();
        if (thiz == NULL)
        {
            LOG_E(TAG, "DnsRecord_New FAILED");
            break;
        }

        if (RET_FAILED(DnsName_Copy(&thiz->name, name)))
        {
            LOG_E(TAG, "DnsName_SetString FAILED");
            DnsRecord_Delete(thiz);
            break;
        }

        thiz->type = TYPE_PTR;
        thiz->clazz = clazz;
        thiz->ttl = ttl;

        if (RET_FAILED(DnsName_Construct(&thiz->data.ptr)))
        {
            LOG_E(TAG, "DnsName_Construct FAILED");
            DnsRecord_Delete(thiz);
            break;
        }

        if (RET_FAILED(DnsName_Copy(&thiz->data.ptr, ptr)))
        {
            LOG_E(TAG, "DnsName_SetString FAILED");
            DnsRecord_Delete(thiz);
            break;
        }
    } while (0);

    return thiz;
}

TINY_LOR
DnsRecord * DnsRecord_NewA(DnsName *name, DnsRecordClass clazz, uint32_t ttl, uint32_t ip)
{
    DnsRecord *thiz = NULL;

    do
    {
        uint8_t *a = (uint8_t *) &ip;

        thiz = DnsRecord_New();
        if (thiz == NULL)
        {
            LOG_E(TAG, "DnsRecord_New FAILED");
            break;
        }

        if (RET_FAILED(DnsName_Copy(&thiz->name, name)))
        {
            LOG_E(TAG, "DnsName_SetString FAILED");
            DnsRecord_Delete(thiz);
            break;
        }

        thiz->type = TYPE_A;
        thiz->clazz = clazz;
        thiz->ttl = ttl;
        thiz->clazz = CLASS_IN;
        tiny_snprintf(thiz->data.a.ip, TINY_IP_LEN, "%d.%d.%d.%d", a[0], a[1], a[2], a[3]);
        thiz->data.a.address = ip;
    } while (0);

    return thiz;
}

TINY_LOR
DnsRecord * DnsRecord_NewSRV(DnsName *name, DnsRecordClass clazz, uint32_t ttl, uint16_t port, DnsName *host)
{
    DnsRecord *thiz = NULL;

    do
    {
        thiz = DnsRecord_New();
        if (thiz == NULL)
        {
            LOG_E(TAG, "DnsRecord_New FAILED");
            break;
        }

        if (RET_FAILED(DnsName_Copy(&thiz->name, name)))
        {
            LOG_E(TAG, "DnsName_SetString FAILED");
            DnsRecord_Delete(thiz);
            break;
        }

        thiz->type = TYPE_SRV;
        thiz->clazz = clazz;
        thiz->ttl = ttl;

        if (RET_FAILED(DnsName_Construct(&thiz->data.srv.name)))
        {
            LOG_E(TAG, "DnsName_Construct FAILED");
            DnsRecord_Delete(thiz);
            break;
        }

        if (RET_FAILED(DnsName_Copy(&thiz->data.srv.name, host)))
        {
            LOG_E(TAG, "DnsName_SetString FAILED");
            DnsRecord_Delete(thiz);
            break;
        }

        thiz->data.srv.priority = 0;
        thiz->data.srv.weight = 0;
        thiz->data.srv.port = port;
    } while (0);

    return thiz;
}

TINY_LOR
DnsRecord * DnsRecord_NewTXT(DnsName *name, DnsRecordClass clazz, uint32_t ttl, TinyMap *txt)
{
    DnsRecord *thiz = NULL;

    LOG_E(TAG, "DnsRecord_NewTXT, count: %d", txt->list.size);

    do
    {
        thiz = DnsRecord_New();
        if (thiz == NULL)
        {
            LOG_E(TAG, "DnsRecord_New FAILED");
            break;
        }

        if (RET_FAILED(DnsName_Copy(&thiz->name, name)))
        {
            LOG_E(TAG, "DnsName_SetString FAILED");
            DnsRecord_Delete(thiz);
            break;
        }

        thiz->type = TYPE_TXT;
        thiz->clazz = clazz;
        thiz->ttl = ttl;

        for (uint32_t i = 0; i < txt->list.size; ++i)
        {
            TinyMapItem *item = TinyList_GetAt(&txt->list, i);

            // contains '='
            size_t itemLength = strlen(item->key) + 1 + strlen(item->value);
            if (itemLength > 255)
            {
                LOG_E(TAG, "Item too long!");
                continue;
            }

            // contains Length
            thiz->data.txt.length += 1 + itemLength;
        }

        thiz->data.txt.value = tiny_malloc(thiz->data.txt.length);
        if (thiz->data.txt.value == NULL)
        {
            LOG_E(TAG, "tiny_malloc FAILED");
            DnsRecord_Delete(thiz);
            break;
        }

        thiz->data.txt.offset = 0;
        for (uint32_t i = 0; i < txt->list.size; ++i)
        {
            TinyMapItem *item = TinyList_GetAt(&txt->list, i);
            size_t keyLength = strlen(item->key);
            size_t valueLength = strlen(item->value);
            thiz->data.txt.value[thiz->data.txt.offset] = (uint8_t) (keyLength + 1 + valueLength);
            thiz->data.txt.value[thiz->data.txt.offset + 1 + keyLength] = '=';
            memcpy(thiz->data.txt.value + thiz->data.txt.offset + 1, item->key, keyLength);
            memcpy(thiz->data.txt.value + thiz->data.txt.offset + 1 + keyLength + 1, item->value, valueLength);

            thiz->data.txt.offset += 2 + keyLength + valueLength;
        }

        LOG_E(TAG, "thiz->data.txt.length: %d", thiz->data.txt.length);
    } while (0);

    return thiz;
}

TINY_LOR
int DnsRecord_Parse(DnsRecord *thiz, const uint8_t *buf, uint32_t len, uint32_t offset)
{
    RETURN_VAL_IF_FAIL(thiz, 0);
    RETURN_VAL_IF_FAIL(buf, 0);
    RETURN_VAL_IF_FAIL(len, 0);

//    LOG_BINARY("resource", buf + offset, len - offset, true);

    uint32_t parsed = DnsName_Parse(&thiz->name, buf, len, offset);
    if (parsed > 0)
    {
        const uint8_t *data = NULL;
        uint16_t dataLength = 0;

        if ((offset + parsed + 10) > len)
        {
            LOG_D(TAG, "INVALID DATA LENGTH: %d", parsed + 10);
            return 0;
        }

#ifdef ESP
        thiz->type = (DnsRecordType) (((uint16_t)(buf[offset + parsed])) << 8) + buf[offset + parsed + 1];
        parsed += 2;

        thiz->clazz = (DnsRecordClass) (((uint16_t)(buf[offset + parsed])) << 8) + buf[offset + parsed + 1];
        thiz->cacheFlush = (thiz->clazz & 0x80) == 0x80;
        parsed += 2;

        thiz->ttl = (((uint32_t)(buf[offset + parsed])) << 24) +
                (((uint32_t)(buf[offset + parsed + 1])) << 16) +
                (((uint32_t)(buf[offset + parsed + 2])) << 8) +
                ((uint32_t)(buf[offset + parsed+ 3]));
        parsed += 4;

        dataLength = (((uint16_t)(buf[offset + parsed])) << 8) + buf[offset + parsed + 1];
        parsed += 2;
#else
        thiz->type = (DnsRecordType) ntohs(*((uint16_t *) (buf + offset + parsed)));
        parsed += 2;

        thiz->clazz = (DnsRecordClass) ntohs(*((uint16_t *) (buf + offset + parsed)));
        thiz->cacheFlush = (thiz->clazz & 0x80) == 0x80;
        parsed += 2;

        thiz->ttl = ntohl(*((uint32_t *) (buf + offset + parsed)));
        parsed += 4;

        dataLength = ntohs(*((uint16_t *) (buf + offset + parsed)));
        parsed += 2;
#endif

#ifdef TINY_DEBUG
        printf("NAME: %s\n", thiz->name.string);
        printf("TYPE: %d = %s\n", thiz->type, DnsRecordType_ToString(thiz->type));
        printf("CLASS: %d (%X) = %s\n", thiz->clazz, thiz->clazz, DnsRecordClass_ToString(thiz->clazz));
        printf("TTL: %d (%X)\n", thiz->ttl, thiz->ttl);
        printf("RDLength: %d (%X)\n", dataLength, dataLength);
#endif

        data = buf + offset + parsed;
        if ((offset + parsed + dataLength) > len)
        {
            LOG_D(TAG, "INVALID DATA LENGTH: %d", dataLength);
            return 0;
        }

//        LOG_BINARY("RDATA", data, dataLength, true);

        switch (thiz->type)
        {
            case TYPE_A:
#ifdef ESP
                thiz->data.a.address = (((uint32_t)(data[0])) << 24) +
                            (((uint32_t)(data[1])) << 16) +
                            (((uint32_t)(data[2])) << 8) +
                            ((uint32_t)(data[3]));
#else
                thiz->data.a.address = ntohl(* ((unsigned int *)data));
#endif
                tiny_snprintf(thiz->data.a.ip, TINY_IP_LEN, "%d.%d.%d.%d", data[0], data[1], data[2], data[3]);

#ifdef TINY_DEBUG
                printf("A: %s\n", thiz->data.a.ip);
#endif
                break;

            case TYPE_NS:
                DnsName_Construct(&thiz->data.ns);
                DnsName_Parse(&thiz->data.ns, buf, len, offset + parsed);
                printf("NS: %s\n", thiz->data.ns.string);
                break;

            case TYPE_CNAME:
            case TYPE_PTR:
                DnsName_Construct(&thiz->data.cname);
                DnsName_Parse(&thiz->data.cname, buf, len, offset + parsed);

#ifdef TINY_DEBUG
                printf("CNAME or PTR: %s\n", thiz->data.cname.string);
#endif
                break;

            case TYPE_TXT:
                thiz->data.txt.length = dataLength;
                if (thiz->data.txt.value != NULL)
                {
                    tiny_free(thiz->data.txt.value);
                }
                thiz->data.txt.value = tiny_malloc(dataLength);
                memcpy(thiz->data.txt.value, buf + offset + parsed, dataLength);
                break;

            case TYPE_SRV:
#ifdef ESP
                thiz->data.srv.priority = (((uint16_t)(data[0])) << 8) + data[1];
                thiz->data.srv.weight = (((uint16_t)(data[2])) << 8) + data[3];
                thiz->data.srv.port = (((uint16_t)(data[4])) << 8) + data[5];
#else
                thiz->data.srv.priority = ntohs(*((uint16_t *) (buf + offset + parsed)));
                thiz->data.srv.weight = ntohs(*((uint16_t *) (buf + offset + parsed + 2)));
                thiz->data.srv.port = ntohs(*((uint16_t *) (buf + offset + parsed + 4)));
#endif
                DnsName_Construct(&thiz->data.srv.name);
                DnsName_Parse(&thiz->data.srv.name, buf, len, offset + parsed + 6);

#ifdef TINY_DEBUG
                printf("SRV: %s\n", thiz->data.srv.name.string);
#endif
                break;

            case TYPE_AAAA:
                // IPv6
                break;

            case TYPE_ANY:
                // TODO ?
                break;
        }

        parsed += dataLength;

#ifdef TINY_DEBUG
                printf("\n");
#endif
    }

    return parsed;
}

TINY_LOR
uint32_t DnsRecord_ToBytes(DnsRecord *thiz, uint8_t *buf, uint32_t length, uint32_t offset)
{
    uint16_t word = 0;
    uint32_t dword = 0;

    /**
     * Name
     */
    uint32_t newOffset = DnsName_ToBytes(&thiz->name, buf, length, offset) + offset;

    /**
     * Type
     */
    word = htons(thiz->type);
    memcpy(buf + newOffset, &word, sizeof(uint16_t));
    newOffset += sizeof(uint16_t);

    /**
     * Class
     */
    word = htons(thiz->clazz);
    memcpy(buf + newOffset, &word, sizeof(uint16_t));
    newOffset += sizeof(uint16_t);

    /**
     * TTL
     */
    dword = htonl(thiz->ttl);
    memcpy(buf + newOffset, &dword, sizeof(uint32_t));
    newOffset += sizeof(uint32_t);

    switch (thiz->type)
    {
        case TYPE_A:
        {
            word = htons(4);
            memcpy(buf + newOffset, &word, sizeof(uint16_t));
            newOffset += sizeof(uint16_t);

            uint32_t a = htonl(thiz->data.a.address);
            memcpy(buf + newOffset, &a, sizeof(uint32_t));
            newOffset += sizeof(uint32_t);
            break;
        }

        case TYPE_NS:
        {
            word = htons((uint16_t) thiz->data.ns.length);
            memcpy(buf + newOffset, &word, sizeof(uint16_t));
            newOffset += sizeof(uint16_t);

            newOffset += DnsName_ToBytes(&thiz->data.ns, buf, length, newOffset);
            break;
        }

        case TYPE_CNAME:
        {
            word = htons((uint16_t) thiz->data.cname.length);
            memcpy(buf + newOffset, &word, sizeof(uint16_t));
            newOffset += sizeof(uint16_t);

            newOffset += DnsName_ToBytes(&thiz->data.cname, buf, length, newOffset);
            break;
        }

        case TYPE_PTR:
        {
            word = htons((uint16_t) thiz->data.ptr.length);
            memcpy(buf + newOffset, &word, sizeof(uint16_t));
            newOffset += sizeof(uint16_t);

            // LOG_E(TAG, "data length: %d", thiz->data.ptr.length);

            newOffset += DnsName_ToBytes(&thiz->data.ptr, buf, length, newOffset);
            break;
        }

        case TYPE_TXT:
        {
            word = htons((uint16_t) thiz->data.txt.length);
            memcpy(buf + newOffset, &word, sizeof(uint16_t));
            newOffset += sizeof(uint16_t);

            memcpy(buf + newOffset, thiz->data.txt.value, thiz->data.txt.length);
            newOffset += thiz->data.txt.length;
            break;
        }

        case TYPE_AAAA:
            break;

        case TYPE_SRV:
        {
            word = htons((uint16_t) (thiz->data.srv.name.length + 6));
            memcpy(buf + newOffset, &word, sizeof(uint16_t));
            newOffset += sizeof(uint16_t);

            word = htons(thiz->data.srv.priority);
            memcpy(buf + newOffset, &word, sizeof(uint16_t));
            newOffset += sizeof(uint16_t);

            word = htons(thiz->data.srv.weight);
            memcpy(buf + newOffset, &word, sizeof(uint16_t));
            newOffset += sizeof(uint16_t);

            word = htons(thiz->data.srv.port);
            memcpy(buf + newOffset, &word, sizeof(uint16_t));
            newOffset += sizeof(uint16_t);

            newOffset += DnsName_ToBytes(&thiz->data.srv.name, buf, length, newOffset);
            break;
        }

        case TYPE_ANY:
            break;
    }

    return newOffset - offset;
}