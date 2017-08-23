/**
 * Copyright (C) 2013-2015
 *
 * @author jxfengzi@gmail.com
 * @date   2013-11-19
 *
 * @file   DnsQuestion.c
 *
 * @remark
 *      set tabstop=4
 *      set shiftwidth=4
 *      set expandtab
 */

#include <tiny_malloc.h>
#include <tiny_inet.h>
#include <tiny_log_binary.h>
#include "DnsQuestion.h"

TINY_LOR
static TinyRet DnsQuestion_Construct(DnsQuestion *thiz)
{
    memset(thiz, 0, sizeof(DnsQuestion));

    DnsName_Construct(&thiz->name);

    return TINY_RET_OK;
}

TINY_LOR
static void DnsQuestion_Dispose(DnsQuestion *thiz)
{
    DnsName_Dispose(&thiz->name);
}

TINY_LOR
DnsQuestion *DnsQuestion_New(void)
{
    DnsQuestion *thiz = NULL;

    do
    {
        thiz = (DnsQuestion *) tiny_malloc(sizeof(DnsQuestion));
        if (thiz == NULL)
        {
            break;
        }

        if (RET_FAILED(DnsQuestion_Construct(thiz)))
        {
            DnsQuestion_Dispose(thiz);
            thiz = NULL;
            break;
        }
    } while (0);

    return thiz;
}

TINY_LOR
void DnsQuestion_Delete(DnsQuestion *thiz)
{
    DnsQuestion_Dispose(thiz);
    tiny_free(thiz);
}

TINY_LOR
int DnsQuestion_Parse(DnsQuestion *thiz, const uint8_t *buf, uint32_t len, uint32_t offset)
{
    RETURN_VAL_IF_FAIL(thiz, 0);
    RETURN_VAL_IF_FAIL(buf, 0);
    RETURN_VAL_IF_FAIL(len, 0);

    //LOG_BINARY("questions", buf + offset, len - offset, true);

    uint32_t parsed = DnsName_Parse(&thiz->name, buf, len, offset);
    if (parsed == 0 || ((offset + parsed + 4) > len))
    {
        return 0;
    }

#ifdef ESP
    thiz->type = (DnsRecordType) (((uint16_t)(buf[offset + parsed])) << 8) + buf[offset + parsed + 1];
    thiz->clazz = (DnsRecordClass) (((uint16_t)(buf[offset + parsed + 2])) << 8) + buf[offset + parsed + 3];
#else
    thiz->type = (DnsRecordType) (ntohs(*((uint16_t *) (buf + offset + parsed))));
    thiz->clazz = (DnsRecordClass) (ntohs(*((uint16_t *) (buf + offset + parsed + 2))));
#endif

    thiz->unicast = ((thiz->clazz & 0x8000) == 0x8000);
    thiz->clazz &= 0x7FFF;
    parsed += 4;

#ifdef TINY_DEBUG
    printf("Q NAME: %s\n", thiz->name.string);
    printf("Q TYPE: %d = %s\n", thiz->type, DnsRecordType_ToString(thiz->type));
    printf("Q UNICAST: %d\n", thiz->unicast);
    printf("Q CLASS: %d (%X) = %s\n\n", thiz->clazz, thiz->clazz, DnsRecordClass_ToString(thiz->clazz));
#endif

    return parsed;
}

TINY_LOR
uint32_t DnsQuestion_ToBytes(DnsQuestion *thiz, uint8_t *buf, uint32_t length, uint32_t offset)
{
    uint32_t newOffset = DnsName_ToBytes(&thiz->name, buf, length, offset) + offset;

    uint16_t v = htons(thiz->type);
    memcpy(buf + newOffset, &v, sizeof(uint16_t));
    newOffset += 2;

    v = htons(thiz->clazz);
    memcpy(buf + newOffset, &v, sizeof(uint16_t));
    newOffset += 2;

    return (newOffset - offset);
}