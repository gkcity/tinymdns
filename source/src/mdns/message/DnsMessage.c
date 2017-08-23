/**
 * Copyright (C) 2013-2015
 *
 * @author jxfengzi@gmail.com
 * @date   2013-11-19
 *
 * @file   DnsMessage.c
 *
 * @remark
 *      set tabstop=4
 *      set shiftwidth=4
 *      set expandtab
 */

#include <tiny_log_binary.h>
#include <tiny_inet.h>
#include <tiny_log.h>
#include <tiny_malloc.h>
#include "DnsMessage.h"
#include "DnsQuestion.h"
#include "DnsRecord.h"

#define TAG     "DnsMessage"

TINY_LOR
static void _OnQuestionDelete(void * data, void *ctx)
{
    DnsQuestion * q = (DnsQuestion *)data;
    DnsQuestion_Delete(q);
}

TINY_LOR
static void _OnResourceDelete(void * data, void *ctx)
{
    DnsRecord * r = (DnsRecord *)data;
    DnsRecord_Delete(r);
}

TINY_LOR
TinyRet DnsMessage_Construct(DnsMessage *thiz)
{
    memset(thiz, 0, sizeof(DnsMessage));

    TinyList_Construct(&thiz->questions);
    TinyList_Construct(&thiz->answers);
    TinyList_Construct(&thiz->authorities);
    TinyList_Construct(&thiz->additionals);

    TinyList_SetDeleteListener(&thiz->questions, _OnQuestionDelete, thiz);
    TinyList_SetDeleteListener(&thiz->answers, _OnResourceDelete, thiz);
    TinyList_SetDeleteListener(&thiz->authorities, _OnResourceDelete, thiz);
    TinyList_SetDeleteListener(&thiz->additionals, _OnResourceDelete, thiz);

    return TINY_RET_OK;
}

TINY_LOR
void DnsMessage_Dispose(DnsMessage *thiz)
{
    TinyList_Dispose(&thiz->questions);
    TinyList_Dispose(&thiz->answers);
    TinyList_Dispose(&thiz->authorities);
    TinyList_Dispose(&thiz->additionals);
}

TINY_LOR
DnsMessage * DnsMessage_New(void)
{
    DnsMessage *thiz = NULL;

    do
    {
        thiz = (DnsMessage *) tiny_malloc(sizeof(DnsMessage));
        if (thiz == NULL)
        {
            break;
        }

        if (RET_FAILED(DnsMessage_Construct(thiz)))
        {
            DnsMessage_Dispose(thiz);
            thiz = NULL;
            break;
        }
    } while (0);

    return thiz;
}

TINY_LOR
void DnsMessage_Delete(DnsMessage *thiz)
{
    DnsMessage_Dispose(thiz);
    tiny_free(thiz);
}

#ifdef TINY_DEBUG
TINY_LOR
static void print_message(DnsMessage *thiz)
{
    printf("ID: %d\n", thiz->header.ID);
    printf("bits: 0x%04X\n", thiz->header.FLAG.value);

    printf("QR: %d", thiz->header.FLAG.bits.QR);
    switch (thiz->header.FLAG.bits.QR)
    {
        case QR_QUERY:
            printf(" QUERY\n");
            break;

        case QR_RESPONSE:
            printf(" RESPONSE\n");
            break;

        default:
            break;
    }

    printf("Opcode: %d", thiz->header.FLAG.bits.Opcode);
    switch (thiz->header.FLAG.bits.Opcode)
    {
        case QPCODE_QUERY:
            printf(" QUERY\n");
            break;

        case QPCODE_IQUERY:
            printf(" IQUERY\n");
            break;

        case QPCODE_STATUS:
            printf(" STATUS\n");
            break;

        case OPCODE_UNASSIGNED:
            printf(" UNASSIGNED\n");
            break;

        case OPCODE_NOTIFY:
            printf(" NOTIFY\n");
            break;

        case OPCODE_UPDATE:
            printf(" UPDATE\n");
            break;

        default:
            printf("\n");
            break;
    }

    printf("AA: %d (Authoritative Answer)\n", thiz->header.FLAG.bits.AA);
    printf("TC: %d (TrunCation)\n", thiz->header.FLAG.bits.TC);
    printf("RD: %d (Recursion Desired)\n", thiz->header.FLAG.bits.RD);
    printf("RA: %d (Recursion Available)\n", thiz->header.FLAG.bits.RA);
    printf("Z: %d (Reserved)\n", thiz->header.FLAG.bits.Z);

    printf("RCODE: %d (Response code) = ", thiz->header.FLAG.bits.RCODE);
    switch (thiz->header.FLAG.bits.RCODE)
    {
        case RCODE_NO_ERROR:
            printf(" NO_ERROR\n");
            break;

        case RCODE_FORMAT_ERROR:
            printf(" FORMAT_ERROR\n");
            break;

        case RCODE_SERVER_FAILURE:
            printf(" SERVER_FAILURE\n");
            break;

        case RCODE_NAME_ERROR:
            printf(" NAME_ERROR\n");
            break;

        case RCODE_NOT_IMPLEMENTED:
            printf(" NOT_IMPLEMENTED\n");
            break;

        case RCODE_REFUSED:
            printf(" REFUSED\n");
            break;

        default:
            printf("\n");
            break;
    }

    printf("QDCOUNT: %d (questions)\n", thiz->header.QDCOUNT);
    printf("ANCOUNT: %d (answers)\n", thiz->header.ANCOUNT);
    printf("NSCOUNT: %d (name server resource records)\n", thiz->header.NSCOUNT);
    printf("ARCOUNT: %d (additional resource records)\n", thiz->header.ARCOUNT);
}
#endif

TINY_LOR
static TinyRet DnsMessage_ParseDnsQuestion(DnsMessage *thiz, const void *buf, uint32_t len, uint32_t *offset, TinyList *list, int count)
{
    for (int i = 0; i < count; ++i)
    {
        int size = 0;

#ifdef TINY_DEBUG
        printf("[%d]\n", i);
#endif

        DnsQuestion * question = DnsQuestion_New();
        if (question == NULL)
        {
            LOG_E(TAG, "DnsQuestion_New FAILED");
            return TINY_RET_E_NEW;
        }

        size = DnsQuestion_Parse(question, buf, len, *offset);
        if (size == 0)
        {
            LOG_E(TAG, "DnsQuestion_Parse FAILED");
            DnsQuestion_Delete(question);
            return TINY_RET_E_INTERNAL;
        }

        if (question->unicast)
        {
            thiz->unicast = true;
        }

        if (RET_FAILED(TinyList_AddTail(list, question)))
        {
            LOG_E(TAG, "TinyList_AddTail FAILED");
            break;
        }

        *offset += size;
    }

    return TINY_RET_OK;
}

#ifdef MDNS_DISCOVERY
TINY_LOR
static TinyRet DnsMessage_ParseDnsRecord(DnsMessage *thiz, const void *buf, uint32_t len, uint32_t *index, TinyList *list, int count)
{
    for (int i = 0; i < count; ++i)
    {
        int size = 0;

#ifdef TINY_DEBUG
        printf("[%d]\n", i);
#endif

        DnsRecord *resource = DnsRecord_New();
        if (resource == NULL)
        {
            LOG_E(TAG, "DnsRecord_New FAILED");
            return TINY_RET_E_NEW;
        }

        size = DnsRecord_Parse(resource, buf, len, *index);
        if (size == 0)
        {
            LOG_E(TAG, "DnsRecord_Parse FAILED");
            DnsRecord_Delete(resource);
            return TINY_RET_E_INTERNAL;
        }

        TinyList_AddTail(list, resource);

        *index += size;
    }

    return TINY_RET_OK;
}
#endif

TINY_LOR
TinyRet DnsMessage_Parse(DnsMessage *thiz, const void *buf, uint32_t len)
{
    TinyRet ret = TINY_RET_OK;
    uint32_t offset = sizeof(Header);

    LOG_BINARY("DnsMessage", buf, len, true);

    memcpy(&thiz->header, buf, sizeof(Header));
    thiz->header.ID = ntohs(thiz->header.ID);
    thiz->header.FLAG.value = ntohs(thiz->header.FLAG.value);
    thiz->header.QDCOUNT = ntohs(thiz->header.QDCOUNT);
    thiz->header.ANCOUNT = ntohs(thiz->header.ANCOUNT);
    thiz->header.NSCOUNT = ntohs(thiz->header.NSCOUNT);
    thiz->header.ARCOUNT = ntohs(thiz->header.ARCOUNT);

#ifdef TINY_DEBUG
    print_message(thiz);
#endif

    ret = DnsMessage_ParseDnsQuestion(thiz, buf, len, &offset, &thiz->questions, thiz->header.QDCOUNT);
    if (RET_FAILED(ret))
    {
        LOG_D(TAG, "DnsMessage_ParseDnsQuestion failed: %d", ret);
        return ret;
    }

#ifdef MDNS_DISCOVERY
    ret = DnsMessage_ParseDnsRecord(thiz, buf, len, &offset, &thiz->answers, thiz->header.ANCOUNT);
    if (RET_FAILED(ret))
    {
        LOG_D(TAG, "DnsMessage_ParseDnsRecord failed: %d", ret);
        return ret;
    }
#endif

#if 0
    ret = DnsMessage_ParseDnsRecord(thiz, buf, len, &offset, &thiz->authorities, thiz->header.NSCOUNT);
    if (RET_FAILED(ret))
    {
        return ret;
    }

    ret = DnsMessage_ParseDnsRecord(thiz, buf, len, &offset, &thiz->additionals, thiz->header.ARCOUNT);
    if (RET_FAILED(ret))
    {
        return ret;
    }
#endif

    return TINY_RET_OK;
}

TINY_LOR
uint32_t DnsMessage_ToBytes(DnsMessage *thiz, uint8_t *buf, uint32_t length, uint32_t offset)
{
    Header header;

    RETURN_VAL_IF_FAIL(thiz, 0);
    RETURN_VAL_IF_FAIL(buf, 0);
    RETURN_VAL_IF_FAIL(length, 0);

    header.FLAG.value = htons(thiz->header.FLAG.value);
    header.ID = htons(thiz->header.ID);
    header.QDCOUNT = htons((uint16_t) thiz->questions.size);
    header.ANCOUNT = htons((uint16_t) thiz->answers.size);
    header.NSCOUNT = htons((uint16_t) thiz->authorities.size);
    header.ARCOUNT = htons((uint16_t) thiz->additionals.size);

    memcpy(buf + offset, &header, sizeof(Header));
    offset += sizeof(Header);

    for (uint32_t i = 0; i < thiz->questions.size; ++i)
    {
        offset += DnsQuestion_ToBytes((DnsQuestion *) TinyList_GetAt(&thiz->questions, i), buf, length, offset);
    }

    for (uint32_t i = 0; i < thiz->answers.size; ++i)
    {
        offset += DnsRecord_ToBytes((DnsRecord *) TinyList_GetAt(&thiz->answers, i), buf, length, offset);
    }

    for (uint32_t i = 0; i < thiz->authorities.size; ++i)
    {
        offset += DnsRecord_ToBytes((DnsRecord *) TinyList_GetAt(&thiz->authorities, i), buf, length, offset);
    }

    for (uint32_t i = 0; i < thiz->additionals.size; ++i)
    {
        offset += DnsRecord_ToBytes((DnsRecord *) TinyList_GetAt(&thiz->additionals, i), buf, length, offset);
    }

    return offset;
}