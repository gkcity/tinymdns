/**
 * Copyright (C) 2013-2015
 *
 * @author jxfengzi@gmail.com
 * @date   2013-11-19
 *
 * @file   MdnsHandlerContext.c
 *
 * @remark
 *      set tabstop=4
 *      set shiftwidth=4
 *      set expandtab
 */

#include <tiny_malloc.h>
#include <tiny_inet.h>
#include <tiny_log.h>
#include <message/DnsRecord.h>
#include <message/DnsQuestion.h>
#include "MdnsHandlerContext.h"

#ifdef MDNS_DISCOVERY
#include "ServiceObserver.h"
#endif

#define TAG             "MdnsHandlerContext"
#define DEFAULT_TTL     120

TINY_LOR
static void _OnRecordDelete(void * data, void *ctx)
{
    DnsRecord_Delete((DnsRecord *)data);
}

#ifdef MDNS_DISCOVERY
TINY_LOR
static void _OnObserverDelete(void * data, void *ctx)
{
    ServiceObserver_Delete((ServiceObserver *)data);
}
#endif

TINY_LOR
MdnsHandlerContext * MdnsHandlerContext_New()
{
    MdnsHandlerContext *thiz = NULL;

    do
    {
        thiz = tiny_malloc(sizeof(MdnsHandlerContext));
        if (thiz == NULL)
        {
            LOG_E(TAG, "tiny_malloc failed!");
            break;
        }

        if (RET_FAILED(MdnsHandlerContext_Construct(thiz)))
        {
            LOG_E(TAG, "MdnsHandlerContext_Construct failed!\n");
            MdnsHandlerContext_Delete(thiz);
            thiz = NULL;
            break;
        }
    } while (0);

    return thiz;
}

TINY_LOR
TinyRet MdnsHandlerContext_Construct(MdnsHandlerContext *thiz)
{
    memset(thiz, 0, sizeof(MdnsHandlerContext));

    TinyList_Construct(&thiz->dnssdRecords);
    TinyList_SetDeleteListener(&thiz->dnssdRecords, _OnRecordDelete, thiz);

    TinyList_Construct(&thiz->aRecords);
    TinyList_SetDeleteListener(&thiz->aRecords, _OnRecordDelete, thiz);

    TinyList_Construct(&thiz->ptrRecords);
    TinyList_SetDeleteListener(&thiz->ptrRecords, _OnRecordDelete, thiz);

    TinyList_Construct(&thiz->srvRecords);
    TinyList_SetDeleteListener(&thiz->srvRecords, _OnRecordDelete, thiz);

    TinyList_Construct(&thiz->txtRecords);
    TinyList_SetDeleteListener(&thiz->txtRecords, _OnRecordDelete, thiz);

    thiz->ttl = DEFAULT_TTL;

#ifdef MDNS_DISCOVERY
    TinyList_Construct(&thiz->observers);
    TinyList_SetDeleteListener(&thiz->observers, _OnObserverDelete, thiz);
#endif

    return TINY_RET_OK;
}

TINY_LOR
void MdnsHandlerContext_Dispose(MdnsHandlerContext *thiz)
{
    TinyList_Dispose(&thiz->dnssdRecords);
    TinyList_Dispose(&thiz->aRecords);
    TinyList_Dispose(&thiz->ptrRecords);
    TinyList_Dispose(&thiz->srvRecords);
    TinyList_Dispose(&thiz->txtRecords);

#ifdef MDNS_DISCOVERY
    TinyList_Dispose(&thiz->observers);
#endif

    RETURN_IF_FAIL(thiz);
}

TINY_LOR
void MdnsHandlerContext_Delete(MdnsHandlerContext *thiz)
{
    MdnsHandlerContext_Dispose(thiz);
    tiny_free(thiz);
}

TINY_LOR
TinyRet MdnsHandlerContext_Register(MdnsHandlerContext *thiz, const ServiceInfo *info)
{
    TinyRet ret = TINY_RET_OK;

    DnsName host;
    DnsName revHost;
    DnsName serviceHost;
    DnsName serviceInstance;
    DnsName serviceType;
    DnsName serviceDnssd;

    RETURN_VAL_IF_FAIL(thiz, TINY_RET_E_ARG_NULL);
    RETURN_VAL_IF_FAIL(info, TINY_RET_E_ARG_NULL);

    do
    {
        DnsRecord *record = NULL;
        uint32_t ip = ntohl(inet_addr(info->ip));

        DnsName_Construct(&host);
        DnsName_Construct(&revHost);
        DnsName_Construct(&serviceHost);
        DnsName_Construct(&serviceInstance);
        DnsName_Construct(&serviceType);
        DnsName_Construct(&serviceDnssd);

        DnsName_InitializeHost(&host, info->name);
        DnsName_InitializeReverseIpv4Host(&revHost, ip);
        DnsName_InitializeServiceHost(&serviceHost, "ouyang");
        DnsName_InitializeServiceInstance(&serviceInstance, info->name, info->type);
        DnsName_InitializeServiceType(&serviceType, info->type);
        DnsName_InitializeServiceDnssd(&serviceDnssd);

        /**
         * IPV4 (A)
         *      NAME: .ouyangmbp.local
         *      A: 10.0.1.9
         */
        record = DnsRecord_NewA(&serviceHost, CLASS_IN, 120, ip);
        if (record != NULL)
        {
            ret = TinyList_AddTail(&thiz->aRecords, record);
            if (RET_FAILED(ret))
            {
                break;
            }
        }

        /**
         * IPV4 (PTR) 4.3.2.1.in-addr.arpa -> hostname.local
         *      NAME: ?
         *      PTR: ?
         */
        record = DnsRecord_NewPTR(&revHost, CLASS_IN, 120, &host);
        if (record != NULL)
        {
            ret = TinyList_AddTail(&thiz->ptrRecords, record);
            if (RET_FAILED(ret))
            {
                break;
            }
        }

        /**
         * All Service (PTR)
         *      NAME: ._services._dns-sd._udp.local
         *      PTR: ._airplay._tcp.local
         */
        record = DnsRecord_NewPTR(&serviceDnssd, CLASS_IN, 120, &serviceType);
        if (record != NULL)
        {
            ret = TinyList_AddTail(&thiz->dnssdRecords, record);
            if (RET_FAILED(ret))
            {
                break;
            }
        }

        /**
         * Service Type (PTR)
         *      NAME: ._airplay._tcp.local
         *      PTR: .ouyang._airplay._tcp.local
         */
        record = DnsRecord_NewPTR(&serviceType, CLASS_IN, 120, &serviceInstance);
        if (record != NULL)
        {
            ret = TinyList_AddTail(&thiz->ptrRecords, record);
            if (RET_FAILED(ret))
            {
                break;
            }
        }

        /**
         * (SRV)
         *      NAME: .ouyang._airplay._tcp.local
         *      SRV: .ouyangmbp.local
         */
        record = DnsRecord_NewSRV(&serviceInstance, CLASS_IN, 120, info->port, &serviceHost);
        if (record != NULL)
        {
            ret = TinyList_AddTail(&thiz->srvRecords, record);
            if (RET_FAILED(ret))
            {
                break;
            }
        }

        /**
         * (TXT)
         *      NAME: .ouyang._airplay._tcp.local
         *      TXT: a=b
         */
        if (info->txt.list.size > 0)
        {
            record = DnsRecord_NewTXT(&serviceInstance, CLASS_IN, 120, &(info->txt));
            if (record != NULL)
            {
                ret = TinyList_AddTail(&thiz->txtRecords, record);
                if (RET_FAILED(ret))
                {
                    break;
                }
            }

//            uint8_t buf[1024];
//            uint32_t length = DnsRecord_ToBytes(record, buf, 1024, 0);
//            LOG_E(TAG, "TXT LENGTH: %d", length);
//            if (length > 0)
//            {
//                DnsRecord t;
//
//                DnsRecord_Construct(&t);
//                DnsRecord_Parse(&t, buf, length, 0);
//                DnsRecord_Dispose(&t);
//            }
        }
    } while (0);

    DnsName_Dispose(&host);
    DnsName_Dispose(&revHost);
    DnsName_Dispose(&serviceHost);
    DnsName_Dispose(&serviceInstance);
    DnsName_Dispose(&serviceType);
    DnsName_Dispose(&serviceDnssd);

    return ret;
}

/**
 * Offline Advertisement: send answer that contains TTL(0) 3 times
 *
 * NAME: ._hap._tcp.local
 * TYPE: 12 = PTR
 * CLASS: 1 (1) = IN
 * TTL: 0 (0)
 * RDLength: 12 (C)
 * CNAME or PTR: .XiaomiFan._hap._tcp.local
 */
TINY_LOR
TinyRet MdnsHandlerContext_Unregister(MdnsHandlerContext *thiz, const ServiceInfo *info)
{
    return TINY_RET_E_NOT_IMPLEMENTED;
}

TINY_LOR
static void MdnsHandlerContext_AddAnswer(DnsMessage *response, DnsRecord *record, uint32_t ttl)
{
    DnsRecord *copy = DnsRecord_New();
    if (copy == NULL)
    {
        LOG_E(TAG, "DnsRecord_New FAILED");
        return;
    }

    if (RET_FAILED(DnsRecord_Copy(copy, record)))
    {
        LOG_E(TAG, "DnsRecord_Copy FAILED");
        return;
    }

    copy->ttl = ttl;

    TinyList_AddTail(&response->answers, copy);
}

TINY_LOR
static void MdnsHandlerContext_AddRecord(DnsMessage *response,
                                         TinyList *records,
                                         DnsRecordType type,
                                         uint32_t ttl,
                                         const char *name,
                                         bool fullName)
{
    LOG_D(TAG, "MdnsHandlerContext_AddRecord: %s", DnsRecordType_ToString(type));

    for (uint32_t i = 0; i < records->size; ++i)
    {
        DnsRecord *record = (DnsRecord *) TinyList_GetAt(records, i);
        LOG_D(TAG, "record: %s %s", record->name.string, DnsRecordType_ToString(record->type));

        if (name == NULL)
        {
            LOG_D(TAG, "DnsRecord FOUND!");
            MdnsHandlerContext_AddAnswer(response, record, ttl);
        }
        else
        {
            const char *value = record->name.string;

            if (! fullName)
            {
                value += 1 + (uint8_t) record->name.bytes[0];
            }

            if (STR_EQUAL(value, name))
            {
                LOG_D(TAG, "DnsRecord FOUND!");
                MdnsHandlerContext_AddAnswer(response, record, ttl);
            }
        }
    }
}

/**
 *

1. Query DNSSD serviceH
[0]
Q NAME: ._services._dns-sd._udp.local
Q TYPE: 12 = PTR
Q UNICAST: 0
Q CLASS: 1 (1) = IN

2. Response

[2]
NAME: ._services._dns-sd._udp.local
TYPE: 12 = PTR
CLASS: 1 (1) = IN
TTL: 4500 (1194)
RDLength: 7 (7)
CNAME or PTR: ._hap._tcp.local

3. Continue Query ._hap._tcp.local 服务

[0]
Q NAME: ._hap._tcp.local
Q TYPE: 33 = SRV
Q UNICAST: 0
Q CLASS: 1 (1) = IN

4. Response
[0]
NAME: .XiaomiFan._hap._tcp.local
TYPE: 16 = TXT
CLASS: 32769 (8001) = FLUSH_IN
TTL: 4500 (1194)
RDLength: 59 (3B)

[1]
NAME: ._services._dns-sd._udp.local
TYPE: 12 = PTR
CLASS: 1 (1) = IN
TTL: 4500 (1194)
RDLength: 2 (2)
CNAME or PTR: ._hap._tcp.local

[2]
NAME: ._hap._tcp.local
TYPE: 12 = PTR
CLASS: 1 (1) = IN
TTL: 4500 (1194)
RDLength: 2 (2)
CNAME or PTR: .XiaomiFan._hap._tcp.local

[3]
NAME: .XiaomiFan._hap._tcp.local
TYPE: 33 = SRV
CLASS: 32769 (8001) = FLUSH_IN
TTL: 120 (78)
RDLength: 18 (12)
SRV: .ouyangmbp.local
 */
TINY_LOR
static void MdnsHandlerContext_Query(MdnsHandlerContext *thiz, DnsQuestion *question, DnsMessage *response)
{
    if (question->clazz == CLASS_IN || question->clazz == CLASS_ANY)
    {

#if 0
        switch (question->type)
        {
            case TYPE_A:
                MdnsHandlerContext_AddRecord(response, &thiz->aRecords, question->type, question->name.string, true);
                break;

            case TYPE_PTR:
                MdnsHandlerContext_AddRecord(response, &thiz->dnssdRecords, question->type, question->name.string, true);
                MdnsHandlerContext_AddRecord(response, &thiz->ptrRecords, question->type, question->name.string, true);
                break;

            case TYPE_TXT:
                MdnsHandlerContext_AddRecord(response, &thiz->txtRecords, question->type, question->name.string, true);
                break;

            case TYPE_SRV:
                MdnsHandlerContext_AddRecord(response, &thiz->txtRecords, question->type, question->name.string, false);
                MdnsHandlerContext_AddRecord(response, &thiz->dnssdRecords, question->type, NULL, false);
                MdnsHandlerContext_AddRecord(response, &thiz->ptrRecords, question->type, question->name.string, true);
                MdnsHandlerContext_AddRecord(response, &thiz->srvRecords, question->type, question->name.string, false);
                break;

            case TYPE_ANY:
                MdnsHandlerContext_AddRecord(response, &thiz->aRecords, question->type, NULL, false);
                MdnsHandlerContext_AddRecord(response, &thiz->dnssdRecords, question->type, NULL, false);
                MdnsHandlerContext_AddRecord(response, &thiz->ptrRecords, question->type, NULL, false);
                MdnsHandlerContext_AddRecord(response, &thiz->txtRecords, question->type, NULL, false);
                MdnsHandlerContext_AddRecord(response, &thiz->srvRecords, question->type, NULL, false);
                break;

            default:
                break;
        }
#else
        MdnsHandlerContext_AddRecord(response, &thiz->aRecords, question->type, thiz->ttl, NULL, false);
        MdnsHandlerContext_AddRecord(response, &thiz->dnssdRecords, question->type, thiz->ttl, NULL, false);
        MdnsHandlerContext_AddRecord(response, &thiz->ptrRecords, question->type, thiz->ttl, NULL, false);
        MdnsHandlerContext_AddRecord(response, &thiz->txtRecords, question->type, thiz->ttl, NULL, false);
        MdnsHandlerContext_AddRecord(response, &thiz->srvRecords, question->type, thiz->ttl, NULL, false);
#endif
    }
}

TINY_LOR
DnsMessage * MdnsHandlerContext_MakeResponse(MdnsHandlerContext *thiz, DnsMessage *request)
{
    DnsMessage *response = NULL;

    RETURN_VAL_IF_FAIL(thiz, NULL);

    LOG_D(TAG, "MdnsHandlerContext_MakeResponse");

    do
    {
        response = DnsMessage_New();
        if (response == NULL)
        {
            break;
        }

        response->header.ID = (request != NULL) ? request->header.ID : (uint16_t)0;
        response->header.FLAG.bits.QR = QR_RESPONSE;
        response->header.FLAG.bits.AA = 1;

        if (request != NULL)
        {
            for (uint32_t i = 0; i < request->questions.size; ++i)
            {
                DnsQuestion *question = (DnsQuestion *)TinyList_GetAt(&request->questions, i);
                //printf("[question %d] %s %d %d\n", i, question->name.string, question->type, question->clazz);

                MdnsHandlerContext_Query(thiz, question, response);

                // only 1 response
                break;
            }

            // remove our replies if they were already in their answers

            // see if we can match additional records for answers

            // additional records for additional records
        }
        else
        {
            MdnsHandlerContext_AddRecord(response, &thiz->aRecords, TYPE_A, 0, NULL, false);
            MdnsHandlerContext_AddRecord(response, &thiz->dnssdRecords, TYPE_PTR, 0, NULL, false);
            MdnsHandlerContext_AddRecord(response, &thiz->ptrRecords, TYPE_PTR, 0, NULL, false);
            MdnsHandlerContext_AddRecord(response, &thiz->txtRecords, TYPE_TXT, 0, NULL, false);
            MdnsHandlerContext_AddRecord(response, &thiz->srvRecords, TYPE_SRV, 0, NULL, false);
        }

        if (response->answers.size == 0)
        {
            DnsMessage_Delete(response);
            response = NULL;
        }
    } while (0);

    return response;
}

TINY_LOR
DnsMessage * MdnsHandlerContext_MakeRequest(MdnsHandlerContext *thiz)
{
    DnsMessage *request = NULL;

    RETURN_VAL_IF_FAIL(thiz, NULL);

#ifdef MDNS_DISCOVERY
    do
    {
        if (thiz->observers.size == 0)
        {
            break;
        }

        request = DnsMessage_New();
        if (request == NULL)
        {
            break;
        }

        LOG_E(TAG, "MdnsHandlerContext_MakeRequest");

        request->header.ID = 0;
        request->header.FLAG.bits.QR = QR_QUERY;

        for (uint32_t i = 0; i < thiz->observers.size; ++i)
        {
            ServiceObserver * oo = (ServiceObserver *) TinyList_GetAt(&thiz->observers, i);
            DnsQuestion *question = DnsQuestion_New();

            if (question == NULL)
            {
                LOG_E(TAG, "DnsQuestion_New FAILED!");
                continue;
            }

            LOG_D(TAG, "ServiceObserver: %s", oo->type);

            question->type = TYPE_PTR;
            question->clazz = CLASS_IN;

            DnsName_InitializeServiceDnssd(&question->name);

            TinyList_AddTail(&request->questions, question);
        }

        request->header.QDCOUNT = (uint16_t) request->questions.size;
    } while (0);
#endif

    return request;
}

#ifdef MDNS_DISCOVERY
TINY_LOR
static DnsQuestion * MdnsHandlerContext_CreateQuestion(MdnsHandlerContext *thiz, DnsRecord *answer)
{
    RETURN_VAL_IF_FAIL(thiz, NULL);
    RETURN_VAL_IF_FAIL(answer, NULL);

    LOG_E(TAG, "MdnsHandlerContext_CreateQuestion");

    if (DnsName_IsServiceDnssd(&answer->name) && answer->type == TYPE_PTR && answer->clazz == CLASS_IN)
    {
        for (uint32_t i = 0; i < thiz->observers.size; ++i)
        {
            ServiceObserver * oo = (ServiceObserver *) TinyList_GetAt(&thiz->observers, i);

            if (STR_EQUAL(answer->data.ptr.string, oo->type))
            {
                DnsQuestion *question = DnsQuestion_New();
                if (question == NULL)
                {
                    LOG_E(TAG, "DnsQuestion_New FAILED!");
                    return NULL;
                }

                question->type = TYPE_SRV;
                question->clazz = CLASS_IN;
                DnsName_InitializeServiceType(&question->name, oo->type);

                return question;
            }
        }
    }

    return NULL;
}
#endif

TINY_LOR
DnsMessage * MdnsHandlerContext_MakeRequestByAnswers(MdnsHandlerContext *thiz,  TinyList *answers)
{
    DnsMessage *request = NULL;

    RETURN_VAL_IF_FAIL(thiz, NULL);
    RETURN_VAL_IF_FAIL(answers, NULL);

#ifdef MDNS_DISCOVERY
    do
    {
        if (thiz->observers.size == 0)
        {
            break;
        }

        request = DnsMessage_New();
        if (request == NULL)
        {
            break;
        }

        LOG_E(TAG, "MdnsHandlerContext_MakeRequestByAnswers");

        request->header.ID = 0;
        request->header.FLAG.bits.QR = QR_QUERY;

        for (uint32_t i = 0; i < answers->size; ++i)
        {
            DnsRecord *answer = (DnsRecord *)TinyList_GetAt(answers, i);
            LOG_I(TAG, "Answer[%d] %s %s %s ttl:%d", i, answer->name.string, DnsRecordType_ToString(answer->type),
                  DnsRecordClass_ToString(answer->clazz), answer->ttl);

            DnsQuestion *question = MdnsHandlerContext_CreateQuestion(thiz, answer);
            if (question != NULL)
            {
                TinyList_AddTail(&request->questions, question);
            }
        }

        request->header.QDCOUNT = (uint16_t) request->questions.size;

        if (request->header.QDCOUNT == 0)
        {
            DnsMessage_Delete(request);
            request = NULL;
        }
    } while (0);
#endif

    return request;
}
