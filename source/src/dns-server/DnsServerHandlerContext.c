/**
 * Copyright (C) 2013-2015
 *
 * @author jxfengzi@gmail.com
 * @date   2013-11-19
 *
 * @file   DnsServerHandlerContext.c
 *
 * @remark
 *      set tabstop=4
 *      set shiftwidth=4
 *      set expandtab
 */

#include <tiny_log.h>
#include <tiny_malloc.h>
#include <message/DnsQuestion.h>
#include <message/DnsRecord.h>
#include "DnsServerHandlerContext.h"
#include "DnsConstant.h"

#define TAG             "DnsServerHandlerContext"

TINY_LOR
DnsServerHandlerContext * DnsServerHandlerContext_New(uint32_t ip)
{
    DnsServerHandlerContext *thiz = NULL;

    do
    {
        thiz = tiny_malloc(sizeof(DnsServerHandlerContext));
        if (thiz == NULL)
        {
            LOG_E(TAG, "tiny_malloc failed!");
            break;
        }

        if (RET_FAILED(DnsServerHandlerContext_Construct(thiz, ip)))
        {
            LOG_E(TAG, "DnsServerHandlerContext_Construct failed!\n");
            DnsServerHandlerContext_Delete(thiz);
            thiz = NULL;
            break;
        }
    } while (0);

    return thiz;
}

TINY_LOR
TinyRet DnsServerHandlerContext_Construct(DnsServerHandlerContext *thiz, uint32_t ip)
{
    memset(thiz, 0, sizeof(DnsServerHandlerContext));
    thiz->ip = ip;

    return TINY_RET_OK;
}

TINY_LOR
void DnsServerHandlerContext_Dispose(DnsServerHandlerContext *thiz)
{

}

TINY_LOR
void DnsServerHandlerContext_Delete(DnsServerHandlerContext *thiz)
{
    DnsServerHandlerContext_Dispose(thiz);
    tiny_free(thiz);
}

static void replyWithIP(DnsServerHandlerContext *thiz, DnsMessage *response, DnsQuestion *question)
{
    LOG_I(TAG, "replyWithIP: %s", question->name.string);

    do
    {
        DnsRecord *record = DnsRecord_NewA(&question->name, CLASS_IN, 60, thiz->ip);
        if (record == NULL)
        {
            break;
        }

        if (RET_FAILED(TinyList_AddTail(&response->answers, record)))
        {
            LOG_E(TAG, "DnsRecord_New FAILED");
            DnsRecord_Delete(record);
            break;
        }
    } while (false);
}

static void replyWithNonExistentDomain(DnsServerHandlerContext *thiz, DnsMessage *response)
{
    LOG_I(TAG, "replyWithNonExistentDomain");

    response->header.FLAG.bits.RCODE = RCODE_NAME_ERROR;
}

#if 0
static void addTypeNS(DnsServerHandlerContext *thiz, DnsMessage *response, DnsQuestion *question)
{
    do
    {
        DnsRecord *record = DnsRecord_NewNS(&question->name, CLASS_IN, 0, "ns");
        if (record == NULL)
        {
            break;
        }

        if (RET_FAILED(TinyList_AddTail(&response->answers, record)))
        {
            LOG_E(TAG, "DnsRecord_New FAILED");
            DnsRecord_Delete(record);
            break;
        }
    } while (false);
}

static void addTypeURI(DnsServerHandlerContext *thiz, DnsMessage *response, DnsQuestion *question)
{
    do
    {
        DnsRecord *record = DnsRecord_NewURI(&question->name, CLASS_URI, 0, "http://esp.nonet");
        if (record == NULL)
        {
            break;
        }

        if (RET_FAILED(TinyList_AddTail(&response->answers, record)))
        {
            LOG_E(TAG, "DnsRecord_New FAILED");
            DnsRecord_Delete(record);
            break;
        }
    } while (false);
}
#endif

TINY_LOR
DnsMessage * DnsServerHandlerContext_MakeResponse(DnsServerHandlerContext *thiz, DnsMessage *request)
{
    DnsMessage *response = NULL;

    RETURN_VAL_IF_FAIL(request, NULL);

    LOG_D(TAG, "DnsServerHandlerContext_MakeResponse");

    do
    {
        if (request == NULL)
        {
            break;
        }

        response = DnsMessage_New();
        if (response == NULL)
        {
            break;
        }

        response->header.ID = request->header.ID;
        response->header.FLAG.bits.QR = QR_RESPONSE;
        response->header.FLAG.bits.AA = 1;

        if (request->questions.size == 1)
        {
            DnsQuestion *question = (DnsQuestion *)TinyList_GetAt(&request->questions, 0);
            replyWithIP(thiz, response, question);
        }
        else
        {
            replyWithNonExistentDomain(thiz, response);
        }

//        for (uint32_t i = 0; i < request->questions.size; ++i)
//        {
//            DnsQuestion *question = (DnsQuestion *)TinyList_GetAt(&request->questions, i);
//            printf("[question %d] %s %d %d\n", i, question->name.string, question->type, question->clazz);
//
//            switch (question->type)
//            {
//                case TYPE_A:
//                    replyWithIP(thiz, response, question);
//                    break;
//
//                default:
//                    replyWithCustomCode(thiz, response, question);
//                    break;
//            }
//        }
//
//        if (response->answers.size == 0)
//        {
//            DnsMessage_Delete(response);
//            response = NULL;
//        }
    } while (0);

    return response;
}
