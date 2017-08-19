/**
 * Copyright (C) 2013-2015
 *
 * @author jxfengzi@gmail.com
 * @date   2013-11-19
 *
 * @file   DnsTypedef.c
 *
 * @remark
 *      set tabstop=4
 *      set shiftwidth=4
 *      set expandtab
 */

#include "DnsTypedef.h"

#ifdef TINY_DEBUG
TINY_LOR
const char * DnsRecordType_ToString(DnsRecordType v)
{
    switch (v)
    {
        case TYPE_A:
            return "A";

        case TYPE_NS:
            return "NS";

        case TYPE_CNAME:
            return "CNAME";

        case TYPE_PTR:
            return "PTR";

        case TYPE_TXT:
            return "TXT";

        case TYPE_AAAA:
            return "AAAA";

        case TYPE_SRV:
            return "SRV";

        case TYPE_ANY:
            return "ANY";

        default:
            return "UNKNOWN";
    }
}

TINY_LOR
const char * DnsRecordClass_ToString(DnsRecordClass v)
{
    switch (v)
    {
        case CLASS_IN:
            return "IN";

        case CLASS_CS:
            return "CS";

        case CLASS_CH:
            return "CH";

        case CLASS_HS:
            return "HS";

        case CLASS_FLUSH:
            return "FLUSH";

        case CLASS_FLUSH_IN:
            return "FLUSH_IN";

        case CLASS_NONE:
            return "NONE";

        case CLASS_ANY:
            return "ANY";

        default:
            return "UNKNOWN";
    }
}
#endif