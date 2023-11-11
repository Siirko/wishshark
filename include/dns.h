#pragma once
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct dnshdr
{
    uint16_t transactionID;
#if (BYTE_ORDER == LITTLE_ENDIAN)
    uint16_t recursion_desired : 1, truncation : 1, authoritative_answer : 1, opcode : 4, query_or_response : 1,
        response_code : 4, checking_disabled : 1, authentic_data : 1, zero : 1, recursion_available : 1;
#elif (BYTE_ORDER == BIG_ENDIAN)
    uint16_t query_or_response : 1, opcode : 4, authoritative_answer : 1, truncation : 1, recursion_desired : 1,
        recursion_available : 1, zero : 1, authentic_data : 1, checking_disabled : 1, response_code : 4;
#endif

    uint16_t n_questions;
    uint16_t n_answers;
    uint16_t n_authority;
    uint16_t n_additional;
};

struct __attribute__((__packed__)) dnsquery
{
    uint16_t type;
    uint16_t class;
};

struct __attribute__((__packed__)) dnsanswer
{
    uint16_t name;
    struct dnsquery query;
    uint32_t ttl;
    uint16_t rdlength;
};

#define DNS_IS_COMPRESSED(x) (((x) & (0xc000)) == (0xc000))
#define DNS_RESOLVE_OFFSET(x) ((x) & 0x3fff)

#define DNS_TYPE_A 1
#define DNS_TYPE_NS 2
#define DNS_TYPE_CNAME 5
#define DNS_TYPE_SOA 6
#define DNS_TYPE_PTR 12
#define DNS_TYPE_TXT 16
#define DNS_TYPE_AAAA 28

static inline uint16_t dns_compression_resolve(u_char *rdata, uint16_t rdlength, char *dns_header)
{
    uint16_t new_rdata_len = rdlength;
    for (int i = 0; i < rdlength; i++)
    {
        if (rdata[i] == 0xc0)
        {
            uint16_t offset = ntohs(*((uint16_t *)(rdata + i))) & 0x3fff;
            u_char *name;
            int name_len = asprintf((char **)&name, "%s", (u_char *)dns_header + offset);
            new_rdata_len += name_len - 2;
            rdata = realloc(rdata, new_rdata_len + 1);
            CHK_ALLOC(rdata, "realloc dns_compression_resolve");

            memmove(rdata + i + name_len - 2, rdata + i + 2, rdlength - i - 2);
            memcpy(rdata + i, name, name_len);
            i += name_len - 2;
            rdlength += name_len - 2;
            free(name);
        }
    }
    return new_rdata_len;
}