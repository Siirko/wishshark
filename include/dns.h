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

struct __attribute__((__packed__)) dnssoa
{
    uint32_t serial;
    uint32_t refresh_interval;
    uint32_t retry_interval;
    uint32_t expire_limit;
    uint32_t minimum_ttl;
};

#define DNS_IS_COMPRESSED(x) (((x) & (0xc000)) == (0xc000))
#define DNS_RESOLVE_OFFSET(x) ((x) & 0x3fff)

#define DNS_NAME_MAX_LEN 256

#define DNS_TYPE_A 1
#define DNS_TYPE_NS 2
#define DNS_TYPE_CNAME 5
#define DNS_TYPE_SOA 6
#define DNS_TYPE_PTR 12
#define DNS_TYPE_TXT 16
#define DNS_TYPE_AAAA 28

static inline void dns_unpack(const char *dns_header, u_char *dst, char *answer, bool idk)
{
    uint16_t label = ntohs(*(uint16_t *)answer);
    // static uint8_t len = 0;
    if (label == 0)
    {
        dst[0] = '\0';
        // deprintf("len -> %d\n", len);
        // len = 0;
    }
    else if (DNS_IS_COMPRESSED(label))
    {
        uint16_t offset = DNS_RESOLVE_OFFSET(label);
        dns_unpack(dns_header, dst, (char *)dns_header + offset, idk);
    }
    else
    {
        uint8_t label_len = *(uint8_t *)answer;
        if (label_len == 0)
            return;
        memcpy(dst, answer + 1, label_len);
        // len += label_len;
        dst[label_len] = '.';
        dns_unpack(dns_header, dst + label_len + 1, answer + label_len + 1, idk);
    }
}
