#pragma once
#include <stdint.h>

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

struct dnsquery
{
    uint16_t qtype;
    uint16_t qclass;
};

struct dnsanswer
{
    uint16_t compression;
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t rdlength;
};

#define DNS_TYPE_A 1
#define DNS_TYPE_NS 2
#define DNS_TYPE_CNAME 5
#define DNS_TYPE_SOA 6
#define DNS_TYPE_PTR 12
#define DNS_TYPE_TXT 16
#define DNS_TYPE_AAAA 28