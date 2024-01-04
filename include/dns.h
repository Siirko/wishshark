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

#pragma GCC diagnostic ignored "-Wunused-variable"
static const char *DNS_TYPE_MAP[] = {
    [DNS_TYPE_A] = "A",     [DNS_TYPE_NS] = "NS",   [DNS_TYPE_CNAME] = "CNAME", [DNS_TYPE_SOA] = "SOA",
    [DNS_TYPE_PTR] = "PTR", [DNS_TYPE_TXT] = "TXT", [DNS_TYPE_AAAA] = "AAAA",
};
#pragma GCC diagnostic pop

static inline void dns_unpack(const char *dns_header, u_char *dst, char *answer)
{
    uint16_t label = ntohs(*(uint16_t *)answer);
    uint8_t label_len = label >> 8;
    if (label == 0)
        dst[0] = '\0';
    else if (label_len == 0)
        return;
    else if (DNS_IS_COMPRESSED(label))
        dns_unpack(dns_header, dst, (char *)dns_header + DNS_RESOLVE_OFFSET(label));
    else
    {
        memcpy(dst, answer + 1, label_len);
        dst[label_len] = '.';
        dns_unpack(dns_header, dst + label_len + 1, answer + label_len + 1);
    }
}

static inline void dns_type_show(u_char *rdata, uint16_t type, struct dnshdr *dns_header, struct dnsanswer *dnsanswer,
                                 int __tabs)
{
    switch (type)
    {
    case DNS_TYPE_A:
        spprintf(true, true, " Address: %s\n", __tabs + 3, __tabs + 3, inet_ntoa(*(struct in_addr *)rdata));
        break;
    case DNS_TYPE_AAAA:
        spprintf(true, true, " Address: %s\n", __tabs + 3, __tabs + 3,
                 inet_ntop(AF_INET6, rdata, (char[INET6_ADDRSTRLEN]){0}, INET6_ADDRSTRLEN));
        break;
    case DNS_TYPE_SOA:
    {
        u_char primary_ns[DNS_NAME_MAX_LEN] = {0};
        u_char mailbox[DNS_NAME_MAX_LEN] = {0};

        dns_unpack((char *)dns_header, primary_ns, (char *)dnsanswer + sizeof(*dnsanswer));

        uint16_t label = ntohs(*(uint16_t *)((char *)dnsanswer + sizeof(*dnsanswer)));
        uint8_t padding = DNS_IS_COMPRESSED(label) ? 2 : ((label >> 8) + 2);
        dns_unpack((char *)dns_header, mailbox, (char *)dnsanswer + sizeof(*dnsanswer) + padding);
        size_t mailbox_len = strlen((char *)mailbox);

        struct dnssoa *dnssoa =
            (struct dnssoa *)((char *)dnsanswer + sizeof(*dnsanswer) + padding + 2 + (padding != 2 ? mailbox_len : 0));
        spprintf(true, false, " Primary NS: %s\n", __tabs + 3, __tabs + 3, primary_ns);
        spprintf(true, false, " Mailbox: %s\n", __tabs + 3, __tabs + 3, mailbox);
        spprintf(true, false, " Serial Number: %x\n", __tabs + 3, __tabs + 3, ntohl(dnssoa->serial));
        spprintf(true, false, " Refresh Interval: %d\n", __tabs + 3, __tabs + 3, ntohl(dnssoa->refresh_interval));
        spprintf(true, false, " Retry Interval: %d\n", __tabs + 3, __tabs + 3, ntohl(dnssoa->retry_interval));
        spprintf(true, false, " Expiration Limit: %d\n", __tabs + 3, __tabs + 3, ntohl(dnssoa->expire_limit));
        spprintf(true, true, " Minimum TTL: %d\n", __tabs + 3, __tabs + 3, ntohl(dnssoa->minimum_ttl));

        break;
    }
    // and so on ...
    default:
    {
        if (type == DNS_TYPE_TXT || type == DNS_TYPE_CNAME || type == DNS_TYPE_NS || type == DNS_TYPE_PTR)
        {
            u_char name[DNS_NAME_MAX_LEN] = {0};
            dns_unpack((char *)dns_header, name, (char *)dnsanswer + sizeof(*dnsanswer));
            spprintf(true, true, " Name: %s\n", __tabs + 3, __tabs + 3, name);
        }
        break;
    }
    }
}