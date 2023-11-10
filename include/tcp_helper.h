#pragma once
#include "cprintf.h"
#include "show.h"

enum ProtocolTcpDependant
{
    HTTP = 80,
    FTP = 21,
    SMTP = 25,
    POP = 110,
    IMAP = 143,
};

static const char *PROTOCOL_TCP_DEPENDANT_MAP[] = {
    [HTTP] = "HTTP", [FTP] = "FTP", [SMTP] = "SMTP", [POP] = "POP", [IMAP] = "IMAP",
};

size_t tcp_payload_len(const tshow_t packet)
{
    const u_char *packet_body = packet.packet_body;
    struct ip *ip_header = (struct ip *)(packet_body + sizeof(struct ether_header));
    struct tcphdr *tcp_header = (struct tcphdr *)(packet_body + sizeof(struct ether_header) +
                                                  (packet.is_ipv6 ? sizeof(struct ip6_hdr) : sizeof(struct ip)));
    size_t ethernet_header_length = sizeof(struct ether_header);
    size_t ip_header_length = ip_header->ip_hl * 4;
    size_t tcp_header_length = tcp_header->doff * 4;
    size_t total_header_size = ethernet_header_length + ip_header_length + tcp_header_length;
    return packet.packet_header->len - total_header_size;
}

void printf_tcp_payload(const tshow_t packet, int __tabs, enum ProtocolTcpDependant protocol)
{
    switch (verbose_level)
    {
    case CONCISE:
        printf(BRED " %s " CRESET, PROTOCOL_TCP_DEPENDANT_MAP[protocol]);
        break;
    case VERBOSE:
        spprintf(true, true, BRED " %s\n" CRESET, __tabs + 1, __tabs + 2, PROTOCOL_TCP_DEPENDANT_MAP[protocol]);
        break;
    case COMPLETE:
        spprintf(true, true, BRED " %s\n" CRESET, __tabs + 1, __tabs + 2, PROTOCOL_TCP_DEPENDANT_MAP[protocol]);
    }

    if (verbose_level < COMPLETE)
        return;
    size_t tcp_payload_size = tcp_payload_len(packet);
    if (tcp_payload_size > 0)
    {
        spprintf(true, false, " Payload size: %d\n", __tabs + 2, __tabs + 2, tcp_payload_size);
        u_char payload[tcp_payload_size];
        memset(payload, 0, tcp_payload_size);
        memcpy(payload, packet.packet_body + packet.packet_header->len - tcp_payload_size, tcp_payload_size - 1);
        nprint2print(tcp_payload_size - 1, payload);
        spprintf(true, true, " Payload: %s\n", __tabs + 2, __tabs + 2, payload);
    }
}