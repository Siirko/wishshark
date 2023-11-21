#include "../include/show.h"
#include "../include/ansi_color.h"
#include "../include/bootp.h"
#include "../include/cprintf.h"
#include "../include/show_helper.h"
#include "../include/tcp_helper.h"
#include "../include/telnet.h"
#include "../include/udp_helper.h"
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

void s_ethernet_packet(const tshow_t packet, int __tabs)
{
    const u_char *packet_body = packet.packet_body;
    struct ether_header *ethernet_header = (struct ether_header *)packet_body;
    sh_ethernet_header(ethernet_header, __tabs);
    switch (ntohs(ethernet_header->ether_type))
    {
    case ETHERTYPE_IP:
        s_ip_packet(packet, __tabs + 1);
        break;
    case ETHERTYPE_ARP:
        s_arp_packet(packet, __tabs + 1);
        break;
    case ETHERTYPE_IPV6:
        s_ipv6_packet(packet, __tabs + 1);
        break;
    default:
        break;
    }
}

void s_ip_packet(const tshow_t packet, int __tabs)
{
    const u_char *packet_body = packet.packet_body;
    // https://en.wikipedia.org/wiki/Internet_Protocol_version_4#Packet_structure
    struct ip *ip_header = (struct ip *)(packet_body + sizeof(struct ether_header));
    sh_ip_header(ip_header, __tabs);
    if (ip_header->ip_hl > 5)
    {
        spprintf(true, false, " Options type: %d\n", __tabs + 2, __tabs + 2,
                 ((struct ip_timestamp *)(packet_body + sizeof(struct ether_header) + sizeof(struct ip)))->ipt_code);
    }

    switch (ip_header->ip_p)
    {
    case IPPROTO_TCP:
        s_tcp_packet(packet, __tabs + 1);
        break;
    case IPPROTO_UDP:
        s_udp_packet(packet, __tabs + 1);
        break;
    case IPPROTO_ICMP:
        s_icmp_packet(packet, __tabs + 1);
        break;
    default:
        break;
    }
}

void s_ipv6_packet(const tshow_t packet, int __tabs)
{
    struct ip6_hdr *ip6_header = (struct ip6_hdr *)(packet.packet_body + sizeof(struct ether_header));
    sh_ipv6_header(ip6_header, __tabs);
    switch (ip6_header->ip6_nxt)
    {
    case IPPROTO_TCP:
        s_tcp_packet(packet, __tabs + 1);
        break;
    case IPPROTO_UDP:
        s_udp_packet(packet, __tabs + 1);
        break;
    case IPPROTO_ICMPV6:
        // s_icmpv6_packet(packet, __tabs + 1);
        break;
    default:
        break;
    }
}

void s_tcp_packet(const tshow_t packet, int __tabs)
{
    const u_char *packet_body = packet.packet_body;
    // https://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_segment_structure
    struct tcphdr *tcp_header = (struct tcphdr *)(packet_body + sizeof(struct ether_header) +
                                                  (packet.is_ipv6 ? sizeof(struct ip6_hdr) : sizeof(struct ip)));
    sh_tcp_header(tcp_header, __tabs);
    uint16_t tcp_port_source = ntohs(tcp_header->source);
    uint16_t tcp_port_dest = ntohs(tcp_header->dest);
    if (tcp_port_source == HTTP || tcp_port_dest == HTTP)
        s_http_packet(packet, __tabs + 1);
    if (tcp_port_source == FTP || tcp_port_dest == FTP)
        s_ftp_packet(packet, __tabs + 1);
    if (tcp_port_source == SMTP || tcp_port_dest == SMTP)
        s_smtp_packet(packet, __tabs + 1);
    if (tcp_port_source == POP || tcp_port_dest == POP)
        s_pop_packet(packet, __tabs + 1);
    if (tcp_port_source == IMAP || tcp_port_dest == IMAP)
        s_imap_packet(packet, __tabs + 1);
    if (ntohs(tcp_port_source) == DNS || ntohs(tcp_port_dest) == DNS)
        s_dns_packet(packet, __tabs + 1);
    if (tcp_port_source == TELNET || tcp_port_dest == TELNET)
        s_telnet_packet(packet, __tabs + 1);
}

void s_udp_packet(const tshow_t packet, int __tabs)
{
    const u_char *packet_body = packet.packet_body;
    struct udphdr *udp_header = (struct udphdr *)(packet_body + sizeof(struct ether_header) +
                                                  (packet.is_ipv6 ? sizeof(struct ip6_hdr) : sizeof(struct ip)));
    sh_udp_header(udp_header, __tabs);
    if (ntohs(udp_header->source) == BOOTPS || ntohs(udp_header->dest) == BOOTPS ||
        ntohs(udp_header->source) == BOOTPC || ntohs(udp_header->dest) == BOOTPC)
        s_bootp_packet(packet, __tabs + 1);
    if (ntohs(udp_header->source) == DNS || ntohs(udp_header->dest) == DNS)
        s_dns_packet(packet, __tabs + 1);
}

void s_arp_packet(const tshow_t packet, int __tabs)
{
    const u_char *packet_body = packet.packet_body;
    struct ether_arp *arp_header = (struct ether_arp *)(packet_body + sizeof(struct ether_header));
    sh_arp_header(arp_header, __tabs);
}

void s_bootp_packet(const tshow_t packet, int __tabs)
{
    struct bootp *bootp_header =
        (struct bootp *)(packet.packet_body + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr));
    sh_bootp_header(bootp_header, __tabs);
    sh_bootp_vendor(bootp_header, __tabs);
}

void s_ftp_packet(const tshow_t packet, int __tabs) { printf_tcp_payload(packet, __tabs, FTP); }

void s_http_packet(const tshow_t packet, int __tabs) { printf_tcp_payload(packet, __tabs, HTTP); }

void s_imap_packet(const tshow_t packet, int __tabs) { printf_tcp_payload(packet, __tabs, IMAP); }

void s_pop_packet(const tshow_t packet, int __tabs) { printf_tcp_payload(packet, __tabs, POP); }

void s_smtp_packet(const tshow_t packet, int __tabs) { printf_tcp_payload(packet, __tabs, SMTP); }

void s_dns_packet(const tshow_t packet, int __tabs)
{
    const u_char *packet_body = packet.packet_body;
    struct dnshdr *dns_header =
        (struct dnshdr *)(packet_body + sizeof(struct ether_header) +
                          (packet.is_ipv6 ? sizeof(struct ip6_hdr) : sizeof(struct ip)) + sizeof(struct udphdr));
    sh_dns_header(dns_header, __tabs);
}

void s_icmp_packet(const tshow_t packet, int __tabs)
{
    const u_char *packet_body = packet.packet_body;
    struct icmphdr *icmp_header = (struct icmphdr *)(packet_body + sizeof(struct ether_header) +
                                                     (packet.is_ipv6 ? sizeof(struct ip6_hdr) : sizeof(struct ip)));
    sh_icmp_header(icmp_header, __tabs);
}

void s_telnet_packet(const tshow_t packet, int __tabs)
{
    const u_char *packet_body = packet.packet_body;
    size_t tcp_payload_size = tcp_payload_len(packet);
    if (tcp_payload_size > 0)
    {
        u_char payload[tcp_payload_size];
        memset(payload, 0, tcp_payload_size);
        memcpy(payload, packet_body + packet.packet_header->len - tcp_payload_size, tcp_payload_size);
        spprintf(true, true, " TELNET\n", __tabs + 1, __tabs + 2);
        if (verbose_level == CONCISE)
            return;
        if (payload[0] == IAC)
        {
            for (size_t i = 1; i < tcp_payload_size; i++)
            {
                if (i + 1 < tcp_payload_size)
                {
                    const char *cmd = TELNET_MAP[payload[i]];
                    const char *opt = TELNET_MAP[payload[i + 1]];
                    if (cmd && opt)
                    {
                        spprintf(true, i + 1 < tcp_payload_size ? false : true, " %s : %s\n", __tabs + 2, __tabs + 2,
                                 cmd, opt);
                        i += 2;
                    }
                }
            }
        }
        else
        {
            if (tcp_payload_size > 1)
            {
                nprint2print(tcp_payload_size, payload);
                spprintf(true, true, "Data: %s\n", __tabs + 2, __tabs + 2, payload);
            }
            else if (tcp_payload_size == 1)
                spprintf(true, true, "Data: %c\n", __tabs + 2, __tabs + 2, payload[0]);
        }
    }
}