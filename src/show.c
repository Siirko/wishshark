#include "../include/show.h"
#include "../include/ansi_color.h"
#include "../include/bootp.h"
#include "../include/cprintf.h"
#include "../include/show_helper.h"
#include "../include/tcp_helper.h"
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

void s_ethernet_packet(const tshow_t packet, int __tabs)
{
    const u_char *packet_body = packet.packet_body;
    // https://en.wikipedia.org/wiki/Ethernet_frame#Structure
    spprintf(false, false, BBLU "\n\nEthernet\n" CRESET, __tabs, 0);
    struct ether_header *ethernet_header = (struct ether_header *)packet_body;
    switch (verbose_level)
    {
    case CONCISE:
        printf_ethernet_header_concise(ethernet_header, __tabs);
        break;
    case VERBOSE:
        printf_ethernet_header_verbose(ethernet_header, __tabs);
        break;
    case COMPLETE:
        printf_ethernet_header_complete(ethernet_header, __tabs);
        break;
    }
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
    switch (verbose_level)
    {
    case CONCISE:
        printf_ip_header_concise(ip_header, __tabs);
        break;
    case VERBOSE:
        printf_ip_header_verbose(ip_header, __tabs);
        break;
    case COMPLETE:
        printf_ip_header_complete(ip_header, __tabs);
        break;
    }
    if (ip_header->ip_hl > 5 && verbose_level == COMPLETE)
        spprintf(true, false, " Options type: %d\n", __tabs + 2, __tabs + 2,
                 ((struct ip_timestamp *)(packet_body + sizeof(struct ether_header) + sizeof(struct ip)))->ipt_code);

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
    switch (verbose_level)
    {
    case CONCISE:
        printf_ipv6_header_concise(ip6_header, __tabs);
        break;
    case VERBOSE:
        printf_ipv6_header_verbose(ip6_header, __tabs);
        break;
    case COMPLETE:
        printf_ipv6_header_complete(ip6_header, __tabs);
        break;
    }
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
    switch (verbose_level)
    {
    case CONCISE:
        printf_tcp_header_concise(tcp_header, __tabs);
        break;
    case VERBOSE:
        printf_tcp_header_verbose(tcp_header, __tabs);
        break;
    case COMPLETE:
        printf_tcp_header_complete(tcp_header, __tabs);
        break;
    }
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
}

void s_udp_packet(const tshow_t packet, int __tabs)
{
    const u_char *packet_body = packet.packet_body;
    struct udphdr *udp_header = (struct udphdr *)(packet_body + sizeof(struct ether_header) +
                                                  (packet.is_ipv6 ? sizeof(struct ip6_hdr) : sizeof(struct ip)));
    switch (verbose_level)
    {
    case CONCISE:
        printf_udp_header_concise(udp_header, __tabs);
        break;
    case VERBOSE:
        printf_udp_header_verbose(udp_header, __tabs);
        break;
    case COMPLETE:
        printf_udp_header_complete(udp_header, __tabs);
        break;
    }
    if (ntohs(udp_header->source) == 67 || ntohs(udp_header->dest) == 67 || ntohs(udp_header->source) == 68 ||
        ntohs(udp_header->dest) == 68)
        s_bootp_packet(packet, __tabs + 1);
    if (ntohs(udp_header->source) == 53 || ntohs(udp_header->dest) == 53)
        s_dns_packet(packet, __tabs + 1);
}

void s_icmp_packet(const tshow_t packet, int __tabs)
{
    const u_char *packet_body = packet.packet_body;
    // https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Control_messages
    struct icmphdr *icmp_header = (struct icmphdr *)(packet_body + sizeof(struct ether_header) +
                                                     (packet.is_ipv6 ? sizeof(struct ip6_hdr) : sizeof(struct ip)));

    switch (verbose_level)
    {
    case CONCISE:
        printf_icmp_header_concise(icmp_header, __tabs);
        break;
    case VERBOSE:
        printf_icmp_header_verbose(icmp_header, __tabs);
        break;
    case COMPLETE:
        printf_icmp_header_complete(icmp_header, __tabs);
        break;
    }
}

void printf_icmp_header_complete(struct icmphdr *icmp_header, int __tabs)
{
    spprintf(true, true, BBLU " ICMP\n" CRESET, __tabs + 1, __tabs + 2);
    spprintf(true, false, " Type: %d\n", __tabs + 2, __tabs + 2, icmp_header->type);
    spprintf(true, false, " Code: %d\n", __tabs + 2, __tabs + 2, icmp_header->code);
    spprintf(true, false, " Checksum: 0x%x\n", __tabs + 2, __tabs + 2, ntohs(icmp_header->checksum));
}

void s_arp_packet(const tshow_t packet, int __tabs)
{
    const u_char *packet_body = packet.packet_body;
    struct ether_arp *arp_header = (struct ether_arp *)(packet_body + sizeof(struct ether_header));
    switch (verbose_level)
    {
    case CONCISE:
        printf_arp_header_concise(arp_header, __tabs);
        break;
    case VERBOSE:
        printf_arp_header_verbose(arp_header, __tabs);
        break;
    case COMPLETE:
        printf_arp_header_complete(arp_header, __tabs);
        break;
    }
}

void s_bootp_packet(const tshow_t packet, int __tabs)
{
    struct bootp *bootp_header =
        (struct bootp *)(packet.packet_body + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr));
    switch (verbose_level)
    {
    case CONCISE:
        printf_bootp_header_concise(bootp_header, __tabs);
        break;
    case VERBOSE:
        printf_bootp_header_verbose(bootp_header, __tabs);
        break;
    case COMPLETE:
        printf_bootp_header_complete(bootp_header, __tabs);
        printf_bootp_vendor_complete(bootp_header, __tabs);
        break;
    }
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
    switch (verbose_level)
    {
    case CONCISE:
        printf_dns_header_concise(dns_header, __tabs);
        break;
    case VERBOSE:
        printf_dns_header_verbose(dns_header, __tabs);
        break;
    case COMPLETE:
        printf_dns_header_complete(dns_header, __tabs);
        break;
    }
}