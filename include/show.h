#pragma once

#include <arpa/inet.h>
#include <ctype.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <stdbool.h>

typedef struct tshow
{
    const struct pcap_pkthdr *packet_header;
    const u_char *packet_body;
    bool is_ipv6;
} tshow_t;

size_t tcp_payload_len(const tshow_t packet);

void s_ethernet_packet(const tshow_t packet, int __tabs);

void s_ip_packet(const tshow_t packet, int __tabs);

void s_ipv6_packet(const tshow_t packet, int __tabs);

void s_tcp_packet(const tshow_t packet, int __tabs);

void s_udp_packet(const tshow_t packet, int __tabs);

void s_arp_packet(const tshow_t packet, int __tabs);

void s_http_packet(const tshow_t packet, int __tabs);

void s_bootp_packet(const tshow_t packet, int __tabs);

void s_dns_packet(const tshow_t packet, int __tabs);

void s_imap_packet(const tshow_t packet, int __tabs);

void s_pop_packet(const tshow_t packet, int __tabs);

void s_smtp_packet(const tshow_t packet, int __tabs);

void s_ftp_packet(const tshow_t packet, int __tabs);

void s_icmp_packet(const tshow_t packet, int __tabs);

void s_telnet_packet(const tshow_t packet, int __tabs);