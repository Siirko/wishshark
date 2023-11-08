#pragma once
#include "bootp.h"
#include "show.h"
#include <string.h>

void printf_ethernet_header(const struct ether_header *ethernet_header, int __tabs);
void printf_ip_header(struct ip *ip_header, int __tabs);
void printf_ipv6_header(struct ip6_hdr *ip6_header, int __tabs);
void printf_tcp_header(struct tcphdr *tcp_header, int __tabs);
void printf_udp_header(struct udphdr *udp_header, int __tabs);
void printf_icmp_header(struct icmphdr *icmp_header, int __tabs);
void printf_icmp_type(struct icmphdr *icmp_header, int __tabs);
void printf_arp_header(struct ether_arp *arp_header, int __tabs);
void printf_bootp_header(struct bootp *bootp_header, int __tabs);
void printf_bootp_vendor(struct bootp *bootp_header, int __tabs);