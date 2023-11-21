#pragma once
#include "bootp.h"
#include "cprintf.h"
#include "dns.h"
#include "show.h"
#include <string.h>

extern enum VerboseLevel verbose_level;

void sh_ethernet_header(const struct ether_header *ethernet_header, int __tabs);

void sh_ip_header(struct ip *ip_header, int __tabs);

void sh_ipv6_header(struct ip6_hdr *ip6_header, int __tabs);

void sh_tcp_header(struct tcphdr *tcp_header, int __tabs);

void sh_udp_header(struct udphdr *udp_header, int __tabs);

void sh_icmp_header(struct icmphdr *icmp_header, int __tabs);

void sh_icmp_type(struct icmphdr *icmp_header, int __tabs);

void sh_arp_header(struct ether_arp *arp_header, int __tabs);

void sh_bootp_header(struct bootp *bootp_header, int __tabs);

void sh_bootp_vendor(struct bootp *bootp_header, int __tabs);

void sh_dns_header(struct dnshdr *dns_header, int __tabs);

void sh_icmp_header(struct icmphdr *icmp_header, int __tabs);