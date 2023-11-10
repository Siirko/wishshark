#pragma once
#include "bootp.h"
#include "cprintf.h"
#include "dns.h"
#include "show.h"
#include <string.h>

extern enum VerboseLevel verbose_level;

void printf_ethernet_header_complete(const struct ether_header *ethernet_header, int __tabs);
void printf_ethernet_header_verbose(const struct ether_header *ethernet_header, int __tabs);
void printf_ethernet_header_concise(const struct ether_header *ethernet_header, int __tabs);

void printf_ip_header_complete(struct ip *ip_header, int __tabs);
void printf_ip_header_verbose(struct ip *ip_header, int __tabs);
void printf_ip_header_concise(struct ip *ip_header, int __tabs);

void printf_ipv6_header_complete(struct ip6_hdr *ip6_header, int __tabs);
void printf_ipv6_header_verbose(struct ip6_hdr *ip6_header, int __tabs);
void printf_ipv6_header_concise(struct ip6_hdr *ip6_header, int __tabs);

void printf_tcp_header_complete(struct tcphdr *tcp_header, int __tabs);
void printf_tcp_header_verbose(struct tcphdr *tcp_header, int __tabs);
void printf_tcp_header_concise(struct tcphdr *tcp_header, int __tabs);

void printf_udp_header_complete(struct udphdr *udp_header, int __tabs);
void printf_udp_header_verbose(struct udphdr *udp_header, int __tabs);
void printf_udp_header_concise(struct udphdr *udp_header, int __tabs);

void printf_icmp_header_complete(struct icmphdr *icmp_header, int __tabs);
void printf_icmp_header_verbose(struct icmphdr *icmp_header, int __tabs);
void printf_icmp_header_concise(struct icmphdr *icmp_header, int __tabs);

void printf_icmp_type_complete(struct icmphdr *icmp_header, int __tabs);
void printf_icmp_type_verbose(struct icmphdr *icmp_header, int __tabs);
void printf_icmp_type_concise(struct icmphdr *icmp_header, int __tabs);

void printf_arp_header_complete(struct ether_arp *arp_header, int __tabs);
void printf_arp_header_verbose(struct ether_arp *arp_header, int __tabs);
void printf_arp_header_concise(struct ether_arp *arp_header, int __tabs);

void printf_bootp_header_complete(struct bootp *bootp_header, int __tabs);
void printf_bootp_header_verbose(struct bootp *bootp_header, int __tabs);
void printf_bootp_header_concise(struct bootp *bootp_header, int __tabs);

void printf_bootp_vendor_complete(struct bootp *bootp_header, int __tabs);

void printf_dns_header_complete(struct dnshdr *dns_header, int __tabs);
void printf_dns_header_verbose(struct dnshdr *dns_header, int __tabs);
void printf_dns_header_concise(struct dnshdr *dns_header, int __tabs);