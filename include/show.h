#pragma once

#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <pcap.h>

void s_ethernet_packet(const u_char *packet, const struct pcap_pkthdr *header, int __tabs);

void s_ip_packet(const u_char *packet, const struct pcap_pkthdr *header, int __tabs);

void s_tcp_packet(const u_char *packet, const struct pcap_pkthdr *header, int __tabs);

void s_udp_packet(const u_char *packet, const struct pcap_pkthdr *header, int __tabs);