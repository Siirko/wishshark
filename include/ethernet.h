// headers took from  https://www.tcpdump.org/pcap.html

#pragma once
#include <arpa/inet.h>

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN 6
/* Ethernet headers are always exactly 14 bytes */
#define SIZE_ETHERNET 14

/* Ethernet header */
struct sniff_ethernet
{
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_short ether_type;                 /* IP? ARP? RARP? etc */
};