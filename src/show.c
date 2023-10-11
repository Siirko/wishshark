#include "../include/show.h"
#include "../include/ansi_color.h"
#include "../include/cprintf.h"

// https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
// I have inserted only the most common protocols
const char *IP_PROT_MAP[146] = {[0] = "HOPOPT",       [1] = "ICMP",
                                [2] = "IGMP",         [3] = "GGP",
                                [4] = "IP-in-IP",     [5] = "ST",
                                [6] = "TCP",          [7] = "CBT",
                                [8] = "EGP",          [9] = "IGP",
                                [10] = "BBN-RCC-MON", [11] = "NVP-II",
                                [12] = "PUP",         [13] = "ARGUS",
                                [14] = "EMCON",       [15] = "XNET",
                                [16] = "CHAOS",       [17] = "UDP",
                                [18] = "MUX",         [19] = "DCN-MEAS",
                                [20] = "HMP",         [21] = "PRM",
                                [22] = "XNS-IDP",     [23] = "TRUNK-1",
                                [24] = "TRUNK-2",     [25] = "LEAF-1",
                                [26] = "LEAF-2",      [27] = "RDP",
                                [28] = "IRTP",        [29] = "ISO-TP4",
                                [30] = "NETBLT",      [31] = "MFE-NSP",
                                [32] = "MERIT-INP",   [33] = "DCCP",
                                [34] = "3PC",         [35] = "3PC",
                                [36] = "IDPR",        [41] = "IPv6",
                                [43] = "IPv6-Route",  [44] = "IPv6-Frag",
                                [58] = "IPv6-ICMP",   [59] = "IPv6-NoNxt",
                                [60] = "IPv6-Opts",   [97] = "ETHERIP",
                                [98] = "ENCAP",       [124] = "IS-IS over IPv4",
                                [143] = "Ethernet"};

void s_ethernet_packet(const u_char *packet, const struct pcap_pkthdr *header, int __tabs)
{
    // https://en.wikipedia.org/wiki/Ethernet_frame#Structure
    spprintf(BBLU "\n\nEthernet\n" CRESET, __tabs, 0);
    struct ether_header *ethernet_header = (struct ether_header *)packet;
    spprintf(" Destination MAC Address: %s\n", __tabs + 1, 1,
             ether_ntoa((struct ether_addr *)ethernet_header->ether_dhost));
    spprintf(" Source MAC Address: %s\n", __tabs + 1, 1, ether_ntoa((struct ether_addr *)ethernet_header->ether_shost),
             __tabs + 1);
    spprintf(" Type: %d\n", __tabs + 1, 1, ntohs(ethernet_header->ether_type));
    switch (ntohs(ethernet_header->ether_type))
    {
    case ETHERTYPE_IP:
        s_ip_packet(packet, header, __tabs + 1);
        break;
    default:
        break;
    }
}

void s_ip_packet(const u_char *packet, const struct pcap_pkthdr *header, int __tabs)
{
    // https://en.wikipedia.org/wiki/Internet_Protocol_version_4#Packet_structure
    struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
    spprintf(BBLU " IP\n" CRESET, __tabs + 1, __tabs + 2);
    spprintf(" IHL: %d\n", __tabs + 2, __tabs + 2, ip_header->ip_hl);
    // According to wikipedia ToS = DSCP but this seems to be blurry
    spprintf(" ToS: %d\n", __tabs + 2, __tabs + 2, ip_header->ip_tos);
    // printf("\tDSCP: %d\n", IPTOS_DSCP(ip_header->ip_tos));
    spprintf(" ECN: %d\n", __tabs + 2, __tabs + 2, IPTOS_ECN(ip_header->ip_tos));
    spprintf(" Total Length: %d\n", __tabs + 2, __tabs + 2, ntohs(ip_header->ip_len));
    spprintf(" ID: %d\n", __tabs + 2, __tabs + 2, ntohs(ip_header->ip_id));
    spprintf(" Flags: %d\n", __tabs + 2, __tabs + 2, ntohs(ip_header->ip_off) & IP_OFFMASK);
    spprintf(" Fragment Offset -> %d\n", __tabs + 2, __tabs + 2, ntohs(ip_header->ip_off));
    spprintf(" TTL: %d\n", __tabs + 2, __tabs + 2, ip_header->ip_ttl);
    spprintf(" Protocol: %s\n", __tabs + 2, __tabs + 2,
             IP_PROT_MAP[ip_header->ip_p] ? IP_PROT_MAP[ip_header->ip_p] : "Unknown");
    spprintf(" Source Address: %s\n", __tabs + 2, __tabs + 2, inet_ntoa(ip_header->ip_src));
    spprintf(" Destination Address: %s\n", __tabs + 2, __tabs + 2, inet_ntoa(ip_header->ip_dst));
    if (ip_header->ip_hl > 5)
        spprintf("Options: %s\n", __tabs + 2, __tabs + 2,
                 (char *)(packet + sizeof(struct ether_header) + sizeof(struct ip)));

    // switch (ip_header->ip_p)
    // {
    // case IPPROTO_TCP:
    //     s_tcp_packet(packet, header);
    //     break;
    // case IPPROTO_UDP:
    //     s_udp_packet(packet, header);
    //     break;
    // case IPPROTO_ICMP:
    //     s_icmp_packet(packet, header);
    //     break;
    // default:
    //     break;
    // }
}