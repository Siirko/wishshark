#include "../include/show.h"
#include "../include/ansi_color.h"
#include "../include/bootp.h"
#include "../include/cprintf.h"
#include <stdlib.h>
#include <string.h>

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

const char *ICMP_TYPE_MAP[] = {
    [ICMP_ECHOREPLY] = "Echo reply",
    [ICMP_DEST_UNREACH] = "Destination Unreachable",
    [ICMP_SOURCE_QUENCH] = "Source Quench",
    [ICMP_REDIRECT] = "Redirect",
    [ICMP_ECHO] = "Echo",
    [ICMP_TIME_EXCEEDED] = "Time Exceeded",
    [ICMP_PARAMETERPROB] = "Parameter Problem",
    [ICMP_TIMESTAMP] = "Timestamp",
    [ICMP_TIMESTAMPREPLY] = "Timestamp Reply",
    [ICMP_INFO_REQUEST] = "Information Request",
    [ICMP_INFO_REPLY] = "Information Reply",
    [ICMP_ADDRESS] = "Address Mask Request",
    [ICMP_ADDRESSREPLY] = "Address Mask Reply",
};

void s_ethernet_packet(const tshow_t packet, int __tabs)
{
    const u_char *packet_body = packet.packet_body;
    // https://en.wikipedia.org/wiki/Ethernet_frame#Structure
    spprintf(false, false, BBLU "\n\nEthernet\n" CRESET, __tabs, 0);
    struct ether_header *ethernet_header = (struct ether_header *)packet_body;
    spprintf(false, false, " Destination MAC Address: %s\n", __tabs + 1, 1,
             ether_ntoa((struct ether_addr *)ethernet_header->ether_dhost));
    spprintf(false, false, " Source MAC Address: %s\n", __tabs + 1, 1,
             ether_ntoa((struct ether_addr *)ethernet_header->ether_shost), __tabs + 1);
    spprintf(false, true, " Type: %d\n", __tabs + 1, 1, ntohs(ethernet_header->ether_type));
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
    spprintf(true, true, BBLU " IP\n" CRESET, __tabs + 1, __tabs + 2);
    spprintf(true, false, " Version: %d\n", __tabs + 2, __tabs + 2, ip_header->ip_v);
    spprintf(true, false, " IHL: %d\n", __tabs + 2, __tabs + 2, ip_header->ip_hl);
    // According to wikipedia ToS = DSCP but this seems to be blurry
    spprintf(true, false, " ToS: %d\n", __tabs + 2, __tabs + 2, ip_header->ip_tos);
    // printf("\tDSCP: %d\n", IPTOS_DSCP(ip_header->ip_tos));
    spprintf(true, false, " ECN: %d\n", __tabs + 2, __tabs + 2, IPTOS_ECN(ip_header->ip_tos));
    spprintf(true, false, " Total Length: %d\n", __tabs + 2, __tabs + 2, ntohs(ip_header->ip_len));
    spprintf(true, false, " ID: %d\n", __tabs + 2, __tabs + 2, ntohs(ip_header->ip_id));
    spprintf(true, false, " Flags: %d\n", __tabs + 2, __tabs + 2, ntohs(ip_header->ip_off) & IP_OFFMASK);
    spprintf(true, false, " Fragment Offset: %d\n", __tabs + 2, __tabs + 2, ntohs(ip_header->ip_off));
    spprintf(true, false, " TTL: %d\n", __tabs + 2, __tabs + 2, ip_header->ip_ttl);
    // protocol numbers: https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
    spprintf(true, false, " Protocol ID: %d\n", __tabs + 2, __tabs + 2, ip_header->ip_p);
    spprintf(true, false, " Protocol name: %s\n", __tabs + 2, __tabs + 2,
             IP_PROT_MAP[ip_header->ip_p] ? IP_PROT_MAP[ip_header->ip_p] : "Unknown");
    spprintf(true, false, " Source Address: %s\n", __tabs + 2, __tabs + 2, inet_ntoa(ip_header->ip_src));
    spprintf(true, ip_header->ip_hl > 5 ? false : true, " Destination Address: %s\n", __tabs + 2, __tabs + 2,
             inet_ntoa(ip_header->ip_dst));
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
    char addrstr[INET6_ADDRSTRLEN];
    struct ip6_hdr *ip6_header = (struct ip6_hdr *)(packet.packet_body + sizeof(struct ether_header));
    spprintf(true, true, BBLU " IPv6\n" CRESET, __tabs + 1, __tabs + 2);
    spprintf(true, false, " Version: %d\n", __tabs + 2, __tabs + 2, ip6_header->ip6_vfc >> 4);
    spprintf(true, false, " Traffic Class: %d\n", __tabs + 2, __tabs + 2, ip6_header->ip6_flow >> 20);
    spprintf(true, false, " Flow Label: %d\n", __tabs + 2, __tabs + 2, ip6_header->ip6_flow & 0x000FFFFF);
    spprintf(true, false, " Payload Length: %d\n", __tabs + 2, __tabs + 2, ntohs(ip6_header->ip6_plen));
    spprintf(true, false, " Next Header: %d (%s)\n", __tabs + 2, __tabs + 2, ip6_header->ip6_nxt,
             IP_PROT_MAP[ip6_header->ip6_nxt] ? IP_PROT_MAP[ip6_header->ip6_nxt] : "Unknown");
    spprintf(true, false, " Hop Limit: %d\n", __tabs + 2, __tabs + 2, ip6_header->ip6_hlim);
    inet_ntop(AF_INET6, &ip6_header->ip6_src, addrstr, sizeof(addrstr));
    spprintf(true, false, " Source Address: %s\n", __tabs + 2, __tabs + 2, addrstr);
    inet_ntop(AF_INET6, &ip6_header->ip6_dst, addrstr, sizeof(addrstr));
    spprintf(true, true, " Destination Address: %s\n", __tabs + 2, __tabs + 2, addrstr);
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
    spprintf(true, true, BBLU " TCP\n" CRESET, __tabs + 1, __tabs + 2);
    spprintf(true, false, " Source Port: %d\n", __tabs + 2, __tabs + 2, ntohs(tcp_header->source));
    spprintf(true, false, " Destination Port: %d\n", __tabs + 2, __tabs + 2, ntohs(tcp_header->dest));
    spprintf(true, false, " Sequence Number: %d\n", __tabs + 2, __tabs + 2, ntohs(tcp_header->seq));
    if (tcp_header->ack)
        spprintf(true, false, " Acknowledgment Number: %d\n", __tabs + 2, __tabs + 2, ntohs(tcp_header->ack_seq));
    spprintf(true, false, " Data Offset: %d\n", __tabs + 2, __tabs + 2, tcp_header->doff);
    spprintf(true, false, " Flags: %d%d%d%d%d%d\n", __tabs + 2, __tabs + 2, tcp_header->urg, tcp_header->ack,
             tcp_header->psh, tcp_header->rst, tcp_header->syn, tcp_header->fin);
    spprintf(true, false, " Window: %d\n", __tabs + 2, __tabs + 2, ntohs(tcp_header->window));
    spprintf(true, tcp_header->doff > 5 ? false : true, " Checksum: 0x%x\n", __tabs + 2, __tabs + 2,
             ntohs(tcp_header->check));
    if (tcp_header->urg)
        spprintf(true, false, " Urgent Pointer: %d\n", __tabs + 2, __tabs + 2, ntohs(tcp_header->urg_ptr));
    if (tcp_header->doff > 5)
    {
        // TODO
    }
    if (ntohs(tcp_header->source) == 80 || ntohs(tcp_header->dest) == 80)
        s_http_packet(packet, __tabs + 1);
}

void s_udp_packet(const tshow_t packet, int __tabs)
{
    const u_char *packet_body = packet.packet_body;
    struct udphdr *udp_header = (struct udphdr *)(packet_body + sizeof(struct ether_header) +
                                                  (packet.is_ipv6 ? sizeof(struct ip6_hdr) : sizeof(struct ip)));
    spprintf(true, true, BBLU " UDP\n" CRESET, __tabs + 1, __tabs + 2);
    spprintf(true, false, " Source Port: %d\n", __tabs + 2, __tabs + 2, ntohs(udp_header->source));
    spprintf(true, false, " Destination Port: %d\n", __tabs + 2, __tabs + 2, ntohs(udp_header->dest));
    spprintf(true, false, " Length: %d\n", __tabs + 2, __tabs + 2, ntohs(udp_header->len));
    spprintf(true, true, " Checksum: %d\n", __tabs + 2, __tabs + 2, ntohs(udp_header->check));
    if (ntohs(udp_header->source) == 67 || ntohs(udp_header->dest) == 67 || ntohs(udp_header->source) == 68 ||
        ntohs(udp_header->dest) == 68)
        s_bootp_packet(packet, __tabs + 1);
}

void s_icmp_packet(const tshow_t packet, int __tabs)
{
    const u_char *packet_body = packet.packet_body;
    // https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Control_messages
    struct icmphdr *icmp_header = (struct icmphdr *)(packet_body + sizeof(struct ether_header) +
                                                     (packet.is_ipv6 ? sizeof(struct ip6_hdr) : sizeof(struct ip)));
    spprintf(true, true, BBLU " ICMP\n" CRESET, __tabs + 1, __tabs + 2);
    spprintf(true, false, " Type: %d\n", __tabs + 2, __tabs + 2, icmp_header->type);
    spprintf(true, false, " Code: %d\n", __tabs + 2, __tabs + 2, icmp_header->code);
    spprintf(true, false, " Checksum: %d\n", __tabs + 2, __tabs + 2, ntohs(icmp_header->checksum));

    spprintf(true, false, " Control message: %s\n", __tabs + 2, __tabs + 2,
             ICMP_TYPE_MAP[icmp_header->type] ? ICMP_TYPE_MAP[icmp_header->type] : "Unknown");
    switch (icmp_header->type)
    {
    case ICMP_ECHOREPLY:
        spprintf(true, false, " Identifier: %d\n", __tabs + 2, __tabs + 2, ntohs(icmp_header->un.echo.id));
        spprintf(true, true, " Sequence Number: %d\n", __tabs + 2, __tabs + 2, ntohs(icmp_header->un.echo.sequence));
        break;
    case ICMP_DEST_UNREACH:
        break;
    case ICMP_SOURCE_QUENCH:
        break;
    case ICMP_REDIRECT:
        break;
    case ICMP_ECHO:
        break;
    case ICMP_TIME_EXCEEDED:
        break;
    case ICMP_PARAMETERPROB:
        break;
    case ICMP_TIMESTAMP:
        break;
    case ICMP_TIMESTAMPREPLY:
        break;
    case ICMP_INFO_REQUEST:
        break;
    case ICMP_INFO_REPLY:
        break;
    case ICMP_ADDRESS:
        break;
    case ICMP_ADDRESSREPLY:
        break;
    default:
        break;
    }
}

void s_arp_packet(const tshow_t packet, int __tabs)
{
    const u_char *packet_body = packet.packet_body;
    struct ether_arp *arp_header = (struct ether_arp *)(packet_body + sizeof(struct ether_header));
    spprintf(true, true, BBLU " ARP\n" CRESET, __tabs + 1, __tabs + 2);
    spprintf(true, false, " Hardware type: %d\n", __tabs + 2, __tabs + 2, ntohs(arp_header->arp_hrd));
    spprintf(true, false, " Protocol type: %d\n", __tabs + 2, __tabs + 2, ntohs(arp_header->arp_pro));
    spprintf(true, false, " Hardware size: %d\n", __tabs + 2, __tabs + 2, arp_header->arp_hln);
    spprintf(true, false, " Protocol size: %d\n", __tabs + 2, __tabs + 2, arp_header->arp_pln);
    spprintf(true, false, " Opcode: %d\n", __tabs + 2, __tabs + 2, ntohs(arp_header->arp_op));
    spprintf(true, false, " Sender MAC Address: %s\n", __tabs + 2, __tabs + 2,
             ether_ntoa((struct ether_addr *)arp_header->arp_sha));
    spprintf(true, false, " Sender IP Address: %s\n", __tabs + 2, __tabs + 2,
             inet_ntoa(*(struct in_addr *)arp_header->arp_spa));
    spprintf(true, false, " Target MAC Address: %s\n", __tabs + 2, __tabs + 2,
             ether_ntoa((struct ether_addr *)arp_header->arp_tha));
    spprintf(true, true, " Target IP Address: %s\n", __tabs + 2, __tabs + 2,
             inet_ntoa(*(struct in_addr *)arp_header->arp_tpa));
}

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

void s_http_packet(const tshow_t packet, int __tabs)
{
    const u_char *packet_body = packet.packet_body;
    struct tcphdr *tcp_header = (struct tcphdr *)(packet_body + sizeof(struct ether_header) +
                                                  (packet.is_ipv6 ? sizeof(struct ip6_hdr) : sizeof(struct ip)));
    size_t tcp_payload_size = tcp_payload_len(packet);
    if (tcp_payload_size > 0)
    {
        spprintf(true, true, BBLU " HTTP\n" CRESET, __tabs + 1, __tabs + 2);
        spprintf(true, false, " Source Port: %d\n", __tabs + 2, __tabs + 2, ntohs(tcp_header->source));
        spprintf(true, false, " Destination Port: %d\n", __tabs + 2, __tabs + 2, ntohs(tcp_header->dest));
        u_char *payload[tcp_payload_size];
        memcpy(payload, packet_body + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr),
               tcp_payload_size);
        payload[tcp_payload_size] = '\0';
        spprintf(true, false, " Payload: %s\n", __tabs + 2, __tabs + 2, payload);
    }
}

void s_bootp_packet(const tshow_t packet, int __tabs)
{
    struct bootp *bootp_header =
        (struct bootp *)(packet.packet_body + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr));
    spprintf(true, true, BBLU " BOOTP\n" CRESET, __tabs + 1, __tabs + 2);
    spprintf(true, false, " Opcode: %d (%s)\n", __tabs + 2, __tabs + 2, bootp_header->bp_op,
             bootp_header->bp_op == BOOTREQUEST ? "Request" : "Reply");
    spprintf(true, false, " HType: %d (%s)\n", __tabs + 2, __tabs + 2, bootp_header->bp_htype,
             BOOTP_HTYPE_MAP[bootp_header->bp_htype] ? BOOTP_HTYPE_MAP[bootp_header->bp_htype] : "Unknown");
    spprintf(true, false, " HLen: %d\n", __tabs + 2, __tabs + 2, bootp_header->bp_hlen);
    spprintf(true, false, " Hops: %d\n", __tabs + 2, __tabs + 2, bootp_header->bp_hops);
    spprintf(true, false, " XID: 0x%x\n", __tabs + 2, __tabs + 2, htonl(bootp_header->bp_xid));
    spprintf(true, false, " Secs: %d\n", __tabs + 2, __tabs + 2, bootp_header->bp_secs);
    spprintf(true, false, " Flags: %d\n", __tabs + 2, __tabs + 2, bootp_header->bp_flags);
    spprintf(true, false, " CIAddr: %s\n", __tabs + 2, __tabs + 2, inet_ntoa(bootp_header->bp_ciaddr));
    spprintf(true, false, " YIAddr: %s\n", __tabs + 2, __tabs + 2, inet_ntoa(bootp_header->bp_yiaddr));
    spprintf(true, false, " SIAddr: %s\n", __tabs + 2, __tabs + 2, inet_ntoa(bootp_header->bp_siaddr));
    spprintf(true, false, " GIAddr: %s\n", __tabs + 2, __tabs + 2, inet_ntoa(bootp_header->bp_giaddr));
    spprintf(true, false, " CHAddr: %x:%x:%x:%x:%x:%x\n", __tabs + 2, __tabs + 2, bootp_header->bp_chaddr[0],
             bootp_header->bp_chaddr[1], bootp_header->bp_chaddr[2], bootp_header->bp_chaddr[3],
             bootp_header->bp_chaddr[4], bootp_header->bp_chaddr[5]);
    spprintf(true, false, " SName: %s\n", __tabs + 2, __tabs + 2, bootp_header->bp_sname);
    spprintf(true, false, " File: %s\n", __tabs + 2, __tabs + 2, bootp_header->bp_file);

    uint8_t *vend_ptr = bootp_header->bp_vend;
    u_char magic_cookie[4] = {0};
    memcpy(magic_cookie, vend_ptr, 4);
    spprintf(true, false, " Magic Cookie: %x:%x:%x:%x\n", __tabs + 2, __tabs + 2, magic_cookie[0], magic_cookie[1],
             magic_cookie[2], magic_cookie[3]);
    vend_ptr += 4;
    spprintf(true, true, BGRN " Vendor Specific Information:\n" CRESET, __tabs + 2, __tabs + 2);
    // TODO: To enhance, give a function to use for each tag to have exact output
    for (; *vend_ptr != 0xff;)
    {
        uint8_t tag = *vend_ptr;
        uint8_t len = *(++vend_ptr);
        u_char value[len + 10];
        memset(value, 0, len + 10);
        memcpy(value, ++vend_ptr, len);
        vend_ptr += len;
        spprintf(true, false, " Tag: %d (%s)\n", __tabs + 2, __tabs + 3, tag,
                 BOOTP_TAG_MAP[tag] ? BOOTP_TAG_MAP[tag] : "Unknown");
        spprintf(true, false, " Len: %d\n", __tabs + 2, __tabs + 3, len);

        u_char hex_value[len * 2 + 1];
        for (int i = 0; i < len; i++)
            sprintf(hex_value + i * 2, "%02x", value[i]);
        spprintf(true, true, " Value: %s (0x%s)\n", __tabs + 2, __tabs + 3, value, hex_value);
        // fwrite(value, sizeof(char), len, stdout);
    }
}