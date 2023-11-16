#include "../include/show_helper.h"
#include "../include/ansi_color.h"
#include "../include/bootp.h"
#include "../include/cprintf.h"
#include "../include/protocol_map.h"
#include <stdarg.h>
#include <stdlib.h>
void printf_bootp_vendor(struct bootp *bootp_header, int __tabs)
{
    uint8_t *vend_ptr = bootp_header->bp_vend;
    struct cmu_vend *cmu_vend = (struct cmu_vend *)vend_ptr;
    spprintf(true, false, " Magic Cookie: 0x%02x 0x%02x 0x%02x 0x%02x\n", __tabs + 2, __tabs + 2, cmu_vend->v_magic[0],
             cmu_vend->v_magic[1], cmu_vend->v_magic[2], cmu_vend->v_magic[3]);
    vend_ptr += 4;
    spprintf(true, true, BGRN " Vendor Specific Information:\n" CRESET, __tabs + 2, __tabs + 2);
    for (; *vend_ptr != 0xff;)
    {
        uint8_t tag = *vend_ptr;
        if (tag == 0) // Padding
        {
            spprintf(true, true, " Tag: %d (%s)\n", __tabs + 2, __tabs + 3, tag,
                     BOOTP_TAG_MAP[tag] ? BOOTP_TAG_MAP[tag] : "Unknown");
            vend_ptr++;
            continue;
        }
        uint8_t len = *(++vend_ptr);
        u_char value[len + 1];
        memset(value, 0, len + 1);
        memcpy(value, ++vend_ptr, len);
        vend_ptr += len;
        spprintf(true, false, " Tag: %d (%s)\n", __tabs + 2, __tabs + 3, tag,
                 BOOTP_TAG_MAP[tag] ? BOOTP_TAG_MAP[tag] : "Unknown");
        spprintf(true, false, " Len: %d\n", __tabs + 2, __tabs + 3, len);
        if (tag == TAG_IP_LEASE || tag == TAG_RENEWAL_TIME || tag == TAG_REBIND_TIME)
        {
            spprintf(true, true, " Value: %ds\n", __tabs + 2, __tabs + 3, ntohl(*(uint32_t *)value));
            continue;
        }
        if (tag == TAG_SUBNET_MASK || tag == TAG_GATEWAY || tag == TAG_SERVER_ID)
        {
            spprintf(true, true, " Value: %s\n", __tabs + 2, __tabs + 3, inet_ntoa(*(struct in_addr *)value));
            continue;
        }
        switch (tag)
        {
        case TAG_DHCP_MESSAGE:
        {
            spprintf(true, true, " Value: %d (%s)\n", __tabs + 2, __tabs + 3, value[0],
                     BOOTP_DHCP_MESSAGE_MAP[value[0]] ? BOOTP_DHCP_MESSAGE_MAP[value[0]] : "Unknown");
            break;
        }
        case TAG_DOMAIN_SERVER:
        {
            int size = len / 4;
            struct in_addr *addr = (struct in_addr *)value;
            for (int i = 0; i < size; i++)
                spprintf(true, size - 1 == i ? true : false, " Value: %s\n", __tabs + 2, __tabs + 3,
                         inet_ntoa(addr[i]));
            break;
        }
        case TAG_CLIENT_ID: // TYPE:VENDOR...
        {
            spprintf(true, false, " Type: %d (%s)\n", __tabs + 2, __tabs + 3, value[0],
                     BOOTP_CLIENT_ID_TYPE_MAP[value[0]] ? BOOTP_CLIENT_ID_TYPE_MAP[value[0]] : "Unknown");
            switch (value[0])
            {
            case BOOTP_CLIENT_ID_TYPE_ASCII:
                spprintf(true, true, " Value: %s\n", __tabs + 2, __tabs + 3, value + 1);
                break;
            case BOOTP_CLIENT_ID_TYPE_HEX:
            {
                char hex_value[len * 3 + 1];
                memset(hex_value, 0, len * 3 + 1);
                for (int i = 0; i < len - 1; i++)
                    if (i == len - 2)
                        sprintf(hex_value + i * 3, "%02x", value[i + 1]);
                    else
                        sprintf(hex_value + i * 3, "%02x:", value[i + 1]);
                spprintf(true, true, " Value: %s\n", __tabs + 2, __tabs + 3, hex_value);
                break;
            }
            case BOOTP_CLIENT_ID_TYPE_MAC:
                spprintf(true, true, " Value: %x:%x:%x:%x:%x:%x\n", __tabs + 2, __tabs + 3, value[1], value[2],
                         value[3], value[4], value[5], value[6]);
                break;
            }
            break;
        }
        case TAG_REQUESTED_IP:
        {
            spprintf(true, true, " Value: %s\n", __tabs + 2, __tabs + 3, inet_ntoa(*(struct in_addr *)value));
            break;
        }
        case TAG_PARM_REQUEST:
        {
            int size = len;
            for (int i = 0; i < size; i++)
                spprintf(true, size - 1 == i ? true : false, " Value: %d (%s)\n", __tabs + 2, __tabs + 3, value[i],
                         BOOTP_TAG_MAP[value[i]] ? BOOTP_TAG_MAP[value[i]] : "Unknown");
            break;
        }
        case TAG_MAX_MSG_SIZE:
        {
            spprintf(true, true, " Value: %d\n", __tabs + 2, __tabs + 3, ntohs(*(uint16_t *)value));
            break;
        }
        default:
        {
            char hex_value[len * 2 + 1];
            memset(hex_value, 0, len * 2 + 1);
            for (int i = 0; i < len; i++)
                sprintf(hex_value + i * 2, "%02x", value[i]);
            spprintf(true, true, " Value: 0x%s\n", __tabs + 2, __tabs + 3, hex_value);
        }
        }
    }
}

void printf_bootp_header(struct bootp *bootp_header, int __tabs)
{
    switch (verbose_level)
    {
    case CONCISE:
        printf(BWHT " BOOTP " CRESET);
        break;
    case VERBOSE:
        spprintf(true, true, BWHT " BOOTP\n" CRESET, __tabs + 1, __tabs + 2);
        spprintf(true, false, " Opcode: %d (%s)\n", __tabs + 2, __tabs + 2, bootp_header->bp_op,
                 bootp_header->bp_op == BOOTREQUEST ? "Request" : "Reply");
        spprintf(true, false, " HType: %d (%s)\n", __tabs + 2, __tabs + 2, bootp_header->bp_htype,
                 BOOTP_HTYPE_MAP[bootp_header->bp_htype] ? BOOTP_HTYPE_MAP[bootp_header->bp_htype] : "Unknown");
        break;
    case COMPLETE:
        spprintf(true, true, BWHT " BOOTP\n" CRESET, __tabs + 1, __tabs + 2);
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
        spprintf(true, false, " CHAddr: %02x:%02x:%02x:%02x:%02x:%02x\n", __tabs + 2, __tabs + 2,
                 bootp_header->bp_chaddr[0], bootp_header->bp_chaddr[1], bootp_header->bp_chaddr[2],
                 bootp_header->bp_chaddr[3], bootp_header->bp_chaddr[4], bootp_header->bp_chaddr[5]);
        spprintf(true, false, " SName: %s\n", __tabs + 2, __tabs + 2, bootp_header->bp_sname);
        spprintf(true, false, " File: %s\n", __tabs + 2, __tabs + 2, bootp_header->bp_file);
        break;
    }
}

void printf_arp_header(struct ether_arp *arp_header, int __tabs)
{
    switch (verbose_level)
    {
    case CONCISE:
        printf(BCYN " ARP " CRESET);
        break;
    case VERBOSE:
        spprintf(true, true, BCYN " ARP\n" CRESET, __tabs + 1, __tabs + 2);

        spprintf(true, false, " Sender MAC Address: %s\n", __tabs + 2, __tabs + 2,
                 ether_ntoa((struct ether_addr *)arp_header->arp_sha));
        spprintf(true, false, " Sender IP Address: %s\n", __tabs + 2, __tabs + 2,
                 inet_ntoa(*(struct in_addr *)arp_header->arp_spa));
        spprintf(true, false, " Target MAC Address: %s\n", __tabs + 2, __tabs + 2,
                 ether_ntoa((struct ether_addr *)arp_header->arp_tha));
        spprintf(true, true, " Target IP Address: %s\n", __tabs + 2, __tabs + 2,
                 inet_ntoa(*(struct in_addr *)arp_header->arp_tpa));
        break;
    case COMPLETE:
        spprintf(true, true, BCYN " ARP\n" CRESET, __tabs + 1, __tabs + 2);
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
        break;
    }
}

// void printf_icmp_type(struct icmphdr *icmp_header, int __tabs)
// {
//     spprintf(true, icmp_header->type > NR_ICMP_TYPES ? true : false, " Control message: %s\n", __tabs + 2, __tabs +
//     2,
//              icmp_header->type > NR_ICMP_TYPES ? "Unknown" : ICMP_TYPE_MAP[icmp_header->type]);
//     switch (icmp_header->type)
//     {
//     case ICMP_ECHOREPLY:
//         spprintf(true, false, " Identifier: %d\n", __tabs + 2, __tabs + 2, ntohs(icmp_header->un.echo.id));
//         spprintf(true, true, " Sequence Number: %d\n", __tabs + 2, __tabs + 2, ntohs(icmp_header->un.echo.sequence));
//         break;
//     case ICMP_DEST_UNREACH:
//         break;
//     case ICMP_SOURCE_QUENCH:
//         break;
//     case ICMP_REDIRECT:
//         break;
//     case ICMP_ECHO:
//         spprintf(true, false, " Identifier: %d\n", __tabs + 2, __tabs + 2, ntohs(icmp_header->un.echo.id));
//         spprintf(true, true, " Sequence Number: %d\n", __tabs + 2, __tabs + 2, ntohs(icmp_header->un.echo.sequence));
//         break;
//     case ICMP_TIME_EXCEEDED:
//         break;
//     case ICMP_PARAMETERPROB:
//         break;
//     case ICMP_TIMESTAMP:
//         break;
//     case ICMP_TIMESTAMPREPLY:
//         break;
//     case ICMP_INFO_REQUEST:
//         break;
//     case ICMP_INFO_REPLY:
//         break;
//     case ICMP_ADDRESS:
//         break;
//     case ICMP_ADDRESSREPLY:
//         break;
//     default:
//         break;
//     }
// }

void printf_udp_header(struct udphdr *udp_header, int __tabs)
{
    switch (verbose_level)
    {
    case CONCISE:
        printf(BMAG " UDP " CRESET);
        break;
    case VERBOSE:
        spprintf(true, true, BMAG " UDP\n" CRESET, __tabs + 1, __tabs + 2);
        spprintf(true, false, " Source Port: %d\n", __tabs + 2, __tabs + 2, ntohs(udp_header->source));
        spprintf(true, true, " Destination Port: %d\n", __tabs + 2, __tabs + 2, ntohs(udp_header->dest));
        break;
    case COMPLETE:
        spprintf(true, true, BMAG " UDP\n" CRESET, __tabs + 1, __tabs + 2);
        spprintf(true, false, " Source Port: %d\n", __tabs + 2, __tabs + 2, ntohs(udp_header->source));
        spprintf(true, false, " Destination Port: %d\n", __tabs + 2, __tabs + 2, ntohs(udp_header->dest));
        spprintf(true, false, " Length: %d\n", __tabs + 2, __tabs + 2, ntohs(udp_header->len));
        spprintf(true, true, " Checksum: %d\n", __tabs + 2, __tabs + 2, ntohs(udp_header->check));
        break;
    }
}

void printf_tcp_header(struct tcphdr *tcp_header, int __tabs)
{
    switch (verbose_level)
    {
    case CONCISE:
        printf(BBLU " TCP " CRESET);
        break;
    case VERBOSE:
        spprintf(true, true, BBLU " TCP\n" CRESET, __tabs + 1, __tabs + 2);
        spprintf(true, false, " Source Port: %d\n", __tabs + 2, __tabs + 2, ntohs(tcp_header->source));
        spprintf(true, false, " Destination Port: %d\n", __tabs + 2, __tabs + 2, ntohs(tcp_header->dest));
        spprintf(true, true, " Sequence Number: %d\n", __tabs + 2, __tabs + 2, ntohs(tcp_header->seq));
        break;
    case COMPLETE:
        spprintf(true, true, BBLU " TCP\n" CRESET, __tabs + 1, __tabs + 2);
        spprintf(true, false, " Source Port: %d\n", __tabs + 2, __tabs + 2, ntohs(tcp_header->source));
        spprintf(true, false, " Destination Port: %d\n", __tabs + 2, __tabs + 2, ntohs(tcp_header->dest));
        spprintf(true, false, " Sequence Number: %d\n", __tabs + 2, __tabs + 2, ntohs(tcp_header->seq));
        if (tcp_header->ack)
            spprintf(true, false, " Acknowledgment Number: %d\n", __tabs + 2, __tabs + 2, ntohs(tcp_header->ack_seq));
        spprintf(true, false, " Data Offset: %d\n", __tabs + 2, __tabs + 2, tcp_header->doff);
        spprintf(true, false, " Flags: 0x%x\n", __tabs + 2, __tabs + 2, tcp_header->th_flags);
        spprintf(true, false, " Window: %d\n", __tabs + 2, __tabs + 2, ntohs(tcp_header->window));
        spprintf(true, tcp_header->urg ? false : true, " Checksum: 0x%x\n", __tabs + 2, __tabs + 2,
                 ntohs(tcp_header->th_sum));
        if (tcp_header->urg)
            spprintf(true, true, " Urgent Pointer: %d\n", __tabs + 2, __tabs + 2, ntohs(tcp_header->urg_ptr));
        break;
    }
}

void printf_ethernet_header(const struct ether_header *ethernet_header, int __tabs)
{
    // https://en.wikipedia.org/wiki/Ethernet_frame#Structure
    switch (verbose_level)
    {
    case CONCISE:
        printf(BYEL " Ethernet " CRESET);
        break;
    case VERBOSE:
        spprintf(false, false, BYEL "\n\nEthernet\n" CRESET, __tabs, 0);
        spprintf(false, false, " Destination MAC Address: %s\n", __tabs + 1, 1,
                 ether_ntoa((struct ether_addr *)ethernet_header->ether_dhost));
        spprintf(false, true, " Source MAC Address: %s\n", __tabs + 1, 1,
                 ether_ntoa((struct ether_addr *)ethernet_header->ether_shost), __tabs + 1);
        break;
    case COMPLETE:
        spprintf(false, false, BYEL "\n\nEthernet\n" CRESET, __tabs, 0);
        spprintf(false, false, " Destination MAC Address: %s\n", __tabs + 1, 1,
                 ether_ntoa((struct ether_addr *)ethernet_header->ether_dhost));
        spprintf(false, false, " Source MAC Address: %s\n", __tabs + 1, 1,
                 ether_ntoa((struct ether_addr *)ethernet_header->ether_shost), __tabs + 1);
        spprintf(false, true, " Type: %d\n", __tabs + 1, 1, ntohs(ethernet_header->ether_type));
        break;
    }
}

void printf_ip_header(struct ip *ip_header, int __tabs)
{
    switch (verbose_level)
    {
    case CONCISE:
        printf(BGRN " IP " CRESET);
        break;
    case VERBOSE:
        spprintf(true, true, BGRN " IP\n" CRESET, __tabs + 1, __tabs + 2);
        spprintf(true, false, " Source Address: %s\n", __tabs + 2, __tabs + 2, inet_ntoa(ip_header->ip_src));
        spprintf(true, true, " Destination Address: %s\n", __tabs + 2, __tabs + 2, inet_ntoa(ip_header->ip_dst));
        break;
    case COMPLETE:
        spprintf(true, true, BGRN " IP\n" CRESET, __tabs + 1, __tabs + 2);
        spprintf(true, false, " Version: %d\n", __tabs + 2, __tabs + 2, ip_header->ip_v);
        spprintf(true, false, " IHL: %d\n", __tabs + 2, __tabs + 2, ip_header->ip_hl);
        // According to wikipedia ToS = DSCP but this seems to be blurry
        spprintf(true, false, " ToS: %d\n", __tabs + 2, __tabs + 2, ip_header->ip_tos);
        // printf("\tDSCP: %d\n", IPTOS_DSCP(ip_header->ip_tos));
        spprintf(true, false, " ECN: %d\n", __tabs + 2, __tabs + 2, IPTOS_ECN(ip_header->ip_tos));
        spprintf(true, false, " Total Length: %d\n", __tabs + 2, __tabs + 2, ntohs(ip_header->ip_len));
        spprintf(true, false, " ID: 0x%x\n", __tabs + 2, __tabs + 2, ntohs(ip_header->ip_id));
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
        break;
    }
}

void printf_ipv6_header(struct ip6_hdr *ip6_header, int __tabs)
{
    char addrstr[INET6_ADDRSTRLEN];
    switch (verbose_level)
    {
    case CONCISE:
        printf(BRED " IPv6 " CRESET);
        break;
    case VERBOSE:
        spprintf(true, true, BRED " IPv6\n" CRESET, __tabs + 1, __tabs + 2);
        spprintf(true, false, " Source Address: %s\n", __tabs + 2, __tabs + 2,
                 inet_ntop(AF_INET6, &ip6_header->ip6_src, addrstr, sizeof(addrstr)));
        spprintf(true, true, " Destination Address: %s\n", __tabs + 2, __tabs + 2,
                 inet_ntop(AF_INET6, &ip6_header->ip6_dst, addrstr, sizeof(addrstr)));
        break;
    case COMPLETE:
    {
        spprintf(true, true, BRED " IPv6\n" CRESET, __tabs + 1, __tabs + 2);
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
        break;
    }
    }
}

void printf_dns_answer(struct dnsquery *dnsquery, uint16_t n_answer, struct dnshdr *dns_header, int __tabs);

void printf_dns_header(struct dnshdr *dns_header, int __tabs)
{
    if (verbose_level <= COMPLETE && verbose_level >= VERBOSE)
    {
        uint16_t flags_word = dns_header->recursion_desired | (dns_header->truncation << 1) |
                              (dns_header->authoritative_answer << 2) | (dns_header->opcode << 3) |
                              (dns_header->query_or_response << 7) | (dns_header->response_code << 8) |
                              (dns_header->checking_disabled << 12) | (dns_header->authentic_data << 13) |
                              (dns_header->zero << 14) | (dns_header->recursion_available << 15);

        uint16_t n_answer = ntohs(dns_header->n_answers);
        spprintf(true, true, BBLU " DNS\n" CRESET, __tabs + 1, __tabs + 2);
        spprintf(true, false, " Transaction ID: 0x%x\n", __tabs + 2, __tabs + 2, ntohs(dns_header->transactionID));
        spprintf(true, false, " Flags: 0x%x\n", __tabs + 2, __tabs + 2, ntohs(flags_word));
        spprintf(true, false, " Questions: %d\n", __tabs + 2, __tabs + 2, ntohs(dns_header->n_questions));
        spprintf(true, false, " Answer RRs: %d\n", __tabs + 2, __tabs + 2, n_answer);
        spprintf(true, false, " Authority RRs: %d\n", __tabs + 2, __tabs + 2, ntohs(dns_header->n_authority));
        spprintf(true, false, " Additional RRs: %d\n", __tabs + 2, __tabs + 2, ntohs(dns_header->n_additional));

        const char *query = (char *)dns_header + sizeof(struct dnshdr) + 1;
        u_char *query_name;
        int query_name_len = asprintf((char **)&query_name, "%s", query);
        nprint2print(query_name_len, query_name);

        struct dnsquery *dnsquery =
            (struct dnsquery *)((char *)dns_header + sizeof(struct dnshdr) + query_name_len + 2);
        spprintf(true, false, " Query: %s\n", __tabs + 2, __tabs + 2, query_name);
        spprintf(true, false, " Query Type: %ld\n", __tabs + 2, __tabs + 2, ntohs(dnsquery->type));
        spprintf(true, true, " Query Class: %ld\n", __tabs + 2, __tabs + 2, ntohs(dnsquery->class));
        free(query_name);

        if (n_answer > 0 && verbose_level == COMPLETE)
            printf_dns_answer(dnsquery, n_answer, dns_header, __tabs);
    }
    else if (verbose_level == CONCISE)
        printf(BBLU " DNS " CRESET);
}

void printf_dns_answer(struct dnsquery *dnsquery, uint16_t n_answer, struct dnshdr *dns_header, int __tabs)
{
    char *answer = (char *)dnsquery + sizeof(struct dnsquery);
    for (uint16_t i = 0; i < n_answer; i++)
    {

        u_char dns_name[DNS_NAME_MAX_LEN] = {0};
        dns_unpack((char *)dns_header, dns_name, answer);
        // size_t dns_name_len = strlen((char *)dns_name);

        uint16_t label = ntohs(*(uint16_t *)answer);
        uint8_t padding = DNS_IS_COMPRESSED(label) ? 0 : ((label >> 8) + 1);

        struct dnsanswer *dnsanswer = (struct dnsanswer *)(answer + padding);
        uint16_t type = ntohs(dnsanswer->query.type);
        uint16_t class = ntohs(dnsanswer->query.class);
        uint32_t ttl = ntohl(dnsanswer->ttl);
        uint16_t rdlength = ntohs(dnsanswer->rdlength);

        // for (int i = 0; i < sizeof(*dnsanswer); i++)
        //     printf("%02x ", answer[i]);

        u_char rdata[rdlength + 1];
        memset(rdata, 0, rdlength + 1);
        memcpy(rdata, (char *)dnsanswer + sizeof(*dnsanswer), rdlength);
        // for (int i = 0; i < rdlength; i++)
        //     printf("%02x ", rdata[i]);

        spprintf(true, true, BBLU " DNS Answer %d\n" CRESET, __tabs + 3, __tabs + 2, i + 1);
        spprintf(true, false, " Name: %s\n", __tabs + 3, __tabs + 3, dns_name);
        spprintf(true, false, " Type: %ld\n", __tabs + 3, __tabs + 3, type);
        spprintf(true, false, " Class: %ld\n", __tabs + 3, __tabs + 3, class);
        spprintf(true, false, " TTL: %ds\n", __tabs + 3, __tabs + 3, ttl);
        spprintf(true, false, " RDLength: %ld\n", __tabs + 3, __tabs + 3, rdlength);

        switch (type)
        {
        case DNS_TYPE_A:
            spprintf(true, true, " Address: %s\n", __tabs + 3, __tabs + 3, inet_ntoa(*(struct in_addr *)rdata));
            break;
        case DNS_TYPE_AAAA:
            spprintf(true, true, " Address: %s\n", __tabs + 3, __tabs + 3,
                     inet_ntop(AF_INET6, rdata, (char[INET6_ADDRSTRLEN]){0}, INET6_ADDRSTRLEN));
            break;
        case DNS_TYPE_SOA:
        {
            u_char primary_ns[DNS_NAME_MAX_LEN] = {0};
            u_char mailbox[DNS_NAME_MAX_LEN] = {0};

            dns_unpack((char *)dns_header, primary_ns, (char *)dnsanswer + sizeof(*dnsanswer));
            // size_t primary_ns_len = strlen(primary_ns);

            uint16_t label = ntohs(*(uint16_t *)((char *)dnsanswer + sizeof(*dnsanswer)));
            uint8_t padding = DNS_IS_COMPRESSED(label) ? 2 : ((label >> 8) + 2);
            dns_unpack((char *)dns_header, mailbox, (char *)dnsanswer + sizeof(*dnsanswer) + padding);
            size_t mailbox_len = strlen((char *)mailbox);

            struct dnssoa *dnssoa = (struct dnssoa *)((char *)dnsanswer + sizeof(*dnsanswer) + padding + 2 +
                                                      (padding != 2 ? mailbox_len : 0));
            spprintf(true, false, " Primary NS: %s\n", __tabs + 3, __tabs + 3, primary_ns);
            spprintf(true, false, " Mailbox: %s\n", __tabs + 3, __tabs + 3, mailbox);
            spprintf(true, false, " Serial Number: %x\n", __tabs + 3, __tabs + 3, ntohl(dnssoa->serial));
            spprintf(true, false, " Refresh Interval: %d\n", __tabs + 3, __tabs + 3, ntohl(dnssoa->refresh_interval));
            spprintf(true, false, " Retry Interval: %d\n", __tabs + 3, __tabs + 3, ntohl(dnssoa->retry_interval));
            spprintf(true, false, " Expiration Limit: %d\n", __tabs + 3, __tabs + 3, ntohl(dnssoa->expire_limit));
            spprintf(true, true, " Minimum TTL: %d\n", __tabs + 3, __tabs + 3, ntohl(dnssoa->minimum_ttl));

            break;
        }
        default:
        {
            if (type == DNS_TYPE_TXT || type == DNS_TYPE_CNAME || type == DNS_TYPE_NS || type == DNS_TYPE_PTR)
            {
                u_char name[DNS_NAME_MAX_LEN] = {0};
                dns_unpack((char *)dns_header, name, (char *)dnsanswer + sizeof(*dnsanswer));
                spprintf(true, true, " Name: %s\n", __tabs + 3, __tabs + 3, name);
            }
            break;
        }
        }

        answer += sizeof(*dnsanswer) + rdlength + padding;
    }
}