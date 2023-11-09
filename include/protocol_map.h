#include "bootp.h"
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

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

const char *BOOTP_DHCP_MESSAGE_MAP[] = {
    [DHCPDISCOVER] = "DHCP Discover", [DHCPOFFER] = "DHCP Offer",   [DHCPREQUEST] = "DHCP Request",
    [DHCPDECLINE] = "DHCP Decline",   [DHCPACK] = "DHCP ACK",       [DHCPNAK] = "DHCP NAK",
    [DHCPRELEASE] = "DHCP Release",   [DHCPINFORM] = "DHCP Inform",
};

const char *BOOTP_HTYPE_MAP[] = {
    [BOOTP_HTYPE_ETHERNET] = "Ethernet",  [BOOTP_HTYPE_IEEE802] = "IEEE 802 Networks", [BOOTP_HTYPE_ARCNET] = "ARCENT",
    [BOOTP_HTYPE_FRELAY] = "Frame Relay", [BOOTP_HTYPE_ATM] = "Async Transfer Mode",   [BOOTP_HTYPE_HDLC] = "HDLC",
};

const char *BOOTP_CLIENT_ID_TYPE_MAP[] = {
    [BOOTP_CLIENT_ID_TYPE_ASCII] = "ASCII",
    [BOOTP_CLIENT_ID_TYPE_HEX] = "Hex",
    [BOOTP_CLIENT_ID_TYPE_MAC] = "MAC",
};

// Could've been simplier with X macros, but didn't want to bother
// this code is not mine, I just want to make it work

// create map with TAG defines associated with a string
const char *BOOTP_TAG_MAP[] = {
    [TAG_PAD] = "PAD",
    [TAG_SUBNET_MASK] = "Subnet Mask",
    [TAG_TIME_OFFSET] = "Time Offset",
    [TAG_GATEWAY] = "Gateway",
    [TAG_TIME_SERVER] = "Time Server",
    [TAG_NAME_SERVER] = "Name Server",
    [TAG_DOMAIN_SERVER] = "Domain Server",
    [TAG_LOG_SERVER] = "Log Server",
    [TAG_COOKIE_SERVER] = "Cookie Server",
    [TAG_LPR_SERVER] = "LPR Server",
    [TAG_IMPRESS_SERVER] = "Impress Server",
    [TAG_RLP_SERVER] = "RLP Server",
    [TAG_HOSTNAME] = "Hostname",
    [TAG_BOOTSIZE] = "Bootsize",
    [TAG_END] = "End",
    [TAG_DUMPPATH] = "Dump Path",
    [TAG_DOMAINNAME] = "Domain Name",
    [TAG_SWAP_SERVER] = "Swap Server",
    [TAG_ROOTPATH] = "Root Path",
    [TAG_EXTPATH] = "Ext Path",
    [TAG_IP_FORWARD] = "IP Forward",
    [TAG_NL_SRCRT] = "NL Srcrt",
    [TAG_PFILTERS] = "P Filters",
    [TAG_REASS_SIZE] = "Reass Size",
    [TAG_DEF_TTL] = "Def TTL",
    [TAG_MTU_TIMEOUT] = "MTU Timeout",
    [TAG_MTU_TABLE] = "MTU Table",
    [TAG_INT_MTU] = "Int MTU",
    [TAG_LOCAL_SUBNETS] = "Local Subnets",
    [TAG_BROAD_ADDR] = "Broad Addr",
    [TAG_DO_MASK_DISC] = "Do Mask Disc",
    [TAG_SUPPLY_MASK] = "Supply Mask",
    [TAG_DO_RDISC] = "Do Rdisc",
    [TAG_RTR_SOL_ADDR] = "Rtr Sol Addr",
    [TAG_STATIC_ROUTE] = "Static Route",
    [TAG_USE_TRAILERS] = "Use Trailers",
    [TAG_ARP_TIMEOUT] = "ARP Timeout",
    [TAG_ETH_ENCAP] = "Eth Encap",
    [TAG_TCP_TTL] = "TCP TTL",
    [TAG_TCP_KEEPALIVE] = "TCP Keepalive",
    [TAG_KEEPALIVE_GO] = "Keepalive Go",
    [TAG_NIS_DOMAIN] = "NIS Domain",
    [TAG_NIS_SERVERS] = "NIS Servers",
    [TAG_NTP_SERVERS] = "NTP Servers",
    [TAG_VENDOR_OPTS] = "Vendor Opts",
    [TAG_NETBIOS_NS] = "Netbios NS",
    [TAG_NETBIOS_DDS] = "Netbios DDS",
    [TAG_NETBIOS_NODE] = "Netbios Node",
    [TAG_NETBIOS_SCOPE] = "Netbios Scope",
    [TAG_XWIN_FS] = "Xwin FS",
    [TAG_XWIN_DM] = "Xwin DM",
    [TAG_NIS_P_DOMAIN] = "NIS P Domain",
    [TAG_NIS_P_SERVERS] = "NIS P Servers",
    [TAG_MOBILE_HOME] = "Mobile Home",
    [TAG_SMPT_SERVER] = "SMTP Server",
    [TAG_POP3_SERVER] = "POP3 Server",
    [TAG_NNTP_SERVER] = "NNTP Server",
    [TAG_WWW_SERVER] = "WWW Server",
    [TAG_FINGER_SERVER] = "Finger Server",
    [TAG_IRC_SERVER] = "IRC Server",
    [TAG_STREETTALK_SRVR] = "Streettalk Server",
    [TAG_STREETTALK_STDA] = "Streettalk Stda",
    // DHCP Options
    [TAG_REQUESTED_IP] = "Requested IP",
    [TAG_IP_LEASE] = "IP Lease",
    [TAG_OPT_OVERLOAD] = "Opt Overload",
    [TAG_TFTP_SERVER] = "TFTP Server",
    [TAG_BOOTFILENAME] = "Bootfilename",
    [TAG_DHCP_MESSAGE] = "DHCP Message",
    [TAG_SERVER_ID] = "Server ID",
    [TAG_PARM_REQUEST] = "Parm Request",
    [TAG_MESSAGE] = "Message",
    [TAG_MAX_MSG_SIZE] = "Max Msg Size",
    [TAG_RENEWAL_TIME] = "Renewal Time",
    [TAG_REBIND_TIME] = "Rebind Time",
    [TAG_VENDOR_CLASS] = "Vendor Class",
    [TAG_CLIENT_ID] = "Client ID",
};

const char *DNS_TYPE_MAP[] = {
    [DNS_TYPE_A] = "A",     [DNS_TYPE_NS] = "NS",   [DNS_TYPE_CNAME] = "CNAME", [DNS_TYPE_SOA] = "SOA",
    [DNS_TYPE_PTR] = "PTR", [DNS_TYPE_TXT] = "TXT", [DNS_TYPE_AAAA] = "AAAA",
};