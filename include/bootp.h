// took from
// https://opensource.apple.com/source/tcpdump/tcpdump-1/tcpdump/bootp.h.auto.html

/* @(#) $Header: /cvs/Darwin/Commands/Other/tcpdump/tcpdump/bootp.h,v 1.1.1.1
 * 2001/07/07 00:50:53 bbraun Exp $ (LBL) */
/*
 * Bootstrap Protocol (BOOTP).  RFC951 and RFC1048.
 *
 * This file specifies the "implementation-independent" BOOTP protocol
 * information which is common to both client and server.
 *
 * Copyright 1988 by Carnegie Mellon.
 *
 * Permission to use, copy, modify, and distribute this program for any
 * purpose and without fee is hereby granted, provided that this copyright
 * and permission notice appear on all copies and supporting documentation,
 * the name of Carnegie Mellon not be used in advertising or publicity
 * pertaining to distribution of the program without specific prior
 * permission, and notice be given in supporting documentation that copying
 * and distribution is by permission of Carnegie Mellon and Stanford
 * University.  Carnegie Mellon makes no representations about the
 * suitability of this software for any purpose.  It is provided "as is"
 * without express or implied warranty.
 */
#pragma once
#include "../include/cprintf.h"
#include <arpa/inet.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include <string.h>
struct bootp
{
    u_int8_t bp_op;           /* packet opcode type */
    u_int8_t bp_htype;        /* hardware addr type */
    u_int8_t bp_hlen;         /* hardware addr length */
    u_int8_t bp_hops;         /* gateway hops */
    u_int32_t bp_xid;         /* transaction ID */
    u_int16_t bp_secs;        /* seconds since boot began */
    u_int16_t bp_flags;       /* flags: 0x8000 is broadcast */
    struct in_addr bp_ciaddr; /* client IP address */
    struct in_addr bp_yiaddr; /* 'your' IP address */
    struct in_addr bp_siaddr; /* server IP address */
    struct in_addr bp_giaddr; /* gateway IP address */
    u_int8_t bp_chaddr[16];   /* client hardware address */
    u_int8_t bp_sname[64];    /* server host name */
    u_int8_t bp_file[128];    /* boot file name */
    u_int8_t bp_vend[64];     /* vendor-specific area */
};

/*
 * UDP port numbers, server and client.
 */
#define IPPORT_BOOTPS 67
#define IPPORT_BOOTPC 68

#define BOOTREPLY 2
#define BOOTREQUEST 1

/*
 * Vendor magic cookie (v_magic) for CMU
 */
#define VM_CMU "CMU"

/*
 * Vendor magic cookie (v_magic) for RFC1048
 */
#define VM_RFC1048                                                                                                     \
    {                                                                                                                  \
        99, 130, 83, 99                                                                                                \
    }

#define CHECK_MAGIC_COOKIE(a) ((a)[0] == 99 && (a)[1] == 130 && (a)[2] == 83 && (a)[3] == 99)

/*
 * RFC1048 tag values used to specify what information is being supplied in
 * the vendor field of the packet.
 */

#define TAG_PAD ((u_int8_t)0)
#define TAG_SUBNET_MASK ((u_int8_t)1)
#define TAG_TIME_OFFSET ((u_int8_t)2)
#define TAG_GATEWAY ((u_int8_t)3)
#define TAG_TIME_SERVER ((u_int8_t)4)
#define TAG_NAME_SERVER ((u_int8_t)5)
#define TAG_DOMAIN_SERVER ((u_int8_t)6)
#define TAG_LOG_SERVER ((u_int8_t)7)
#define TAG_COOKIE_SERVER ((u_int8_t)8)
#define TAG_LPR_SERVER ((u_int8_t)9)
#define TAG_IMPRESS_SERVER ((u_int8_t)10)
#define TAG_RLP_SERVER ((u_int8_t)11)
#define TAG_HOSTNAME ((u_int8_t)12)
#define TAG_BOOTSIZE ((u_int8_t)13)
#define TAG_END ((u_int8_t)255)
/* RFC1497 tags */
#define TAG_DUMPPATH ((u_int8_t)14)
#define TAG_DOMAINNAME ((u_int8_t)15)
#define TAG_SWAP_SERVER ((u_int8_t)16)
#define TAG_ROOTPATH ((u_int8_t)17)
#define TAG_EXTPATH ((u_int8_t)18)
/* RFC2132 */
#define TAG_IP_FORWARD ((u_int8_t)19)
#define TAG_NL_SRCRT ((u_int8_t)20)
#define TAG_PFILTERS ((u_int8_t)21)
#define TAG_REASS_SIZE ((u_int8_t)22)
#define TAG_DEF_TTL ((u_int8_t)23)
#define TAG_MTU_TIMEOUT ((u_int8_t)24)
#define TAG_MTU_TABLE ((u_int8_t)25)
#define TAG_INT_MTU ((u_int8_t)26)
#define TAG_LOCAL_SUBNETS ((u_int8_t)27)
#define TAG_BROAD_ADDR ((u_int8_t)28)
#define TAG_DO_MASK_DISC ((u_int8_t)29)
#define TAG_SUPPLY_MASK ((u_int8_t)30)
#define TAG_DO_RDISC ((u_int8_t)31)
#define TAG_RTR_SOL_ADDR ((u_int8_t)32)
#define TAG_STATIC_ROUTE ((u_int8_t)33)
#define TAG_USE_TRAILERS ((u_int8_t)34)
#define TAG_ARP_TIMEOUT ((u_int8_t)35)
#define TAG_ETH_ENCAP ((u_int8_t)36)
#define TAG_TCP_TTL ((u_int8_t)37)
#define TAG_TCP_KEEPALIVE ((u_int8_t)38)
#define TAG_KEEPALIVE_GO ((u_int8_t)39)
#define TAG_NIS_DOMAIN ((u_int8_t)40)
#define TAG_NIS_SERVERS ((u_int8_t)41)
#define TAG_NTP_SERVERS ((u_int8_t)42)
#define TAG_VENDOR_OPTS ((u_int8_t)43)
#define TAG_NETBIOS_NS ((u_int8_t)44)
#define TAG_NETBIOS_DDS ((u_int8_t)45)
#define TAG_NETBIOS_NODE ((u_int8_t)46)
#define TAG_NETBIOS_SCOPE ((u_int8_t)47)
#define TAG_XWIN_FS ((u_int8_t)48)
#define TAG_XWIN_DM ((u_int8_t)49)
#define TAG_NIS_P_DOMAIN ((u_int8_t)64)
#define TAG_NIS_P_SERVERS ((u_int8_t)65)
#define TAG_MOBILE_HOME ((u_int8_t)68)
#define TAG_SMPT_SERVER ((u_int8_t)69)
#define TAG_POP3_SERVER ((u_int8_t)70)
#define TAG_NNTP_SERVER ((u_int8_t)71)
#define TAG_WWW_SERVER ((u_int8_t)72)
#define TAG_FINGER_SERVER ((u_int8_t)73)
#define TAG_IRC_SERVER ((u_int8_t)74)
#define TAG_STREETTALK_SRVR ((u_int8_t)75)
#define TAG_STREETTALK_STDA ((u_int8_t)76)
/* DHCP options */
#define TAG_REQUESTED_IP ((u_int8_t)50)
#define TAG_IP_LEASE ((u_int8_t)51)
#define TAG_OPT_OVERLOAD ((u_int8_t)52)
#define TAG_TFTP_SERVER ((u_int8_t)66)
#define TAG_BOOTFILENAME ((u_int8_t)67)
#define TAG_DHCP_MESSAGE ((u_int8_t)53)
#define TAG_SERVER_ID ((u_int8_t)54)
#define TAG_PARM_REQUEST ((u_int8_t)55)
#define TAG_MESSAGE ((u_int8_t)56)
#define TAG_MAX_MSG_SIZE ((u_int8_t)57)
#define TAG_RENEWAL_TIME ((u_int8_t)58)
#define TAG_REBIND_TIME ((u_int8_t)59)
#define TAG_VENDOR_CLASS ((u_int8_t)60)
#define TAG_CLIENT_ID ((u_int8_t)61)
/* RFC 2241 */
#define TAG_NDS_SERVERS ((u_int8_t)85)
#define TAG_NDS_TREE_NAME ((u_int8_t)86)
#define TAG_NDS_CONTEXT ((u_int8_t)87)
/* RFC 2485 */
#define TAG_OPEN_GROUP_UAP ((u_int8_t)98)
/* RFC 2563 */
#define TAG_DISABLE_AUTOCONF ((u_int8_t)116)
/* RFC 2610 */
#define TAG_SLP_DA ((u_int8_t)78)
#define TAG_SLP_SCOPE ((u_int8_t)79)
/* RFC 2937 */
#define TAG_NS_SEARCH ((u_int8_t)117)
/* RFC 3011 */
#define TAG_IP4_SUBNET_SELECT ((u_int8_t)118)
/* ftp://ftp.isi.edu/.../assignments/bootp-dhcp-extensions */
#define TAG_USER_CLASS ((u_int8_t)77)
#define TAG_SLP_NAMING_AUTH ((u_int8_t)80)
#define TAG_CLIENT_FQDN ((u_int8_t)81)
#define TAG_AGENT_CIRCUIT ((u_int8_t)82)
#define TAG_AGENT_REMOTE ((u_int8_t)83)
#define TAG_AGENT_MASK ((u_int8_t)84)
#define TAG_TZ_STRING ((u_int8_t)88)
#define TAG_FQDN_OPTION ((u_int8_t)89)
#define TAG_AUTH ((u_int8_t)90)
#define TAG_VINES_SERVERS ((u_int8_t)91)
#define TAG_SERVER_RANK ((u_int8_t)92)
#define TAG_CLIENT_ARCH ((u_int8_t)93)
#define TAG_CLIENT_NDI ((u_int8_t)94)
#define TAG_CLIENT_GUID ((u_int8_t)97)
#define TAG_LDAP_URL ((u_int8_t)95)
#define TAG_6OVER4 ((u_int8_t)96)
#define TAG_PRINTER_NAME ((u_int8_t)100)
#define TAG_MDHCP_SERVER ((u_int8_t)101)
#define TAG_IPX_COMPAT ((u_int8_t)110)
#define TAG_NETINFO_PARENT ((u_int8_t)112)
#define TAG_NETINFO_PARENT_TAG ((u_int8_t)113)
#define TAG_URL ((u_int8_t)114)
#define TAG_FAILOVER ((u_int8_t)115)
#define TAG_EXTENDED_REQUEST ((u_int8_t)126)
#define TAG_EXTENDED_OPTION ((u_int8_t)127)

#define BOOTP_CLIENT_ID_TYPE_ASCII 0
#define BOOTP_CLIENT_ID_TYPE_HEX 1
#define BOOTP_CLIENT_ID_TYPE_MAC 2

/* DHCP Message types (values for TAG_DHCP_MESSAGE option) */
#define DHCPDISCOVER 1
#define DHCPOFFER 2
#define DHCPREQUEST 3
#define DHCPDECLINE 4
#define DHCPACK 5
#define DHCPNAK 6
#define DHCPRELEASE 7
#define DHCPINFORM 8

/*
 * "vendor" data permitted for CMU bootp clients.
 */

struct cmu_vend
{
    u_int8_t v_magic[4];           /* magic number */
    u_int32_t v_flags;             /* flags/opcodes, etc. */
    struct in_addr v_smask;        /* Subnet mask */
    struct in_addr v_dgate;        /* Default gateway */
    struct in_addr v_dns1, v_dns2; /* Domain name servers */
    struct in_addr v_ins1, v_ins2; /* IEN-116 name servers */
    struct in_addr v_ts1, v_ts2;   /* Time servers */
    u_int8_t v_unused[24];         /* currently unused */
};

/* v_flags values */
#define VF_SMASK 1 /* Subnet mask field contains valid data */

// I will not bother to implement other ones, I have other things to do
// https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml#arp-parameters-2
#define BOOTP_HTYPE_ETHERNET 1
#define BOOTP_HTYPE_IEEE802 6
#define BOOTP_HTYPE_ARCNET 7
#define BOOTP_HTYPE_FRELAY 15
#define BOOTP_HTYPE_ATM 16
#define BOOTP_HTYPE_HDLC 17

static const char *BOOTP_DHCP_MESSAGE_MAP[] = {
    [DHCPDISCOVER] = "DHCP Discover", [DHCPOFFER] = "DHCP Offer",   [DHCPREQUEST] = "DHCP Request",
    [DHCPDECLINE] = "DHCP Decline",   [DHCPACK] = "DHCP ACK",       [DHCPNAK] = "DHCP NAK",
    [DHCPRELEASE] = "DHCP Release",   [DHCPINFORM] = "DHCP Inform",
};

#pragma GCC diagnostic ignored "-Wunused-variable"
static const char *BOOTP_HTYPE_MAP[] = {
    [BOOTP_HTYPE_ETHERNET] = "Ethernet",  [BOOTP_HTYPE_IEEE802] = "IEEE 802 Networks", [BOOTP_HTYPE_ARCNET] = "ARCENT",
    [BOOTP_HTYPE_FRELAY] = "Frame Relay", [BOOTP_HTYPE_ATM] = "Async Transfer Mode",   [BOOTP_HTYPE_HDLC] = "HDLC",
};
#pragma GCC diagnostic pop

static const char *BOOTP_CLIENT_ID_TYPE_MAP[] = {
    [BOOTP_CLIENT_ID_TYPE_ASCII] = "ASCII",
    [BOOTP_CLIENT_ID_TYPE_HEX] = "Hex",
    [BOOTP_CLIENT_ID_TYPE_MAC] = "MAC",
};

// Could've been simplier with X macros (see telnet.h to give you an idea), but didn't want to bother
// this code is not mine, I just want to make it work

static const char *BOOTP_TAG_MAP[] = {
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

static inline void bootp_tag_display(uint8_t tag, uint8_t len, u_char *value, int __tabs)
{
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
            spprintf(true, size - 1 == i ? true : false, " Value: %s\n", __tabs + 2, __tabs + 3, inet_ntoa(addr[i]));
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
            spprintf(true, true, " Value: %x:%x:%x:%x:%x:%x\n", __tabs + 2, __tabs + 3, value[1], value[2], value[3],
                     value[4], value[5], value[6]);
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
    // and so on...
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

static inline void bootp_vendor_show(uint8_t *vend_ptr, int __tabs)
{
    for (; *vend_ptr != 0xff;)
    {
        uint8_t tag = *vend_ptr;
        if (tag == 0)
        {
            spprintf(true, true, " Tag: %d (%s)\n", __tabs + 2, __tabs + 3, tag,
                     BOOTP_TAG_MAP[tag] ? BOOTP_TAG_MAP[tag] : "Unknown");
            vend_ptr++;
            continue; // we skip padding
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
        bootp_tag_display(tag, len, value, __tabs);
    }
}