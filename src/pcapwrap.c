#include "../include/pcapwrap.h"
#include "../include/cprintf.h"
#include "../include/show.h"
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

char *get_device_name(bpf_u_int32 *net, bpf_u_int32 *mask)
{
    char *dev, errbuf[PCAP_ERRBUF_SIZE];

    dev = pcap_lookupdev(errbuf);
    if (dev == NULL)
    {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }
    if (pcap_lookupnet(dev, net, mask, errbuf) == -1)
    {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev,
                errbuf);
        exit(EXIT_FAILURE);
    }
    deprintf("Net -> %s\n", inet_ntoa(*(struct in_addr *)net));
    deprintf("Mask -> %s\n", inet_ntoa(*(struct in_addr *)mask));
    deprintf("Device -> %s\n", dev);
    return dev;
}

pcap_t *open_pcap_handle(char *dev)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    int delay = 1000; // in ms
    int to_promisc = 1;
    pcap_t *handle = pcap_open_live(dev, BUFSIZE, to_promisc, delay, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        exit(EXIT_FAILURE);
    }
    return handle;
}

void apply_filter(char *filter_exp, pcap_t *handler, bpf_u_int32 net)
{
    struct bpf_program fp;
    if (pcap_compile(handler, &fp, filter_exp, 0, net) == -1)
    {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp,
                pcap_geterr(handler));
        exit(EXIT_FAILURE);
    }
    if (pcap_setfilter(handler, &fp) == -1)
    {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp,
                pcap_geterr(handler));
        exit(EXIT_FAILURE);
    }
    deprintf("Filter -> %s\n", filter_exp);
}

void packet_handler_callback(u_char *args,
                             const struct pcap_pkthdr *packet_header,
                             const u_char *packet_body)
{
    // struct ether_header *ethernet_header = (struct ether_header
    // *)packet_body;
    s_ethernet_packet(packet_body, packet_header, 0);
}