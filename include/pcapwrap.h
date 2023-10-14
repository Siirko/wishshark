#pragma once
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <pcap.h>

#define BUFSIZE 2048

char *get_device_name(bpf_u_int32 *net, bpf_u_int32 *mask);

pcap_t *open_pcap_handle(char *device);

pcap_t *open_pcap_handle_offline(char *filename);

void set_pcap_filter(char *filter_exp, pcap_t *handler, bpf_u_int32 net);

void packet_handler_callback(u_char *args, const struct pcap_pkthdr *packet_header, const u_char *packet_body);
