#include "../include/cprintf.h"
#include "../include/pcapwrap.h"
#include "../include/show.h"
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    bpf_u_int32 net, mask = 0;
    // char filter_exp[] = "port 80";
    const u_char *packet;
    struct pcap_pkthdr header;

    char *dev = get_device_name(&net, &mask);
    pcap_t *handle = open_pcap_handle(dev);

    pcap_loop(handle, -1, packet_handler_callback, NULL);

    pcap_close(handle);
    return 0;
}
