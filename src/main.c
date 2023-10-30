#include "../include/cprintf.h"
#include "../include/pcapwrap.h"
#include "../include/show.h"
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    bpf_u_int32 net, mask = 0;
    (void)argc;
    char *dev = get_device_name(&net, &mask);
    pcap_t *handle = open_pcap_handle_offline(argv[1]);
    pcap_loop(handle, -1, packet_handler_callback, NULL);

    pcap_close(handle);
    return 0;
}
