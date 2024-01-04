#include "../include/args_parser.h"
#include "../include/cprintf.h"
#include "../include/pcapwrap.h"
#include "../include/show.h"
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct arguments arguments;

enum VerboseLevel verbose_level = 3;

void initiate_args(int argc, char *argv[])
{

    arguments.verbose_level = 3;
    arguments.interface = "";
    arguments.input_file = "";
    arguments.filter = "";
    argp_parse(&argp, argc, argv, 0, 0, &arguments);
    verbose_level = arguments.verbose_level;
}

int main(int argc, char **argv)
{
    initiate_args(argc, argv);
    bpf_u_int32 net, mask = 0;
    char *dev;
    pcap_t *handle;
    if (strcmp(arguments.interface, "") == 0 && strcmp(arguments.input_file, "") == 0)
    {
        dev = get_device_name(&net, &mask);
        handle = open_pcap_handle(dev);
    }
    else if (strcmp(arguments.interface, "") == 0 && strcmp(arguments.input_file, "") != 0)
        handle = open_pcap_handle_offline(arguments.input_file);
    else if (strcmp(arguments.interface, "") != 0 && strcmp(arguments.input_file, "") == 0)
        handle = open_pcap_handle(arguments.interface);

    if (strcmp(arguments.filter, "") != 0)
        set_pcap_filter(arguments.filter, handle, net);

    CHK_PCAP(pcap_loop(handle, -1, packet_handler_callback, NULL), handle);
    pcap_close(handle);
    return 0;
}
