#include "../include/args_parser.h"
#include "../include/cprintf.h"
#include "../include/pcapwrap.h"
#include "../include/show.h"
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

struct arguments arguments;

void initiate_args(int argc, char *argv[])
{

    arguments.verbose_level = 3;
    arguments.interface = "";
    arguments.input_file = "";
    argp_parse(&argp, argc, argv, 0, 0, &arguments);
}

int main(int argc, char **argv)
{
    initiate_args(argc, argv);
    bpf_u_int32 net, mask = 0;
    char *dev;
    pcap_t *handle;
    if (arguments.interface == "" && arguments.input_file == "")
    {
        dev = get_device_name(&net, &mask);
        handle = open_pcap_handle(dev);
    }
    else if (arguments.interface == "" && arguments.input_file != "")
        handle = open_pcap_handle_offline(arguments.input_file);
    else if (arguments.interface != "" && arguments.input_file == "")
        handle = open_pcap_handle(arguments.interface);

    pcap_loop(handle, -1, packet_handler_callback, NULL);
    pcap_close(handle);
    return 0;
}
