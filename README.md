# wishshark
Packet sniffer (Low cost version of wireshark)

## Support
IP (v6, v4), ARP, ICMP, TCP, UDP, HTTP, DNS, DHCP (and BOOTP), IMAP, POP3, FTP, SMTP, TELNET

## Usage
```
$ make
$ ./bin/wishsark --help

Usage: wishshark [OPTION...]
Cheap version of Wireshark.

  -f, --filter=FILTER        Filter to apply to the analysis (check
                             https://www.tcpdump.org/manpages/pcap-filter.7.html)
  -i, --interface=INTERFACE  Interface for live analysis
  -o, --file=PCAP_FILE       PCAP file for offline analysis
  -v, --verbosity=<1..3>     Verbosity : 1 = Concise, 2 = Verbose, 3 = Complete
                            
  -?, --help                 Give this help list
      --usage                Give a short usage message
  -V, --version              Print program version

Mandatory or optional arguments to long options are also mandatory or optional
for any corresponding short options.
```

## Examples 
### Online usage
```
$ sudo ./bin/wishsark
```
will listen to your default network default in verbose mode 3.

### Offline usage
```
$ ./bin/wishshark -o ./samples/...
```

### With Interface
```
$ sudo ./bin/wishsark -i yourinterfacename
```
### With filter
```
$ ./bin/wishshark -v 1 -f "tcp" -o samples/ftp.pcap 
```
Set verbosity to 1, apply filter "tcp" and analyze the file samples/ftp.pcap

