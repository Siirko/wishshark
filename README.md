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

  -i, --interface=INTERFACE  Interface for live analysis
  -o, --file=PCAP_FILE       PCAP file for offline analysis
  -v, --verbosity=<1..3>     Verbosity : 1 = Concise, 2 = Verbose, 3 =
                             Complete
  -?, --help                 Give this help list
      --usage                Give a short usage message
  -V, --version              Print program version

Mandatory or optional arguments to long options are also mandatory or optional
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
$ ./bin/wishsark -i yourinterfacename
```

