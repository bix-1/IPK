## file: README

## author: Jakub Bartko, xbartk07@stud.fit.vutbr.cz

Program ipk-sniffer is a packet analyzer implemented as part of 2nd project variant: ZETA for course IPK at FIT BUT, 2021.

List of submitted files:
	README
	Makefile
	ipk-sniffer.cpp
	ip-sniffer.h
	manual.pdf

Use `make` build executable file. RUN WITH ROOT PRIVILEGES.

Usage: [--interface | --interface INTERFACE] [-p PORT] [--tcp] [--udp] [--arp] [--icmp] [-n NUM]
  -h, --help		print this help
required arguments:
  -i, --interface	print list of active network interfaces & exit
  -i INTERFACE, --interface INTERFACE
			network interface to sniff on
optional arguments:
  -p PORT		limitation to single port; unlimited by default
  -n NUM		number of protocols to be sniffed
{protocol limitations; stackable; unlimited by default}:
  -t, --tcp		TCP protocol
  -u, --udp		UDP protocol
  --arp			ARP protocol
  --icmp		ICMPv4 & ICMPv6 protocols


Examples:
	./ipk-sniffer -i
	eth0
	lo

	./ipk-sniffer -i eth0 -p 443 --tcp
	2021-04-13T10:10:10.778+02:00 192.1.1.1 : 52434 > 91.1.1.1 : 443, length 74 bytes
	0x0000: 4c c5 3e 2e d2 10 f8 a2 d6 66 e9 47 08 00 45 00  L.>......f.G..E.
	0x0010: 00 3c 24 0c 40 00 40 06 39 ac c0 a8 64 76 5b bd  .<$.@.@.9...dv[.
	0x0020: 5c 28 cc d2 01 bb fa c3 0b f1 00 00 00 00 a0 02  \(..............
	0x0030: fa f0 dd 32 00 00 02 04 05 b4 04 02 08 0a de d1  ...2............
	0x0040: 25 43 00 00 00 00 01 03 03 07  %C........
