/**
 * @file ipk-sniffer.cpp
 * @brief Implementation of packet analyzer for packet capturing & filtering
 * @author Jakub Bartko <xbartk07@stud.fit.vutbr.cz>
 */

/**NOTE
 * https://www.codeproject.com/Questions/463912/Identify-ARP-and-Broadcast-Packets-with-packet-sni
 * LICENSE: https://www.codeproject.com/info/cpol10.aspx
 * ^arph->arp_sha conversion
 */

#include "ipk-sniffer.h"
#include <iostream>         // I/O
#include <string>           // string
#include <cstring>          // strlen
#include <getopt.h>         // CL options
// PACKETS & PROTOCOLS
#include <pcap.h>           // catching & filtering
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

using namespace std;


int main(int argc, char * argv[]) {
    opts.get_opts(argc, argv);  // CL options

    if (opts.device[0] == '\0')
        print_all_devs();
    else
        sniff_packets();

    return 0;
}


void error(const char * msg) {
    cerr << "ERROR: " << msg << endl;
    exit(EXIT_FAILURE);
}


void Options::get_opts(int argc, char * argv[]) {
    opterr = 0; // disable getopt error call
    // define valid CL options
    static struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"device", optional_argument, 0, 'i'},
        {"tcp", no_argument, 0, 't'},
        {"udp", no_argument, 0, 'u'},
        {"arp", no_argument, 0, 'a'},
        {"icmp", no_argument, 0, 'c'},
        {0, 0, 0, 0}
    };

    int opt, opt_index;
    while(true) {
        opt = getopt_long(argc, argv, "hi::p:tun:", long_options, &opt_index);
        const char * arg = optarg;
        if (opt == -1) break;
        switch (opt) {
            // help
            case 'h':
                cout << "usage: [--interface | --interface INTERFACE] [-p PORT] [--tcp] [--udp] [--arp] [--icmp] [-n NUM]" << endl << endl;
                cout << "Packet analyzer for packet capturing, filtering & analysing." << endl << endl;
                cout << "required arguments:\n";
                cout << "  -i, --interface\tprint list of active network interfaces & exit\n";
                cout << "  -i INTERFACE, --interface INTERFACE\n\t\t\tnetwork interface to sniff on\n";
                cout << "optional arguments:\n";
                cout << "  -p PORT\t\tlimitation to single port; unlimited by default\n";
                cout << "  -n NUM\t\tnumber of protocols to be sniffed\n";
                cout << "{protocol limitations; stackable; unlimited by default}:\n";
                cout << "  -t, --tcp\t\tTCP protocol\n";
                cout << "  -u, --udp\t\tUDP protocol\n";
                cout << "  --arp\t\t\tARP protocol\n";
                cout << "  --icmp\t\tICMPv4 & ICMPv6 protocols\n";
                exit(EXIT_SUCCESS);

            // opts with argument
            case 'i': case 'p': case 'n':
                // check if following opt might be current opt's argument
                if (!optarg && argv[optind] != NULL && argv[optind][0] != '-') {
                    arg = argv[optind++];
                }
                // handle opts
                switch (opt) {
                    case 'i':
                        opts.device = (arg) ? arg : "";
                        break;
                    case 'p':
                        opts.port = static_cast<string>(arg);
                        break;
                    case 'n':
                        size_t i;
                        if (!isdigit(arg[0]) && arg[0] != '-') error("Invalid num");
                        opts.n = stoi(arg, &i);
                        if (i < strlen(arg)) error("Invalid num");
                        break;
                }
                break;

            // opts without argument
            case 't': opts.tcp  = true; break;
            case 'u': opts.udp  = true; break;
            case 'a': opts.arp  = true; break;
            case 'c': opts.icmp = true; break;

            default:
                error("Invalid CL argument");
        }
    }
    // validation
    if (optind < argc) error("Invalid arguments");
    if (!opts.device) error("Missing --interface option");
}


const string Options::get_filter() {
    string filter;
    // protocols
    if (opts.tcp || opts.udp || opts.arp || opts.icmp) {
        filter = "(";
        if (opts.tcp)   filter += "tcp or ";
        if (opts.udp)   filter += "udp or ";
        if (opts.arp)   filter += "arp or ";
        if (opts.icmp)  filter += "icmp or icmp6 or ";
        filter = filter.substr(0, filter.length()-4);
        filter += ')';
    }
    // port
    if (!empty(opts.port)) {
        if (!filter.empty()) filter += " and ";
        filter += "port " + opts.port;
    }

    return filter;
}


void print_all_devs() {
    // get all devs
    pcap_if_t * alldevs;
    if (pcap_findalldevs(&alldevs, NULL) == PCAP_ERROR)
        error("Failed to find devices");
    // print names of devs
    int cnt = 0;
    for (pcap_if_t * dev = alldevs; dev != NULL; dev = dev->next) {
        cout << dev->name << endl;
        cnt++;
    }
    // free list of devs
    if (cnt == 0)
        cerr << "No devices found\n";
    else
        pcap_freealldevs(alldevs);
}


void sniff_packets() {
    pcap_t * handle;
    struct bpf_program filter;
    char errbuf[PCAP_ERRBUF_SIZE];

    // open session in promiscuous mode
    handle = pcap_open_live(opts.device, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) error("Failed to open device");

    // compile & set filter
    const string f_str = opts.get_filter();
    if (pcap_compile(handle, &filter, f_str.c_str(), 1, 0) == -1)
        error("Failed to compile filter");
    if (pcap_setfilter(handle, &filter) == -1)
        error("Failed to set filter");

    // iterate given number of packets
    pcap_loop(handle, opts.n, handle_packet, NULL);

    pcap_close(handle);
}


void handle_packet(
    u_char *args,
    const struct pcap_pkthdr *header,
    const u_char *packet
) {
    (void)args; // options that won't be used
    // output buffers
    string saddr, daddr, sport, dport;

    // get timestamp & packet length
    string timestamp = format_timestamp(&header->ts);
    int length = header->len;

    // get packet's info according to its protocol
    struct ether_header *eptr = (struct ether_header *) packet;
    switch (ntohs(eptr->ether_type)) {
        case ETHERTYPE_IP: {
            // get IP
            struct iphdr *iph = (struct iphdr*)(packet + sizeof(struct ethhdr));
            saddr = get_addr_v4(iph->saddr);
            daddr = get_addr_v4(iph->daddr);

            // get ports
            switch (iph->protocol) {
                case 6: {   // TCP
                    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct ethhdr) + sizeof(struct ip));
                    sport = to_string(ntohs(tcph->th_sport));
                    dport = to_string(ntohs(tcph->th_dport));
                    break;
                }
                case 17: {  // UDP
                    struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct ethhdr) + sizeof(struct ip));
                    sport = to_string(ntohs(udph->uh_sport));
                    dport = to_string(ntohs(udph->uh_dport));
                    break;
                }
                default:
                    break;
            }
            break;
        }
        case ETHERTYPE_IPV6: {
            // get address
            struct ip6_hdr *ip6_h = (struct ip6_hdr*)(packet + sizeof(struct ethhdr));
            char tmp[INET6_ADDRSTRLEN];
            saddr = inet_ntop(AF_INET6, &ip6_h->ip6_src, tmp, sizeof(tmp));
            daddr = inet_ntop(AF_INET6, &ip6_h->ip6_dst, tmp, sizeof(tmp));
            break;
        }
        case ETHERTYPE_ARP: {
            // get address
            char buf[100];
            snprintf(
                buf, sizeof(buf),
                "%02x:%02x:%02x:%02x:%02x:%02x",
                eptr->ether_shost[0],
                eptr->ether_shost[1],
                eptr->ether_shost[2],
                eptr->ether_shost[3],
                eptr->ether_shost[4],
                eptr->ether_shost[5]
            );
            saddr = buf;
            snprintf(
                buf, sizeof(buf),
                "%02x:%02x:%02x:%02x:%02x:%02x",
                eptr->ether_dhost[0],
                eptr->ether_dhost[1],
                eptr->ether_dhost[2],
                eptr->ether_dhost[3],
                eptr->ether_dhost[4],
                eptr->ether_dhost[5]
            );
            daddr = buf;
            break;
        }
        default:
            break;
    }

    // correct port strings for output
    if (!sport.empty()) sport.insert(0, " : ");
    if (!dport.empty()) dport.insert(0, " : ");

    // print header of output
    cout << timestamp << " " << saddr << sport << " > " << daddr << dport;
    cout << ", length " << length << " bytes\n";
    // print packet's data
    print_data(packet, length);
}


void print_data(const u_char *data, const int size) {
    int offset = 0, i;
    char buff[17];
    u_char c;
    // iterate byte by byte
    while (offset < size) {
        // print offset
        printf("0x%04x:", offset);
        // print bytes in HEX
        for (i = 0; (i < 16) && (i+offset < size); i++) {
            c = data[offset+i];
            printf(" %02x", c);
            buff[i] = (isprint(c)) ? c : '.';
        }
        // print bytes in ASCII
        buff[i] = '\0';
        cout << "  " << buff << endl;
        offset += 16;
    }
    cout << endl;
}


string format_timestamp(const timeval * timer) {
    // format time as string:   YYYY-MM-DD\THH:MM:SS+offset
    string timestamp;
    char buf[50];

    // get local time from packet timestamp
    struct tm *timeptr = localtime(&timer->tv_sec);
    // get date & time
    strftime(buf, sizeof(buf)-1, "%FT%T", timeptr);
    timestamp = buf;

    // append decimal part of seconds
    timestamp += '.' + to_string(timer->tv_usec).substr(0, 3);

    // append timezone offset as +HH:MM
    size_t len = strftime(buf, sizeof(buf)-1, "%z", timeptr);
    if (len < 2) return timestamp;   // tz might be unavailable
    timestamp += buf;
    timestamp.insert(timestamp.length()-2, ":");

    return timestamp;
}


string get_addr_v4(uint32_t in) {
    string out;
    for (int i=0; i<4; i++) {
        out += to_string(in >> (i*8) & 0xFF);
        out += ".";
    }
    out.back() = '\0';
    return out;
}
