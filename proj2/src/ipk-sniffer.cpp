/**
 * @file ipk-sniffer.cpp
 * @brief Implementation of packet analyzer for packet capturing & filtering
 * @author Jakub Bartko <xbartk07@stud.fit.vutbr.cz>
 */

/**
 * TODO
 *
 */

/**
 * NOTE
 * https://www.codeproject.com/Questions/463912/Identify-ARP-and-Broadcast-Packets-with-packet-sni
 * LICENSE: https://www.codeproject.com/info/cpol10.aspx
 * ^arph->arp_sha conversion
 */


#include "ipk-sniffer.h"
#include <iostream>
#include <string>
#include <cstring>
#include <getopt.h>

#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>

using namespace std;


int main(int argc, char * argv[]) {
    // get CL options
    get_opts(argc, argv);

    if (opts.device[0] == '\0')
        print_all_devs();
    else {
        pcap_t * handle;
        struct bpf_program filter;
        bpf_u_int32 mask, net;
        char errbuf[PCAP_ERRBUF_SIZE];

        // get netmask
        if (pcap_lookupnet(opts.device, &net, &mask, errbuf) == -1) {
            cerr << "Failed to get netmask for device\n";
            net = 0; mask = 0;
        }
        // open session in promiscuous mode
        handle = pcap_open_live(opts.device, BUFSIZ, 1, 1000, errbuf);
        if (handle == NULL) error("Failed to open device");
        // set filter
        if (pcap_compile(handle, &filter, opts.filter.c_str(), 1, 0) == -1)
            error("Failed to compile filter");
        if (pcap_setfilter(handle, &filter) == -1)
            error("Failed to set filter");
        // iterate given number of packets
        pcap_loop(handle, opts.n, handle_packet, NULL);

        pcap_close(handle);
    }

    return 0;
}


void error(const char * msg) {
    cerr << "ERROR: " << msg << endl;
    exit(EXIT_FAILURE);
}


void get_opts(int argc, char * argv[]) {
    opterr = 0; // disable getopt error call
    // define CL options
    static struct option long_options[] = {
        {"device", optional_argument, 0, 'i'},
        {"tcp", no_argument, 0, 't'},
        {"udp", no_argument, 0, 'u'},
        {"arp", no_argument, 0, 'a'},
        {"icmp", no_argument, 0, 'c'},
        {0, 0, 0, 0}
    };

    int opt, opt_index;
    while(true) {
        opt = getopt_long(argc, argv, "i::p:tun:", long_options, &opt_index);
        const char * arg = optarg;
        if (opt == -1) break;
        switch (opt) {
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
                        opts.add_filter("port " + static_cast<string>(arg));
                        break;
                    case 'n':
                        size_t i;
                        if (!isdigit(arg[0]) && arg[0] != '-') error("Invalid num");
                        opts.n = stoi(arg, &i);
                        if (i < strlen(arg)) error("Invalid num");
                        break;
                }
                break;
            case 't': opts.add_filter("tcp"); break;
            case 'u': opts.add_filter("udp"); break;
            case 'a': opts.add_filter("arp"); break;
            case 'c': opts.add_filter("icmp or icmp6"); break;

            default:
                error("Invalid CL argument");
        }
    }
    // validation
    if (optind < argc) error("Invalid arguments");
    if (!opts.device) error("Missing --interface option");
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
        cout << "No devices found\n";
    else
        pcap_freealldevs(alldevs);
}


void handle_packet(
    u_char *args,
    const struct pcap_pkthdr *header,
    const u_char *packet
) {
    // get timestamp
    string timestamp = format_timestamp(&header->ts);


    struct ether_header *eptr = (struct ether_header *) packet;
    struct iphdr *iph = NULL;
    struct ip6_hdr *ip6_h = NULL;
    struct ether_arp *arph = NULL;
    string src, dst, protocol;
    char tmp[INET6_ADDRSTRLEN];
    switch (ntohs(eptr->ether_type)) {
        case ETHERTYPE_IP:
            iph = (struct iphdr*)(packet + sizeof(struct ethhdr));
            src = get_addr_v4(iph->saddr);
            dst = get_addr_v4(iph->daddr);

            switch (iph->protocol) {
                case 1:
                    protocol = "ICMP";
                    break;

                case 6:
                    protocol = "TCP";
                    break;

                case 17:
                    protocol = "UDP";
                    break;

                default:
                    break;
            }
            break;

        case ETHERTYPE_IPV6:
            protocol = "ICMPv6";
            ip6_h = (struct ip6_hdr*)(packet + sizeof(struct ethhdr));
            inet_ntop(AF_INET6, &ip6_h->ip6_src, tmp, sizeof(tmp));
            src = tmp;
            inet_ntop(AF_INET6, &ip6_h->ip6_dst, tmp, sizeof(tmp));
            dst = tmp;
            break;

        case ETHERTYPE_ARP:
            protocol = "ARP";
            arph = (struct ether_arp*)(packet + sizeof(struct ethhdr));
            char buf[100];
            snprintf(
                buf, sizeof(buf),
                "%02x:%02x:%02x:%02x:%02x:%02x",
                arph->arp_sha[0],
                arph->arp_sha[1],
                arph->arp_sha[2],
                arph->arp_sha[3],
                arph->arp_sha[4],
                arph->arp_sha[5]
            );
            src = buf;
            snprintf(
                buf, sizeof(buf),
                "%02x:%02x:%02x:%02x:%02x:%02x",
                arph->arp_tha[0],
                arph->arp_tha[1],
                arph->arp_tha[2],
                arph->arp_tha[3],
                arph->arp_tha[4],
                arph->arp_tha[5]
            );
            dst = buf;
            break;

        default:
            break;
    }

    // print output
    cout << timestamp << " " << src << " > " << dst << "\t\t" << protocol << endl;
}


string format_timestamp(const timeval * timer) {
    char timebuf[100];
    // get local time from packet timestamp
    struct tm *timeptr = localtime(&timer->tv_sec);
    // format time as string:   YYYY-MM-DD\THH:MM:SS+offset
    //      %F == YYYY-MM-DD, %T == HH:MM:SS, %z == offset
    size_t length = strftime(timebuf, sizeof(timebuf)-1, "%FT%T%z", timeptr);
    // add ":" to separate offset HH & MM
    if (length < 2) return timebuf;
    string timestamp = timebuf;
    timestamp.insert(length-2, ":");

    return timestamp;
}


std::string get_addr_v4(uint32_t in) {
    string out;
    for (int i=0; i<4; i++) {
        out += to_string(in >> (i*8) & 0xFF);
        out += ".";
    }
    out.back() = '\0';
    return out;
}
