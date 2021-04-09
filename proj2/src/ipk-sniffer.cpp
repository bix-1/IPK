/**
 * @file ipk-sniffer.cpp
 * @brief Implementation of packet analyzer for packet capturing & filtering
 * @author Jakub Bartko <xbartk07@stud.fit.vutbr.cz>
 */

/**
 * TODO
 *
 */


#include "ipk-sniffer.h"
#include <iostream>
#include <string>
#include <cstring>
#include <getopt.h>

#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>
#include <netinet/ether.h>

using namespace std;


int main(int argc, char * argv[]) {
    // get CL options
    get_opts(argc, argv);

    if (opts.device[0] == '\0') {
        // get all devices
        pcap_if_t * alldevs;
        if (pcap_findalldevs(&alldevs, NULL) == PCAP_ERROR)
            error("Failed to find devices");
        // list add devices
        int cnt = 0;
        for (pcap_if_t * dev = alldevs; dev != NULL; dev = dev->next) {
            cout << dev->name << endl;
            cnt++;
        }
        // free list of devices
        if (cnt == 0)
            cout << "No devices found\n";
        else
            pcap_freealldevs(alldevs);
    }
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
                        opts.filter += "port ";
                        opts.filter += arg;
                        opts.filter += " ";
                        break;
                    case 'n':
                        size_t i;
                        if (!isdigit(arg[0]) && arg[0] != '-') error("Invalid num");
                        opts.n = stoi(arg, &i);
                        if (i < strlen(arg)) error("Invalid num");
                        break;
                }
                break;
            case 't': opts.filter += "tcp ";   break;
            case 'u': opts.filter += "udp ";   break;
            case 'a': opts.filter += "arp ";   break;
            case 'c': opts.filter += "icmp icmp6 ";   break;

            default:
                error("Invalid CL argument");
        }
    }
    // validation
    if (optind < argc) error("Invalid arguments");
    if (!opts.device) error("Missing --interface option");
}


void handle_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    // get timestamp
    auto timestamp = format_timestamp(&header->ts);

    string prot;
    // int size = header->len;
    //Get the IP Header part of this packet , excluding the ethernet header
    struct iphdr *iph = (struct iphdr*)(packet + sizeof(struct ethhdr));
    switch (iph->protocol) //Check the Protocol and do accordingly...
    {
    	case 1:
        case 128:
    		prot = "ICMP";
    		break;

    	case 6:
            prot = "TCP";
    		break;

    	case 17:
    		prot = "UDP";
    		break;

    	default: // other protocols
            struct ether_header *eptr = (struct ether_header *) packet;
            if (ntohs (eptr->ether_type) == ETHERTYPE_ARP)
                prot = "ARP";
            else prot = "?????";   // TODO del
    		break;
    }

    // u_int16_t handle_ethernet(
    //     u_char *args,const struct pcap_pkthdr* pkthdr,const u_char *packet
    // ){
    //     struct ether_header *eptr = (struct ether_header *) packet;
    //     fprintf(stdout,"ethernet header source: %s"
    //             ,ether_ntoa((const struct ether_addr *)&eptr->ether_shost));
    //     fprintf(stdout," destination: %s "
    //             ,ether_ntoa((const struct ether_addr *)&eptr->ether_dhost));
    // }

    cout << timestamp << " " << prot << endl;
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
