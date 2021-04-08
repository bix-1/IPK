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


using namespace std;


int main(int argc, char * argv[]) {
    // get CL options
    get_opts(argc, argv);

    if (opts.interface[0] == '\0') {
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
        // get handle for reading
        pcap_t * handle = pcap_create(opts.interface, NULL);
        struct bpf_program filter;

        if (handle == NULL) error("Failed to open handle");
        pcap_set_promisc(handle, true);
        if (pcap_activate(handle) != 0) {
            pcap_close(handle);
            error("Failed to activate handle");
        }

        cout << opts.filter.c_str() << endl;
        pcap_compile(handle, &filter, opts.filter.c_str(), 1, 0);
        pcap_setfilter(handle, &filter);
        pcap_loop(handle, opts.n, process_packet, NULL);
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
        {"interface", optional_argument, 0, 'i'},
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
                        opts.interface = (arg) ? arg : "";
                        break;
                    case 'p':
                        opts.filter += "port ";
                        opts.filter += arg;
                        opts.filter += " ";
                        break;
                    case 'n':
                        size_t i;
                        if (!isdigit(arg[0])) error("Invalid port");
                        opts.n = stoi(arg, &i);
                        if (i < strlen(arg)) error("Invalid port");
                        break;
                }
                break;
            case 't': opts.filter += "tcp ";   break;
            case 'u': opts.filter += "udp ";   break;
            case 'a': opts.filter += "arp ";   break;
            case 'c': opts.filter += "icmp ";   break;


            default:
                error("Invalid CL argument");
        }
    }
    // validation
    if (optind < argc) error("Invalid arguments");
    if (!opts.interface) error("Missing --interface option");
}


int icmp = 0, igmp = 0, tcp = 0, udp = 0, others = 0, total = 0;
void process_packet(u_char *user, const struct pcap_pkthdr *header, const u_char *bytes) {
    total++;
    int size = header->len;
	//Get the IP Header part of this packet , excluding the ethernet header
	struct iphdr *iph = (struct iphdr*)(bytes + sizeof(struct ethhdr));
	switch (iph->protocol) //Check the Protocol and do accordingly...
	{
		case 1:  //ICMP Protocol
			++icmp;
			break;

		case 2:  //IGMP Protocol
			++igmp;
			break;

		case 6:  //TCP Protocol
			++tcp;
			break;

		case 17: //UDP Protocol
			++udp;
			break;

		default: //Some Other Protocol like ARP etc.
			++others;
			break;
	}
	printf("TCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Others : %d   Total : %d\n", tcp , udp , icmp , igmp , others , total);
}
