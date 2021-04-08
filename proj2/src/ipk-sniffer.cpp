/**
 * @file ipk-sniffer.cpp
 * @brief Implementation of packet analyzer for packet capturing & filtering
 * @author Jakub Bartko <xbartk07@stud.fit.vutbr.cz>
 */

/**
 * TODO
 *  citation for opt parsing??
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

    if (handles.interface[0] == '\0') {
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
    } else {
        cout << "Interface: " << handles.interface << endl;

    }

    return 0;
}


void error(string msg) {
    cerr << "ERROR: " << msg << std::endl;
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
                        handles.interface = (arg) ? arg : "";
                        break;
                    case 'p':
                        size_t i;
                        if (!isdigit(arg[0])) error("Invalid port");
                        handles.port = stoi(arg, &i);
                        if (i < strlen(arg)) error("Invalid port");
                        break;
                    case 'n':
                        if (!isdigit(arg[0])) error("Invalid port");
                        handles.n = stoi(arg, &i);
                        if (i < strlen(arg)) error("Invalid port");
                        break;
                }
                break;
            case 't': handles.tcp = true;   break;
            case 'u': handles.udp = true;   break;
            case 'a': handles.arp = true;   break;
            case 'c': handles.icmp = true;  break;

            default:
                error("Invalid CL argument");
        }
    }
    // validation
    if (optind < argc) error("Invalid arguments");
    if (!handles.interface) error("Missing --interface option");
}
