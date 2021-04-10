/**
 * @file ipk-sniffer.h
 * @brief Header file of ipk-sniffer.cpp
 * @author Jakub Bartko <xbartk07@stud.fit.vutbr.cz>
 */

#ifndef IPK_SNIFFER_H
#define IPK_SNIFFER_H

#include <iostream>   // error()

void error(const char * msg);

class Opts {
    public:
        const char * device = NULL;
        std::string filter = "";
        std::string port = "";
        int n = 1;
        bool tcp = false;
        bool udp = false;
        bool arp = false;
        bool icmp = false;

        const std::string get_filter();
} opts;

void get_opts(int argc, char *argv[]);

void print_all_devs();

void handle_packet(u_char *user, const struct pcap_pkthdr *header, const u_char *bytes);

std::string format_timestamp(const timeval * timer);
std::string get_addr_v4(uint32_t addr);

#endif
