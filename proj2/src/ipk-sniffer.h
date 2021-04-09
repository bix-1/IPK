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
        int n = 1;

        void add_filter(std::string f) {
            filter += (empty(filter)) ? f : " or "+f;
        }
} opts;

void get_opts(int argc, char *argv[]);

void print_all_devs();

void handle_packet(u_char *user, const struct pcap_pkthdr *header, const u_char *bytes);

std::string format_timestamp(const timeval * timer);
std::string get_addr_v4(uint32_t addr);

#endif
