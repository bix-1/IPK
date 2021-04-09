/**
 * @file ipk-sniffer.h
 * @brief Header file of ipk-sniffer.cpp
 * @author Jakub Bartko <xbartk07@stud.fit.vutbr.cz>
 */

#ifndef IPK_SNIFFER_H
#define IPK_SNIFFER_H

#include <iostream>   // error()

void error(const char * msg);

struct Opts {
    const char * device = NULL;
    std::string filter = "";
    int n = 1;
} opts;

void get_opts(int argc, char *argv[]);

void handle_packet(u_char *user, const struct pcap_pkthdr *header, const u_char *bytes);

std::string format_timestamp(const timeval * timer);

#endif
