/**
 * @file ipk-sniffer.h
 * @brief Header file of ipk-sniffer.cpp
 * @author Jakub Bartko <xbartk07@stud.fit.vutbr.cz>
 */

#ifndef IPK_SNIFFER_H
#define IPK_SNIFFER_H

#include <iostream>   // error()

void error(std::string msg);

struct Handles {
    const char * interface = NULL;
    int port = -1;
    bool tcp = false;
    bool udp = false;
    bool arp = false;
    bool icmp = false;
    int n = 1;
} handles;

void get_opts(int argc, char * argv[]);

#endif
