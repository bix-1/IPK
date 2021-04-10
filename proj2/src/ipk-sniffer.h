/**
 * @file ipk-sniffer.h
 * @brief Header file of ipk-sniffer.cpp
 * @author Jakub Bartko <xbartk07@stud.fit.vutbr.cz>
 */

#ifndef IPK_SNIFFER_H
#define IPK_SNIFFER_H

#include <iostream>

class Options {
    /**
    * Command line options parsing
    */
    public:
        const char * device = NULL; // device to sniff on
        std::string port = "";      // limitation to single port
        int n = 1;                  // number of packets to be processed
        // protocol limitations -- all allowed by default
        bool tcp = false;   // TCP
        bool udp = false;   // UDP
        bool arp = false;   // ARP
        bool icmp = false;  // ICMPv4 or ICMPv6

        /**
         * Parse CL arguments to global object opts
         * @param argc number of arguments
         * @param argv array of arguments
         */
        void get_opts(int argc, char *argv[]);
        /**
         * Return string for packet filter generated from CL options
         * @return filter string to be compiled
         */
        const std::string get_filter();
} opts;

/**
 * Print message with prefix "ERROR: " on STDERR and exits with EXIT_FAILURE
 * @param msg message to be printed
 */
void error(const char *msg);

/****************************************************/
/********************PROGRAM MODES*******************/
/****************************************************/
/**
 * Print all found device names to STDOUT
 */
void print_all_devs();
/**
 * Sniff packets on loop in promiscuous mode and print their data to STDOUT.
 * Uses global object opts for device to open connection and opts.get_filter
 * to generate packet filter string. Calls function handle_packet on each
 * iteration.
 */
void sniff_packets();

/****************************************************/
/********************PACKET TOOLS********************/
/****************************************************/
/**
 * Print header for packet's data accordint to it's protocol in format:
 *      [timestamp] [IP_src] : [port_src] > [IP_dst] : [port_dst], length [N] bytes
 * Where:
 *      timestamp   is in format [YYYY-MM-DD]T[HH:MM:SS.SSS][+|-]HH:MM,
 *                  where [+|-]HH:MM is timezone offset
 *      [IP|port]_[src|dst] are IP address and port of packet's source and destination
 *      N           is size of packet
 * Also calls function print_data to print packet's data byte by byte
 * @param args   **unused**
 * @param header packet's header
 * @param packet packet data
 */
void handle_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
/**
* Print packets's data in following format for each line:
*      [offset]: [bytes_hex] [bytes_ascii]     <--single line
* Where:
*      offset      is offset of each line of bytes in hex format: "0xXXXX"
*      bytes_hex   is array of 16 bytes in hex format: "XX" separated by single space
*      bytes_ascii is array of 16 bytes in ascii format:
*                      if byte_is_printable:
*                          ascii_representation_of_byte
*                      else:
*                          \.      // single dot
 * @param data packet's data
 * @param size size of packet in bytes
 */
void print_data(const u_char *data, const int size);
/**
 * Return packet's timestamp in format:
 *      [YYYY-MM-DD]T[HH:MM:SS.SSS][+|-]HH:MM
 * Where [+|-]HH:MM is timezone offset
 * @param  timer pointer to timeval struct with timestamp's data
 * @return       formatted timestamp
 */
std::string format_timestamp(const timeval *timer);
/**
 * Return packet's formatted IPv4 address
 * @param  addr IPv4 address representation
 * @return      formatted IPv4 address
 */
std::string get_addr_v4(uint32_t addr);

#endif
