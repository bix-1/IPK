/**
 * @file ipk-sniffer.cpp
 * @brief Implementation of packet analyzer for packet capturing & filtering
 * @author Jakub Bartko <xbartk07@stud.fit.vutbr.cz>
 */


#include <iostream>
#include <getopt.h>

using namespace std;


void error(string msg) {
    cerr << "ERROR: " << msg << std::endl;
    exit(EXIT_FAILURE);
}


int main(int argc, char * argv[]) {
    opterr = 0; // disable getopt error call
    // define CL options
    static struct option long_options[] = {
        {"interface", optional_argument, 0, 'i'},
        {0, 0, 0, 0}
    };

    int opt, opt_index;
    const char * interface = NULL;
    while(true) {
        opt = getopt_long(argc, argv, "i::", long_options, &opt_index);
        const char * arg = optarg;
        if (opt == -1) break;
        switch (opt) {
            case 'i':
                // check if following opt might be current opt's argument
                if (!optarg && argv[optind] != NULL && argv[optind][0] != '-') {
                    arg = argv[optind];
                }
                if (arg)
                    interface = arg;
                else
                    interface = "";
                break;

            default:
                error("Invalid CL argument");
        }
    }

    if (!interface) {
        error("Missing --interface option");
    }
    else if (interface[0] == '\0') {
        cout << "Get interfaces...\n";
    }
    else {
        cout << "Interface: " << interface << endl;
    }

    return 0;
}
