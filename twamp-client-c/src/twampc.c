/* Simple TWAMP Client */
#include "twamp.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>

int main(int argc, char **argv) {

    char *device_id = "device_id";
    char *host = "twamp-server";
    char *port = "862";
    int family = 4;
    int timeout_test = 15;
    int packet_count = 50;
    int packet_interval_ns = 100000;

    int option;

    while ((option = getopt (argc, argv, "h:f:p:t:c:i:d:")) != -1) {
        switch (option) {
            case 'h':
                host = optarg;
                break;
            case 'f':
                family = atoi(optarg);
                break;
            case 'p':
                port = optarg;
                break;
            case 't':
                timeout_test = atoi(optarg);
                break;
            case 'c':
                packet_count = atoi(optarg);
                break;
            case 'i':
                packet_interval_ns = atoi(optarg);
                break;
            case 'd':
                device_id = optarg;
                break;
            case '?':
                fprintf (stderr,"Unknown option character `\\x%x'.\n", optopt);
                return 1;
        }
    };

    TWAMPParameters param;
    param.device_id = device_id;
    param.host = host;
    param.port = port;
    param.family = family;
    param.timeout_test = (timeout_test <= 0 || timeout_test > 30) ? 30 : timeout_test;
    param.packets_count = (unsigned int)((packet_count <= 0 || packet_count > 100) ? 100 : packet_count);
    param.packets_interval_ns = (unsigned int)(packet_interval_ns);

    int value = twamp_run_client(param);

    if (value != 0) {
        fprintf(stderr, "TWAMP-CLIENT ERROR\n");
        return 0;
    }

    fprintf(stderr, "TWAMP-CLIENT OK\n");
    return 0;
}
