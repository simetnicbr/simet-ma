/* Simple TWAMP Client */
#include "twamp.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>

static void usage(const char * const p, int mode)
{
    fprintf(stderr, "Usage: %s [-h] [-4|-6] [-p <service port>] [-t <timeout (s)>] "
	    "[-c <packet count>] [-i <interpacket interval (ns)>] [-d <device id>] "
	    "<server>\n", p);
    if (mode) {
	fprintf(stderr, "\n"
		"\t-h\tprint usage help and exit\n"
		"\t-4\tuse IPv4, instead of system default\n"
		"\t-6\tuse IPv6, instead of system default\n"
		"\t-t\tconnection timeout in seconds\n"
		"\t-c\tnumber of packets to transmit per session\n"
		"\t-i\ttime in nanoseconds between each packet (lower bound)\n"
		"\t-d\tdevice identification string to send to the TWAMP server\n"
		"\t-p\tservice name or numeric port of the TWAMP server\n"
		"\nserver: hostname or IP address of the TWAMP server\n\n");
    }
    exit((mode)? EXIT_SUCCESS : EXIT_FAILURE);
}

int main(int argc, char **argv)
{
    char *device_id = NULL;
    char *host = NULL;
    char *port = "862";
    int family = 0;
    int timeout_test = 15;
    int packet_count = 50;
    int packet_interval_ns = 100000;

    int option;

    while ((option = getopt(argc, argv, "46hp:t:c:i:d:")) != -1) {
        switch(option) {
	case '4':
	    family = 4;
	    break;
	case '6':
	    family = 6;
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
	case 'h':
	    usage(argv[0], 1);
	    /* fall-through */ /* silence bogus warning */
	default:
	    usage(argv[0], 0);
        }
    }

    if (optind >= argc || argc - optind != 1)
	usage(argv[0], 0);

    host = argv[optind];

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
