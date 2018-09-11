/* Simple TCP Client */
#include "tcpc_config.h"
#include "tcp.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>


static const char program_copyright[]=
	"Copyright (c) 2018 NIC.br\n\n"
	"This is free software; see the source for copying conditions.\n"
	"There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR\n"
	"A PARTICULAR PURPOSE.\n";

static void print_version(void)
{
    fprintf(stdout, "%s %s\n%s\n", PACKAGE_NAME, PACKAGE_VERSION, program_copyright);
    exit(EXIT_SUCCESS);
}

static void print_usage(const char * const p, int mode)
{
    fprintf(stderr, "Usage: %s [-h] [-4|-6] [-p <service port>] [-t <timeout>] "
	    "[-d <device id>] "
	    "<server>\n", p);
    if (mode) {
	fprintf(stderr, "\n"
		"\t-h\tprint usage help and exit\n"
		"\t-4\tuse IPv4, instead of system default\n"
		"\t-6\tuse IPv6, instead of system default\n"
		"\t-t\tconnection timeout in seconds\n"
		"\t-d\tdevice identification string to send to the measurement server\n"
		"\t-p\tservice name or numeric port of the measurement server\n"
		"\nserver: hostname or IP address of the measurement server\n\n");
    }
    exit((mode)? EXIT_SUCCESS : EXIT_FAILURE);
}


int main(int argc, char **argv) {

    char *device_id = NULL;
    char *host_name = NULL;
    char *control_url = "http://docker.lab.simet.nic.br:8800/tcp-control";
    char *token = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJUY3BEb3dubG9hZE1lYXN1cmUiLCJleHAiOjE5MjA2MTY3OTMsImlzcyI6InNpbWV0Lm5pYy5iciIsIm1lYXN1cmVfdHlwZSI6Imh0dHBzRG93bmxvYWQifQ.XXGglVdL6Qb2VYi62hf94X--UsxTXMB0elNzRl2_XKM";
    char *port = "20000";
    int family = 0;
    int timeout_test = 30;

    int option;

    while ((option = getopt (argc, argv, "46hVc:f:p:t:d:j:")) != -1) {
        switch (option) {
	    case '4':
		family = 4;
		break;
	    case '6':
		family = 6;
		break;
            case 'c':
                control_url = optarg;
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
            case 'd':
                device_id = optarg;
                break;
            case 'j':
                token = optarg;
                break;
	    case 'h':
		print_usage(argv[0], 1);
		/* fall-through */ /* silence bogus warning */
	    case 'V':
		print_version();
		/* fall-through */ /* silence bogus warning */
	    default:
		print_usage(argv[0], 0);
        }
    };

    if (optind >= argc || argc - optind != 1)
	print_usage(argv[0], 0);

    host_name = argv[optind];

    MeasureContext ctx;
    ctx.device_id = device_id;
    ctx.host_name = host_name;
    ctx.control_url = control_url;
    ctx.port = port;
    ctx.token = token;
    ctx.family = family;
    ctx.timeout_test = (timeout_test <= 0 || timeout_test > 40) ? 40 : timeout_test;

    int value = tcp_client_run(ctx);

    if (value != 0) {
        fprintf(stderr, "TCP CLIENT RUN ERROR\n");
    }

    return 0;
}
