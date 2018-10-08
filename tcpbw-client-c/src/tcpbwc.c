/*
 * SIMET2 MA - TCP Bandwidth Measurement (tcpbw) client
 * Copyright (c) 2018 NIC.br  <medicoes@simet.nic.br>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "tcpbwc_config.h"
#include "tcpbwc.h"

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
    fprintf(stderr, "Usage: %s [-h] [-4|-6] [-t <timeout>] [-l <test duration>] [-c <number of streams>] "
	    "[-d <agent-id>] [-j <token> ] "
	    "<server URL>\n", p);
    if (mode) {
	fprintf(stderr, "\n"
		"\t-h\tprint usage help and exit\n"
		"\t-4\ttest over IPv4 (default)\n"
		"\t-6\ttest over IPv6\n"
		"\t-t\tconnection timeout in seconds\n"
		"\t-l\tbandwidth measurement duration in seconds (each direction)\n"
		"\t-c\tnumber of desired concurrent streams\n"
		"\t-d\tmeasurement agent id\n"
		"\t-j\taccess credentials\n"
		"\nserver URL: measurement server URL\n\n");
    }
    exit((mode)? EXIT_SUCCESS : EXIT_FAILURE);
}


int main(int argc, char **argv) {
    char *agent_id = NULL;
    char *control_url = NULL;
    char *token = NULL;
    int family = 4;
    int timeout_test = 30;
    int test_lenght = 11;
    int numstreams = 5;

    int option;

    /* FIXME: parameter range checking, proper error messages, strtoul instead of atoi */
    while ((option = getopt (argc, argv, "46hVc:l:t:d:j:")) != -1) {
        switch (option) {
	    case '4':
		family = 4;
		break;
	    case '6':
		family = 6;
		break;
	    case 'l':
		test_lenght = atoi(optarg);
		break;
            case 't':
                timeout_test = atoi(optarg);
                break;
	    case 'c':
		numstreams = atoi(optarg);
		break;
            case 'd':
                agent_id = optarg;
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

    control_url = argv[optind];

    MeasureContext ctx = {
	.agent_id = agent_id,
	.host_name = NULL,
	.port = NULL,
	.control_url = control_url,
	.token = token,
	.family = family,
	.timeout_test = (timeout_test <= 0 || timeout_test > 40) ? 40 : timeout_test,
	.numstreams = (numstreams < 1 || numstreams > MAX_CONCURRENT_SESSIONS) ? MAX_CONCURRENT_SESSIONS : numstreams,
	.test_duration = (test_lenght < 1 || test_lenght > 60) ? 60 : test_lenght,
	.sessionid = NULL,
	.sample_period_ms = 500U,
    };

    int value = tcp_client_run(ctx);

    if (value != 0) {
        fprintf(stderr, "TCP CLIENT RUN ERROR\n");
    }

    return 0;
}
