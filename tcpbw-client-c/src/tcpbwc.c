/*
 * SIMET2 MA - TCP Bandwidth Measurement (tcpbw) client
 * Copyright (c) 2018,2019 NIC.br <medicoes@simet.nic.br>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.  In every case, additional
 * restrictions and permissions apply, refer to the COPYING file in the
 * program Source for details.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License and the COPYING file in the program Source
 * for details.
 */

#include "tcpbwc_config.h"
#include "tcpbwc.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <getopt.h>

#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <time.h>

#include "simet_err.h"
#include "logger.h"

int log_level = 2;
const char *progname = PACKAGE_NAME;


static int is_valid_fd(const int fd)
{
    return fcntl(fd, F_GETFD) != -1 || errno != EBADF;
}

static void fix_fds(const int fd, const int fl)
{
    int nfd;

    if (is_valid_fd(fd))
            return;

    nfd = open("/dev/null", fl);
    if (nfd == -1 || dup2(nfd, fd) == -1) {
            print_err("could not attach /dev/null to file descriptor %d: %s",
                      fd, strerror(errno));
            /* if (nfd != -1) close(nfd); - disabled as we're going to exit() now */
            exit(SEXIT_FAILURE);
    }
    if (nfd != fd)
            close(nfd);
}

/*
 * glibc does not ensure sanity of the standard streams at program start
 * for non suid/sgid applications.  The streams are initialized as open
 * and not in an error state even when their underlying FDs are invalid
 * (closed).  These FDs will later become valid due to an unrelated
 * open(), which will cause undesired behavior (such as data corruption)
 * should the stream be used.
 *
 * freopen() cannot be used to fix this directly, due to a glibc 2.14+ bug
 * when freopen() is called on an open stream that has an invalid FD which
 * also happens to be the first available FD.
 */
static void sanitize_std_fds(void)
{
   /* do it in file descriptor numerical order! */
   fix_fds(STDIN_FILENO,  O_RDONLY);
   fix_fds(STDOUT_FILENO, O_WRONLY);
   fix_fds(STDERR_FILENO, O_RDWR);
}

static const char program_copyright[]=
	"Copyright (c) 2018,2019 NIC.br\n\n"
	"This is free software; see the source for copying conditions.\n"
	"There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR\n"
	"A PARTICULAR PURPOSE.\n";

static void print_version(void)
{
    fprintf(stdout, "%s %s\n%s\n", PACKAGE_NAME, PACKAGE_VERSION, program_copyright);
    exit(SEXIT_SUCCESS);
}

static void print_usage(const char * const p, int mode)
{
    fprintf(stderr, "Usage: %s [-h] [-q] [-v] [-V] [-4|-6] [-t <timeout>] [-l <test duration>] [-c <number of streams>] "
	    "[-d <agent-id>] [-j <token> ] [-r <report_mode>] [-o <path>]"
	    "<server URL>\n", p);
    if (mode) {
	fprintf(stderr, "\n"
		"\t-h\tprint usage help and exit\n"
		"\t-V\tprint program version and copyright, and exit\n"
		"\t-v\tverbose mode (repeat for increased verbosity)\n"
		"\t-q\tquiet mode (repeat for errors-only)\n"
		"\t-4\ttest over IPv4 (default)\n"
		"\t-6\ttest over IPv6\n"
		"\t-t\tconnection timeout in seconds\n"
		"\t-l\tbandwidth measurement duration in seconds (each direction)\n"
		"\t-c\tnumber of desired concurrent streams\n"
		"\t-d\tmeasurement agent id\n"
		"\t-j\taccess credentials\n"
		"\t-r\treport mode: 0 = comma-separated, 1 = json array\n"
		"\t-o\tredirect report output to <path>\n"
		"\nserver URL: measurement server URL\n\n");
    }
    exit((mode)? SEXIT_SUCCESS : SEXIT_BADCMDLINE);
}


int main(int argc, char **argv) {
    char *agent_id = NULL;
    char *control_url = NULL;
    char *token = NULL;
    int family = 6;
    int report_mode = 0;
    int timeout_test = 30;
    int test_lenght = 11;
    int numstreams = 5;

    progname = argv[0];
    sanitize_std_fds();

    int option;
    /* FIXME: parameter range checking, proper error messages, strtoul instead of atoi */
    while ((option = getopt (argc, argv, "vq46hVc:l:t:d:j:r:o:")) != -1) {
        switch (option) {
        case 'v':
            if (log_level < 1)
                log_level = 2;
            else if (log_level < MSG_TRACE)
                log_level++;
            break;
        case 'q':
            if (log_level <= 0)
                log_level = -1;
            else
                log_level = 0;
            break;
	case 'o':
	    if (freopen(optarg, "w", stdout) == NULL) {
	        print_err("could not redirect output to %s: %s", optarg, strerror(errno));
	        exit(SEXIT_FAILURE);
	    }
	    break;
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
	    token = strdup(optarg);
	    break;
	case 'r':
	    report_mode = atoi(optarg);
	    break;
	case 'h':
	    print_usage(progname, 1);
	    /* fall-through */ /* silence bogus warning */
	case 'V':
	    print_version();
	    /* fall-through */ /* silence bogus warning */
	default:
	    print_usage(progname, 0);
        }
    };

    if (optind >= argc || argc - optind != 1)
	print_usage(progname, 0);

    control_url = argv[optind];

    /* the server needs something to know whom we are, either a token, or a guuid */

    if (!token) {
	struct timespec now;
	token = malloc(64);
	if (!token || clock_gettime(CLOCK_REALTIME, &now)) {
	    print_err("out of memory or broken clock!");
	    return SEXIT_OUTOFRESOURCE;
	}
	srandom((long int)(now.tv_nsec + now.tv_sec) & INT_MAX);
	snprintf(token, 64, "TCPC%lx%lx%lxCPCT",
		(unsigned long) now.tv_nsec, (unsigned long) now.tv_sec, (unsigned long) random());
	print_msg(MSG_DEBUG, "generated session id: %s", token);
    }

    MeasureContext ctx = {
	.agent_id = agent_id,
	.host_name = NULL,
	.port = NULL,
	.control_url = control_url,
	.token = token,
	.family = family,
	.report_mode = report_mode,
	.timeout_test = (timeout_test <= 0 || timeout_test > 40) ? 40 : (unsigned int) timeout_test,
	.numstreams = (numstreams < 1 || numstreams > MAX_CONCURRENT_SESSIONS) ? MAX_CONCURRENT_SESSIONS : (unsigned int) numstreams,
	.test_duration = (test_lenght < 1 || test_lenght > 60) ? 60 : (unsigned int) test_lenght,
	.sessionid = NULL,
	.sample_period_ms = 500U,
    };

    print_msg(MSG_ALWAYS, PACKAGE_NAME " " PACKAGE_VERSION " starting...");

    int value = tcp_client_run(ctx);

    if (value != 0)
        print_err("TCP CLIENT RUN ERROR");

    free(token);

    return value;
}
