/*
 * SIMET2 MA - TWAMP client
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


#include "twampc_config.h"
#include "twamp.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>

#include <fcntl.h>
#include <errno.h>

#include "logger.h"


int log_level = 2;
const char* progname = PACKAGE_NAME;

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
    fprintf(stderr, "Usage: %s [-h] [-q|-v] [-V] [-4|-6] [-p <service port>] [-t <timeout>] "
	    "[-c <packet count>] [-i <interpacket interval>] [-d <device id>] "
	    "<server>\n", p);
    if (mode) {
	fprintf(stderr, "\n"
		"\t-h\tprint usage help and exit\n"
		"\t-V\tprint program version and copyright, and exit\n"
		"\t-v\tverbose mode (repeat for increased verbosity)\n"
		"\t-q\tquiet mode (repeat for errors-only)\n"
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
            exit(EXIT_FAILURE);
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

int main(int argc, char **argv)
{
    char *device_id = NULL;
    char *host = NULL;
    char *port = "862";
    int family = 0;
    int timeout_test = 15;
    int packet_count = 50;
    int packet_interval_ns = 100000;

    progname = argv[0];
    sanitize_std_fds();

    int option;

    while ((option = getopt(argc, argv, "vq46hVp:t:c:i:d:")) != -1) {
        switch(option) {
        case 'v':
            if (log_level < 1)
                log_level = 2;
            else if (log_level < 3)
                log_level++;
            break;
        case 'q':
            if (log_level <= 0)
                log_level = -1;
            else
                log_level = 0;
            break;
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
	    print_usage(argv[0], 1);
	    /* fall-through */ /* silence bogus warning */
	case 'V':
	    print_version();
	    /* fall-through */ /* silence bogus warning */
	default:
	    print_usage(argv[0], 0);
        }
    }

    if (optind >= argc || argc - optind != 1)
	print_usage(argv[0], 0);

    host = argv[optind];

    TWAMPParameters param;
    param.device_id = device_id;
    param.host = host;
    param.port = port;
    param.family = family;
    param.timeout_test = (timeout_test <= 0 || timeout_test > 30) ? 30 : timeout_test;
    param.packets_count = (unsigned int)((packet_count <= 0 || packet_count > 100) ? 100 : packet_count);
    param.packets_interval_ns = (unsigned int)(packet_interval_ns);

    print_msg(MSG_ALWAYS, PACKAGE_NAME " " PACKAGE_VERSION " starting...");

    int value = twamp_run_client(param);

    if (value != 0) {
        print_err("TWAMP-CLIENT ERROR");
        return 0;
    }

    return 0;
}
