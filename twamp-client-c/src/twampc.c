/*
 * SIMET2 MA - TWAMP client
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

#include "twampc_config.h"
#include "twamp.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>

#include <fcntl.h>
#include <errno.h>

#include "simet_err.h"
#include "logger.h"


int log_level = 2;
const char* progname = PACKAGE_NAME;

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
    fprintf(stderr, "Usage: %s [-h] [-q|-v] [-V] [-4|-6] [-p <service port>] [-t <timeout>] "
        "[-c <packet count>] [-s <payload size>] [-i <interpacket interval>] [-T <packet discard timeout>] "
        "[-r <report mode>] [-o <path>] <server>\n", p);
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
            "\t-s\tsize of the packet payload (UDP/IP headers not included)\n"
            "\t-i\ttime in microseconds between each packet (lower bound)\n"
            "\t-T\ttime in microseconds to wait for the last packet\n"
            "\t-p\tservice name or numeric port of the TWAMP server\n"
            "\t-r\treport mode: 0 = comma-separated, 1 = json array\n"
            "\t-o\tredirect report output to <path>\n"
            "\nserver: hostname or IP address of the TWAMP server\n\n");
    }
    exit((mode)? SEXIT_SUCCESS : SEXIT_BADCMDLINE);
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

int main(int argc, char **argv)
{
    const char *host = NULL;
    const char *port = "862";
    int family = 0;
    int connect_timeout = 15;
    int packet_count = 200;
    int payload_size = DFL_TSTPKT_SIZE;
    int report_mode = 0;
    long packet_interval_us = 30000;
    long packet_timeout_us = 10000000;

    progname = argv[0];
    sanitize_std_fds();

    int option;

    while ((option = getopt(argc, argv, "vq46hVp:t:c:s:T:i:r:o:")) != -1) {
        switch(option) {
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
        case 'p':
            port = optarg;
            break;
        case 't':
            connect_timeout = atoi(optarg);
            break;
        case 'c':
            packet_count = atoi(optarg);
            break;
        case 's':
            payload_size = atoi(optarg);
            break;
        case 'i':
            packet_interval_us = atol(optarg);
            break;
        case 'T':
            packet_timeout_us = atol(optarg);
            break;
        case 'r':
            report_mode = atoi(optarg);
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
    param.host = host;
    param.port = port;
    param.family = family;
    param.report_mode = report_mode;
    param.connect_timeout = (connect_timeout <= 0 || connect_timeout > 30) ? 30 : connect_timeout;
    param.packets_count = (unsigned int)((packet_count <= 0 || packet_count > 1000) ? 1000 : packet_count);
    param.payload_size = (unsigned int)((payload_size < MAX_TSTPKT_SIZE)? ( (payload_size > MIN_TSTPKT_SIZE)? payload_size : MIN_TSTPKT_SIZE ) : MAX_TSTPKT_SIZE);
    param.packets_max = param.packets_count * 2;
    param.packets_interval_us = (packet_interval_us > 0) ? (unsigned long int) packet_interval_us : 30000U;
    param.packets_timeout_us = (packet_timeout_us > 0) ? (unsigned long int) packet_timeout_us : 100000U;

    print_msg(MSG_ALWAYS, PACKAGE_NAME " " PACKAGE_VERSION " starting...");

    int value = twamp_run_client(param);

    if (value != 0) {
        print_err("TWAMP-CLIENT ERROR");
    }

    return value;
}

/* vim: set et ts=4 sw=4 : */
