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

#include <ctype.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <fcntl.h>
#include <errno.h>

#include <assert.h>
#if !defined(static_assert) && defined(__STDC_VERSION__) && (__STDC_VERSION__ < 202301L)
#  define static_assert _Static_assert
#endif

#include "simet_err.h"
#include "logger.h"
#include "base64.h"

/* We depend on these */
static_assert(sizeof(int) >= 4, "code assumes (int) is at least 32 bits");
static_assert(sizeof(long long) >= 8, "code assumes (long long) is at least 64 bits");

int log_level = 2;
const char* progname = PACKAGE_NAME;

/*
 * helpers
 */

/* lets not blind the type system just to squash a false-positive */
static inline void free_constchar(const char *p) { free((void *)p); }

/* strcmp with proper semanthics for NULL */
static inline int xstrcmp(const char * const s1, const char * const s2)__attribute__((__unused__));
static inline int xstrcmp(const char * const s1, const char * const s2)
{
    if (s1 && s2)
        return strcmp(s1, s2);
    if (!s1 && !s2)
        return 0;
    if (!s1)
        return -1;
    return 1;
}

/* trim spaces, note we return NULL if the result is empty or ENOMEM */
static char *strndup_trim(const char *s, size_t l)
{
    if (!s)
        return NULL;

    while (isspace(*s) && l > 0) {
        s++;
        l--;
    };

    if (!*s || l <= 0)
        return NULL;

    while (l > 0 && isspace(s[l-1]))
        l--;

    return (l > 0) ? strndup(s, l) : NULL;
}

/* trim spaces, note we return NULL if the result is empty or ENOMEM */
static char *strdup_trim(const char *s)
{
    if (!s)
        return NULL;
    return strndup_trim(s, strlen(s));
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

/* breaks name into hostname and port, either can be NULL */
/* returns 0 ok, 1 error */
static int cmdln_parse_hostport(const char *name, const char ** const phost, const char ** const pport)
{
    char *hostname = NULL;
    char *port = NULL;
    const char *r;

    if (!name)
        goto finish;

    while (*name && isspace(*name))
        name++;

    if (!*name)
        return 1;

    r = name;

    /* handle IPv6 [<ip address>]:<port> */
    /* FIXME: this is lax, accepts [<dns hostname>] as well, and [<ipv4>], etc */
    if (*name == '[') {
        name++;
        r = strchr(name, ']');
        if (!r)
            goto err_exit;

        hostname = strndup_trim(name, (size_t)(r - name));
        r++;

        if (*r && *r != ':') {
            while (*r && isspace(*r))
                r++;
            if (*r)
                goto err_exit;
            r = NULL;
        }
    } else {
        r = strrchr(r, ':');
        if (r) {
            hostname = strndup_trim(name, (size_t)(r - name));
        } else {
            hostname = strdup_trim(name);
        }
    }

    if (r && *r == ':') {
        /* parse optional :<port> */
        r++;
        if (!*r)
            goto err_exit;
        port = strdup_trim(r);
    }

finish:
    if (pport)
        *pport = port;

    if (phost)
        *phost = hostname;

    return 0;

err_exit:
    free(hostname);
    free(port);
    return 1;
}

static int cmdline_parse_bindsrc(const char * const p, struct sockaddr_storage *ss)
{
    const char *host = NULL;
    const char *port = NULL;

    struct addrinfo *res;
    struct addrinfo hints = {
        .ai_flags = AI_NUMERICSERV | AI_NUMERICHOST | AI_PASSIVE | AI_ADDRCONFIG,
    };

    if (!ss)
        return 1;
    if (cmdln_parse_hostport(p, &host, &port))
        return 1;
    if (!host && !port)
        return 1;

    hints.ai_family = (ss->ss_family != 0) ? ss->ss_family : AF_UNSPEC;
    int s = getaddrinfo(host, port, &hints, &res);
    if (s) {
        print_err("%s: failed to resolve: %s", p, gai_strerror(s));
        return 1;
    }
    if (!res) {
        print_err("%s: address not found", p);
        return 1;
    }

    memcpy(ss, res->ai_addr, res->ai_addrlen);

    freeaddrinfo(res);
    free_constchar(port);
    free_constchar(host);

    return 0;
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

static int cmdline_parse_reportenabled(const char *arg, twampc_report_flags_t * const e)
{
    const char *delim = ";, \t";

    assert(e);

    *e = 0;
    char *tokens = strdup(arg); /* no trim because " " is in our strtok delimiters */
    if (!tokens)
        return 0;

    for (char *tok = strtok(tokens, delim); tok && *tok; tok = strtok(NULL, delim)) {
        if (!strcmp(tok, "lmap") || !strcmp(tok, "LMAP")) { *e |= TWAMP_REPORT_ENABLED_LMAP; }
        else if (!strcmp(tok, "summary"))         { *e |= TWAMP_REPORT_ENABLED_SUMMARY; }
        else if (!strcmp(tok, "metadata"))        { *e |= TWAMP_REPORT_ENABLED_TMETADATA; }
        else if (!strcmp(tok, "parameters"))      { *e |= TWAMP_REPORT_ENABLED_TPARAMETERS; }
        else if (!strcmp(tok, "results_summary")) { *e |= TWAMP_REPORT_ENABLED_RSTATS; }
        else {
            print_err("unknown report mode: %s", tok);
            return 1;
        }
    }

    free(tokens);
    return 0;
}

static void print_usage(const char * const p, int mode)
{
    fprintf(stderr, "Usage: %s [-h] [-q|-v] [-V] [-4|-6] [-m twamp|light] [-p <service port>] [-t <timeout>] "
        "[-c <packet count>] [-s <payload size>] [-i <interpacket interval>] [-T <packet discard timeout>] "
        "[-r <report mode>] [-o <path>] [-R <report types>] [-O <path>] <server>\n", p);
    if (mode) {
        fprintf(stderr, "\n"
            "\t-h\tprint usage help and exit\n"
            "\t-V\tprint program version and copyright, and exit\n"
            "\t-v\tverbose mode (repeat for increased verbosity)\n"
            "\t-q\tquiet mode (repeat for errors-only)\n"
            "\t-4\tuse IPv4, instead of system default\n"
            "\t-6\tuse IPv6, instead of system default\n"
            "\t-m\toperating mode: twamp (default), light\n"
            "\t-k\tauthentication key, base64 (SIMET extension, not auth mode)\n"
            "\t-t\tconnection timeout in seconds\n"
            "\t-c\tnumber of packets to transmit per session\n"
            "\t-s\tsize of the packet payload (UDP/IP headers not included)\n"
            "\t-i\ttime in microseconds between each packet (lower bound)\n"
            "\t-T\ttime in microseconds to wait for the last packet\n"
            "\t-p\tservice name or numeric port of the TWAMP server\n"
            "\t-I\tsource IP address and/or :port for TWAMP-Light TEST stream, use [] for ipv6 literals\n"
            "\t-r\treport mode: 0 = comma-separated, 1 = json array\n"
            "\t-o\tredirect LMAP report output to <path>, stdout if <path> is - or empty\n"
            "\t-R\tenable reports using a comma-separated list of report types (see below)\n"
            "\t-O\tredirect non-LMAP report output to <path>, stdout if <path> is - or empty\n"
            "\nserver: hostname or IP address of the TWAMP server\n"
            "\n"
            "report types: lmap (default), summary, metadata, parameters, results_summary\n"
            "report type 'summary' includes: metadata, parameters, results_summary\n"
            "\n"
            "LMAP reports can be diverted from stdout through -o option,\n"
            "non-LMAP reports can be diverted from stdout through -O option.\n"
            "report ordering in stdout is fixed: first LMAP, then non-LMAP.\n"
        );
    }
    exit((mode)? SEXIT_SUCCESS : SEXIT_BADCMDLINE);
}

int main(int argc, char **argv)
{
    const char *host = NULL;
    const char *port = TWAMP_DEFAULT_PORT;
    struct sockaddr_storage *ss_source = NULL;

    sa_family_t family = AF_UNSPEC;
    int connect_timeout = 15;
    int packet_count = 200;
    int payload_size = DFL_TSTPKT_SIZE;
    int lmap_report_mode = 0;
    const char* lmap_report_path = NULL;
    twampc_report_flags_t reports_enabled = TWAMP_REPORT_ENABLED_LMAP;
    const char* summary_report_path = NULL;
    int twamp_mode = 0;
    long packet_interval_us = 30000;
    long packet_timeout_us = 10000000;
    TWAMPKey key = { 0 };

    progname = argv[0];
    sanitize_std_fds();

    int option;

    while ((option = getopt(argc, argv, "vq46hVm:p:I:t:c:s:T:i:r:R:o:O:k:")) != -1) {
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
            if (lmap_report_path)
                free_constchar(lmap_report_path);
            if (optarg && (optarg[0] != '\0') && !(optarg[0] == '-' && optarg[1] == '\0')) {
                lmap_report_path = strdup_trim(optarg);
            } else {
                lmap_report_path = NULL;
            }
            break;
        case 'O':
            if (summary_report_path)
                free_constchar(summary_report_path);
            if (optarg && (*optarg != '\0')) {
                summary_report_path = strdup_trim(optarg);
            } else {
                summary_report_path = NULL;
            }
            break;
        case '4':
            family = AF_INET;
            break;
        case '6':
            family = AF_INET6;
            break;
        case 'p':
            port = optarg;
            break;
        case 'I':
            ss_source = malloc(sizeof(*ss_source));
            if (!ss_source)
                exit(SEXIT_FAILURE);
            memset(ss_source, 0, sizeof(*ss_source));

            ss_source->ss_family = family;
            if (cmdline_parse_bindsrc(optarg, ss_source)) {
                print_err("invalid source interface address or port");
                exit(SEXIT_FAILURE);
            }
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
            lmap_report_mode = atoi(optarg);
            if (lmap_report_mode < 0 || lmap_report_mode >= TWAMP_REPORT_MODE_EOL) {
                print_err("unknown report mode: %s", optarg);
                exit(SEXIT_FAILURE);
            }
            break;
        case 'R':
            if (cmdline_parse_reportenabled(optarg, &reports_enabled)) {
                exit(SEXIT_FAILURE);
            }
            break;
        case 'm':
            if (optarg && !strcasecmp("twamp", optarg)) {
                twamp_mode = TWAMP_MODE_TWAMP;
            } else if (optarg && !strcasecmp("light", optarg)) {
                twamp_mode = TWAMP_MODE_TWAMPLIGHT;
            } else {
                print_usage(argv[0], 1);
            }
            break;
        case 'k': {
                char *key_base64 = strdup_trim(optarg);
                ssize_t b64len = base64_decode(key_base64, strlen(key_base64), key.data, sizeof(key.data));
                if (b64len < 0) {
                    print_err("authentication key: base64 decoding error: %s", strerror(-(int)b64len));
                    exit(SEXIT_FAILURE);
                } else if (b64len < SIMET_TWAMP_AUTH_MINKEYSIZE) {
                    print_err("authentication key: too short (must be at least %u bytes)", (unsigned int)SIMET_TWAMP_AUTH_MINKEYSIZE);
                    exit(SEXIT_FAILURE);
                }
                key.len = (size_t)b64len; /* verified, b64len >= 0 */

                free(key_base64);
                key_base64 = NULL;
            }
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

    TWAMPParameters param = {
        .host = host,
        .port = port,
        .source_ss = ss_source,
        .family = family,
        .lmap_report_mode = lmap_report_mode,
        .lmap_report_path = lmap_report_path,
        .lmap_report_output = (!lmap_report_path) ? stdout : NULL,
        .reports_enabled = reports_enabled,
        .summary_report_path = summary_report_path,
        .summary_report_output = (!summary_report_path) ? stdout : NULL,
        .connect_timeout = (connect_timeout <= 0 || connect_timeout > 30) ? 30 : connect_timeout,
        .packets_count = (unsigned int)((packet_count <= 0 || packet_count > 1000) ? 1000 : packet_count),
        .payload_size = (unsigned int)((payload_size < MAX_TSTPKT_SIZE)? ( (payload_size > MIN_TSTPKT_SIZE)? payload_size : MIN_TSTPKT_SIZE ) : MAX_TSTPKT_SIZE),
        .packets_max = param.packets_count * 2,
        .packets_interval_us = (packet_interval_us > 0) ? (unsigned int) packet_interval_us : 30000U,
        .packets_timeout_us = (packet_timeout_us > 0) ? (unsigned int) packet_timeout_us : 100000U,
        .ttl = 255,
        .key = key,
    };

    print_msg(MSG_ALWAYS, PACKAGE_NAME " " PACKAGE_VERSION " starting...");

    int value = SEXIT_INTERNALERR;
    switch (twamp_mode) {
    case TWAMP_MODE_TWAMP:
        value = twamp_run_client(&param);
        break;
    case TWAMP_MODE_TWAMPLIGHT:
        value = twamp_run_light_client(&param);
        break;
    }

    if (value != 0) {
        print_err("TWAMP-CLIENT ERROR");
    }

    free(ss_source);

    return value;
}

/* vim: set et ts=4 sw=4 : */
