/*
 * SIMET2 MA - simple name resolver
 * Copyright (c) 2024 NIC.br <medicoes@simet.nic.br>
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

#include "simet-dnsaddr_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>

#include <limits.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>

#include <assert.h>
#if !defined(static_assert) && defined(__STDC_VERSION__) && (__STDC_VERSION__ < 202301L)
#  define static_assert _Static_assert
#endif

#include <fcntl.h>

#include <time.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include "simet_err.h"
#include "simet_random.h"
#include "base64.h"
#include "timespec.h"
#include "logger.h"
#include "report.h"

#define SIMET_DNSREFLECT_DOMAIN "mp.dns.simet.nic.br"

const char *progname = PACKAGE_NAME;

const char *simet_dns_domain = SIMET_DNSREFLECT_DOMAIN;
int report_mode = SSPOOF_REPORT_MODE_FRAGMENT;
int log_level = MSG_NORMAL;


/*
 * helpers
 */

static inline void free_const(const void * const cp)
{
    /* Works even with -Wcast-qual, and does *not* cast integer to pointer */
    union {
        const void *cp;
        void *p;
    } cast_ptr = { .cp = cp };
    free(cast_ptr.p);
}

static int fatal_enomem(void) __attribute__((__noreturn__));
static int fatal_enomem(void)
{
    print_err("out of memory!");
    exit(SEXIT_OUTOFRESOURCE);
}

static int sdnsa_get_randomstr(char ** const s)
{
    if (!s)
        return -EINVAL;

    uint8_t buf[sizeof(uint64_t)];
    if (simet_getrandom(buf, sizeof(buf))) {
        /* could not get real random data, fudge it */
        struct timespec ts_now = {};
        clock_gettime(CLOCK_REALTIME, &ts_now);
        *(uint32_t *)(&buf) = (getpid() ^ ts_now.tv_sec) & 0xffffU;
        *(uint32_t *)(&buf[4]) = (getppid() ^ ts_now.tv_nsec) & 0xffffU;
    }

    char b64buf[16] = "a"; /* ensure hostname starts with letter just in case */
    ssize_t rc = base64safe_encode(buf, sizeof(buf), &b64buf[1], sizeof(b64buf)-1, 0);
    if (rc < 8)
        return -EINVAL;

    /* there should be enough entropy even with case-insensitive DNS */

    *s = strndup(b64buf, (size_t) rc); /* rc >= 8 */
    return (*s != NULL)? 0 : -EINVAL;
}

static const char *sdnsa_get_reflect_domain(int is_ip6, const char * const id, const char * const domain)
{
    char node[64] = "";

    if (!domain)
        return NULL;

    int s = snprintf(node, sizeof(node), "%s%sreflect.ip%c.%s.",
            (id)? id : "", (id)? "." : "",
            (is_ip6)? '6' : '4',
            domain);
    if (s < 10 || s >= (int)sizeof(node))
        return NULL;

    /* Trim dots at end, there is at least one already */
    while (--s > 0 && node[s-1] == '.') {
        node[s] = '\0';
    }

    return strdup(node);
}

static int sdnsa_getaddrinfo(int af, const char * node, struct dns_addrinfo_head *result)
{
    /* we give a hint for SOCK_DGRAM UDP so that we don't get multiple answers for tcp, udp, raw... */
    struct addrinfo hints = { .ai_socktype = SOCK_DGRAM, .ai_protocol = IPPROTO_UDP, .ai_family = af };

    struct addrinfo *addr = NULL, *rp;
    struct sockaddr *sa = NULL;

    struct timespec ts1, ts2;
    int eai;

    if (!node || !node[9])
        return SEXIT_FAILURE;

    int fast_retries = 5;
    clock_gettime(CLOCK_MONOTONIC, &ts1);
    do {
        eai = getaddrinfo(node, NULL, &hints, &addr);
    } while (eai == EAI_SYSTEM && errno == EINTR && (--fast_retries) > 0);
    clock_gettime(CLOCK_MONOTONIC, &ts2);
    long long delta_us = timespec_sub_microseconds(&ts2, &ts1);

    if (eai) {
        print_msg(MSG_TRACE, "failed to resolve %s: %s", node, gai_strerror(eai));
        return SEXIT_FAILURE;
    } else {
        print_msg(MSG_TRACE, "getaddrinfo(%s) took %lld microseconds", node, delta_us);
    }

    if (!addr) {
        /* ugh, no results... */
        print_msg(MSG_TRACE, "failed to resolve %s: no data", node);
        return SEXIT_FAILURE;
    }

    if (result) {
        for (rp = addr; rp != NULL; rp = rp->ai_next) {
            if (rp->ai_family == AF_INET || rp->ai_family == AF_INET6) {
                if (sa && !memcmp(sa, rp->ai_addr, rp->ai_addrlen)) {
                    continue; /* dedup just in case */
                }
                struct dns_addrinfo_result * n = calloc(1, sizeof(struct dns_addrinfo_result));
                if (!n) {
                    fatal_enomem();
                    /* not reached */
                }
                if (rp->ai_addrlen > sizeof(n->last_resolver)) {
                    print_err("internal error: addrinfo buffer too small");
                    exit(SEXIT_INTERNALERR);
                }
                memcpy(&n->last_resolver, rp->ai_addr, rp->ai_addrlen);
                n->query_time_us = delta_us;

                n->next = NULL;
                if (!result->head)
                    result->head = n;
                if (result->tail)
                    result->tail->next = n;
                result->tail = n;

                sa = rp->ai_addr; /* not owned */
            }
        }
    }

    freeaddrinfo(addr);
    addr = NULL; sa = NULL;
    return 0;
}

/*
 * Query:  REFLECT
 *  1. Select random ID to bypass cache
 *  2. timestamp
 *  3.   Query up to 3 times.
 *  4. timestamp, this is the not-in-cache delay
 *  5. if failed, exit with error.
 *  6. report for the no-cache delay.
 *
 *  1. timestamp, query, timestamp
 *  2. repeat 5 times.  Record each delay.
 *  3. report for the in-cache delay.
 *
 *  6. Report the set of IP addresses returned from all queries (they could be different).
 *
 *  Note: getaddrinfo needs to be family specific for timing, otherwise
 *  it calls into the stub or recursive resolver at least twice, for A and AAAA,
 *  which falsifies the measurement.
 */

static int sdnsa_reflect_query(const char * const domain,
                               struct dns_addrinfo_head * const dnsres_nocache,
                               struct dns_addrinfo_head * const dnsres_cached)
{
    const char *node4 = NULL;
    const char *node6 = NULL;
    char *id = NULL;
    int rc4, rc6;
    int retries;

    int result = SEXIT_FAILURE;

    retries = 3;
    do {
        free(id);
        id = NULL;

        if (sdnsa_get_randomstr(&id))
            goto err_exit;

        free_const(node4); node4 = sdnsa_get_reflect_domain(0, id, domain);
        rc4 = sdnsa_getaddrinfo(AF_INET, node4, dnsres_nocache);

        free_const(node6); node6 = sdnsa_get_reflect_domain(1, id, domain);
        rc6 = sdnsa_getaddrinfo(AF_INET6, node6, dnsres_nocache);
    } while (--retries > 0 && rc4 && rc6);
    if (rc4 && rc6) {
        print_err("failed to resolve both %s and %s", node4, node6);
        result = SEXIT_DNSERR;
        goto err_exit;
    }

    /* now, redo the queries, expecting them to be cached */
    /* it *is* actually possible to have both families, if the resolver
     * load-balances queries over IPv4 and IPv6 to the authoritative,
     * as we use the same ID for both */
    retries = 0;
    for (int i = 0; i < 10 && retries < 3; i++) {
        rc4 = sdnsa_getaddrinfo(AF_INET,  node4, dnsres_cached);
        rc6 = sdnsa_getaddrinfo(AF_INET6, node6, dnsres_cached);

        if (rc4 && rc6)
            retries++;
    }

#if 0
    if (dnsres_nocache) {
        struct dns_addrinfo_result *r = dnsres_nocache->head;
        while (r) {
            char buf[INET6_ADDRSTRLEN];
            getnameinfo(&r->last_resolver.sa, sizeof(r->last_resolver), buf, sizeof(buf),
                    NULL, 0, NI_NUMERICHOST);
            print_msg(MSG_DEBUG, "recursive resolver %s, cold query time %" PRId64, buf, r->query_time_us);
            r = r->next;
        }
    }

    if (dnsres_cached) {
        struct dns_addrinfo_result *r = dnsres_cached->head;
        while (r) {
            char buf[INET6_ADDRSTRLEN];
            getnameinfo(&r->last_resolver.sa, sizeof(r->last_resolver), buf, sizeof(buf),
                    NULL, 0, NI_NUMERICHOST);
            print_msg(MSG_DEBUG, "recursive resolver %s, cached query time %" PRId64, buf, r->query_time_us);
            r = r->next;
        }
    }
#endif

    result = 0;

err_exit:
    free_const(node4);
    free_const(node6);
    free(id);

    return result;
}


/*
 * Command line and main executable
 */

static const char program_copyright[]=
    "Copyright (c) 2024 NIC.br\n\n"
    "This is free software; see the source for copying conditions.\n"
    "There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR\n"
    "A PARTICULAR PURPOSE.\n";

static void print_version(void)
{
    fprintf(stdout, "%s %s\n%s\n", PACKAGE_NAME, PACKAGE_VERSION, program_copyright);
    exit(SEXIT_SUCCESS);
}

static void print_usage(const char * const p, int mode) __attribute__((__noreturn__));
static void print_usage(const char * const p, int mode)
{
    fprintf(stderr, "Usage: %s [-q][-v][-h][-V][-o <path>][-r <mode>][-d <domain>]\n", p);

    if (mode) {
        fprintf(stderr, "\n"
            "\t-h\tprint usage help and exit\n"
            "\t-V\tprint program version and copyright, and exit\n"
            "\t-v\tverbose mode (does nothing)\n"
            "\t-q\tquiet mode (does nothing)\n"
            "\t-d\tSIMET-DNS base domain (%s)\n"
            "\t-o\tredirect report output to <path>\n"
            "\t-r\treport mode: 0 = comma-separated (default), 1 = json array\n"
            "\n",
            simet_dns_domain);
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

static void sanitize_std_fds(void)
{
   /* do it in file descriptor numerical order! */
   fix_fds(STDIN_FILENO,  O_RDONLY);
   fix_fds(STDOUT_FILENO, O_WRONLY);
   fix_fds(STDERR_FILENO, O_RDWR);
}

int main(int argc, char **argv) {
    progname = argv[0];
    sanitize_std_fds();

    int option;
    while ((option = getopt (argc, argv, "vqhVd:r:o:")) != -1) {
        switch (option) {
        case 'v':
            if (log_level < MSG_TRACE)
                log_level++;
            break;
        case 'q':
            if (log_level >= MSG_NORMAL)
                log_level = MSG_IMPORTANT;
            else
                log_level = MSG_ALWAYS;
            break;

        case 'd':
            if (optarg)
                simet_dns_domain = optarg;
            break;

        case 'o':
            if (freopen(optarg, "w", stdout) == NULL) {
                print_err("could not redirect output to %s: %s", optarg, strerror(errno));
                exit(SEXIT_FAILURE);
            }
            break;
        case 'r':
            report_mode = atoi(optarg);
            if (report_mode < 0 || report_mode >= SSPOOF_REPORT_MODE_EOL) {
                print_err("unknown report mode: %s", optarg);
                exit(SEXIT_BADCMDLINE);
            }
            break;

        case 'h':
            print_usage(progname, 1);
            /* fall-through */
        case 'V':
            print_version();
            /* fall-through */
        default:
            print_usage(progname, 0);
        }
    };

    /*
    if (optind >= argc || !argv[optind])
        print_usage(progname, 0);

    const char *mode = argv[optind];
    optind++;
    */

    struct dns_addrinfo_head dnsres_nocache = {};
    struct dns_addrinfo_head dnsres_cached = {};
    int rc = sdnsa_reflect_query(simet_dns_domain, &dnsres_nocache, &dnsres_cached);
    if (!rc) {
        rc = sdnsa_render_report(&dnsres_nocache, &dnsres_cached, report_mode);
    }

    return rc;
}

/* vim: set et ts=8 sw=4 : */
