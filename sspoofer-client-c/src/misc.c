/*
 * SIMET2 MA SIMET Spoofer client (sspooferc) - misc
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

#include "sspooferc_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>

#include <limits.h>
#include <string.h>
#include <errno.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>  /* getnameinfo */

#include <assert.h>
#if !defined(static_assert) && defined(__STDC_VERSION__) && (__STDC_VERSION__ < 202301L)
#  define static_assert _Static_assert
#endif

#include "sspooferc.h"

#ifdef HAVE_JSON_JSON_H
#include <json/json.h>
#elif HAVE_JSON_C_JSON_H
#include <json-c/json.h>
#else
#include <json.h>
#endif

/* For control protocol and reporting purposes */
const char *str_ip46(int ai_family)
{
    switch (ai_family) {
        case AF_INET:
            return "ip4";
        case AF_INET6:
            return "ip6";
    }
    return "ip";
}

/* For user display purposes */
const char *str_ipv46(int ai_family)
{
    switch (ai_family) {
        case AF_INET:
            return "IPv4";
        case AF_INET6:
            return "IPv6";
    }
    return "IP";
}

int sspoof_nameinfo(const sockaddr_any_t_ * const sa,
                    sa_family_t * const family,
                    const char ** const hostname, const char ** const hostport)
{
    char namebuf[256] = "unknown";
    char portbuf[32]  = "unknown";
    sa_family_t af = AF_UNSPEC;

    if (sa->sa.sa_family != AF_UNSPEC && !getnameinfo(&sa->sa, sizeof(sockaddr_any_t_),
                                                   namebuf, sizeof(namebuf), portbuf, sizeof(portbuf),
                                                   NI_NUMERICHOST | NI_NUMERICSERV)) {
        af = sa->sa.sa_family;
    }

    if (!(*hostname) || strncmp(namebuf, *hostname, sizeof(namebuf))) {
        free_const(*hostname);
        *hostname = strdup(namebuf);
    }
    if (!(*hostport) || strncmp(portbuf, *hostport, sizeof(portbuf))) {
        free_const(*hostport);
        *hostport = strdup(portbuf);
    }
    *family = af;

    return (af != AF_UNSPEC)? 0 : 1;
}

/* ensure it is compatible with xx_nameinfo()! */
int sspoof_cmpnameinfo(const struct addrinfo * const ai,
                          const sa_family_t family, const char * const hostname)
{
    char namebuf[256];

    if (!hostname || !ai || ai->ai_family != family || !ai->ai_addr || !ai->ai_addrlen)
        return 0;
    if (getnameinfo(ai->ai_addr, ai->ai_addrlen, namebuf, sizeof(namebuf),
                    NULL, 0, NI_NUMERICHOST | NI_NUMERICSERV))
        return 0; /* fail safe */

    return (strncmp(namebuf, hostname, sizeof(namebuf)) == 0);
}


/* vim: set et ts=8 sw=4 : */
