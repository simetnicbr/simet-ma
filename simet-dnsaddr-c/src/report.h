/*
 * SIMET2 MA SIMET Spoofer client (sspooferc) - reports
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

#ifndef REPORT_H_
#define REPORT_H_

#include <inttypes.h>

enum report_mode {
    SSPOOF_REPORT_MODE_FRAGMENT = 0, /* Array contents */
    SSPOOF_REPORT_MODE_OBJECT   = 1, /* array or object */
    SSPOOF_REPORT_MODE_EOL
};

typedef union sockaddr_any_t_ {
    struct sockaddr     sa;
    struct sockaddr_in  in;
    struct sockaddr_in6 in6;
} sockaddr_any_t_;

struct dns_addrinfo_result {
    struct dns_addrinfo_result *next;
    sockaddr_any_t_ last_resolver;
    int64_t query_time_us;
};

struct dns_addrinfo_head {
    struct dns_addrinfo_result *head;
    struct dns_addrinfo_result *tail;
};

int sdnsa_render_report(struct dns_addrinfo_head * const data_nocache,
                        struct dns_addrinfo_head * const data_cached,
                        enum report_mode report_mode);

#endif /* REPORT_H_ */

/* vim: set et ts=8 sw=4 : */
