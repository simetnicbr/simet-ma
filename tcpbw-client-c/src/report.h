/*
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

#ifndef REPORT_H_
#define REPORT_H_

#include "tcpbwc.h"
#include <inttypes.h>

typedef struct tcpbw_download_result
{
    uint64_t bytes;
    uint64_t interval; /* microseconds */
    unsigned int nstreams;
} DownResult;

struct tcpbw_report {
    /* all fields private, size unknown */
};

struct tcpbw_report* tcpbw_report_init(void);
void tcpbw_report_done(struct tcpbw_report *);
int report_socket_metrics(struct tcpbw_report *, int sockfd, int proto);
int tcpbw_report(struct tcpbw_report *, const char *, DownResult *, uint32_t, MeasureContext *);

#endif /* REPORT_H_ */
