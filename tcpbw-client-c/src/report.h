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

#include "tcpinfo.h"
#include <linux/sock_diag.h> /* for SK_MEMINFO_* */

typedef struct tcpbw_download_result
{
    uint64_t bytes;
    uint64_t interval_ns; /* nanoseconds */
    unsigned int nstreams;
} DownResult;

typedef uint32_t tcpbw_skmeminfo_t[SK_MEMINFO_VARS];

typedef struct tcpbw_data_sample {
    struct timespec timestamp; /* relative to start of this measurement pass */
    unsigned int stream_id;
    struct simet_tcp_info tcpi;
} TcpInfoSample;

typedef struct tcpbw_skmem_sample {
    struct timespec timestamp; /* relative to start of this measurement pass */
    unsigned int stream_id;
    tcpbw_skmeminfo_t sk_meminfo; /* SO_MEMINFO */
} SkmemSample;

typedef struct report_context {
    struct tcpbw_report *report;
    const char  *peer_json_report;

    unsigned int download_streams_count;
    unsigned int upload_streams_count;

    unsigned long int download_tcpi_count;
    unsigned long int upload_tcpi_count;
    TcpInfoSample  *download_tcpi;
    TcpInfoSample  *upload_tcpi;

    unsigned long int download_skmem_count;
    unsigned long int upload_skmem_count;
    SkmemSample *download_skmem;
    SkmemSample *upload_skmem;

    unsigned int summary_sample_count;
    DownResult  *summary_samples;
} ReportContext;

struct tcpbw_report {
    /* ensures proper aligment for the struct, does not really exist */
    void * do_not_use_this_field;
    /* all fields private, size unknown */
};

ReportContext *tcpbw_report_init(void);
void tcpbw_report_done(ReportContext *rctx);
int report_socket_metrics(ReportContext *rctx, int sockfd, int proto);
int tcpbw_report(ReportContext *rctx, const char *upload_results_json, MeasureContext *ctx);

#endif /* REPORT_H_ */
