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

#include "twamp.h"
#include "report.h"
#include "message.h"
#include "logger.h"

#include <json-c/json.h>
#include <assert.h>
#include <errno.h>

#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>

#define TWAMP_R_NUMCOLS 8
const char * const twamp_report_col_names[TWAMP_R_NUMCOLS] = {
    "senderSeqNum", "reflectorSeqNum", "receiverSeqNum",
    "senderTimeUs", "reflectorRecvTimeUs",
    "reflectorSendTimeUs", "receiverTimeUs",
    "rttUs"
};

enum {
    socket_tbl_col_connid = 0,
    socket_tbl_col_observer,
    socket_tbl_col_local_af,
    socket_tbl_col_local_addr,
    socket_tbl_col_local_port,
    socket_tbl_col_remote_af,
    socket_tbl_col_remote_addr,
    socket_tbl_col_remote_port,
    SOCK_TBL_COL_MAX
};
const char * const socket_report_col_names[SOCK_TBL_COL_MAX] = {
    [socket_tbl_col_connid] = "connection-id",
    [socket_tbl_col_observer] = "observer",
    [socket_tbl_col_local_af] = "local-address-family",
    [socket_tbl_col_local_addr] = "local-address",
    [socket_tbl_col_local_port] = "local-port",
    [socket_tbl_col_remote_af] = "remote-address-family",
    [socket_tbl_col_remote_addr] = "remote-address",
    [socket_tbl_col_remote_port] = "remote-port",
};

struct twamp_report_private {
    json_object *lmap_root;
}; /* TWAMPReport->privdata */

static void xx_json_object_array_add_uint64_as_str(json_object *j, uint64_t v)
{
    char buf[32];
    snprintf(buf, sizeof(buf), "%" PRIu64, v);
    json_object_array_add(j, json_object_new_string(buf));
}

static const char *str_ip46(sa_family_t ai_family)
{
    switch (ai_family) {
    case AF_INET:
        return "ip4";
    case AF_INET6:
        return "ip6";
    }
    return "ip";
}


static int xx_nameinfo(struct sockaddr_storage *sa, socklen_t sl,
                        sa_family_t *sa_f, const char **family,
                        const char **hostname, const char **hostport)
{
    char namebuf[256], portbuf[32];
    assert(hostname && hostport);

    if (sa->ss_family == AF_UNSPEC
            || getnameinfo((struct sockaddr *)sa, sl, namebuf, sizeof(namebuf),
                            portbuf, sizeof(portbuf), NI_NUMERICHOST | NI_NUMERICSERV)) {
        if (sa_f)
            *sa_f = AF_UNSPEC;
        if (family)
           *family = strdup("unknown");
        *hostname = strdup("unknown");
        *hostport = strdup("error");
        return 1;
    }

    *hostname = strdup(namebuf);
    *hostport = strdup(portbuf);
    if (sa_f)
        *sa_f = sa->ss_family;
    if (family)
        *family = strdup(str_ip46(sa->ss_family));

    return 0;
}

static json_object* xx_report_socket_metric(int sockfd, int proto)
{
    char metric_name[256];
    const char *t_row[SOCK_TBL_COL_MAX];
    struct sockaddr_storage ss_local, ss_remote;
    socklen_t ss_len;
    json_object *jres_tbl_content = NULL;

    if (sockfd == -1 || (proto != IPPROTO_TCP && proto != IPPROTO_UDP))
        return NULL;

    ss_len = sizeof(ss_local);
    memset(&ss_local, 0, ss_len);
    if (getsockname(sockfd, (struct sockaddr*) &ss_local, &ss_len))
        return NULL;
    ss_len = sizeof(ss_remote);
    memset(&ss_remote, 0, ss_len);
    if (getpeername(sockfd, (struct sockaddr*) &ss_remote, &ss_len))
        return NULL;

    snprintf(metric_name, sizeof(metric_name),
             "urn:ietf:metrics:perf:Priv_MPMonitor_Active_%s-ConnectionEndpoints__Multiple_Raw",
             (proto == IPPROTO_TCP) ? "TCP" : "UDP" );

    memset(t_row, 0, sizeof(t_row));
    t_row[socket_tbl_col_connid] = strdup("0");
    t_row[socket_tbl_col_observer] = strdup("ma"); /* measurement-agent */
    if (xx_nameinfo(&ss_local, sizeof(ss_local), NULL,
                &t_row[socket_tbl_col_local_af],
                &t_row[socket_tbl_col_local_addr],
                &t_row[socket_tbl_col_local_port]))
        goto err_exit;
    if (xx_nameinfo(&ss_remote, sizeof(ss_remote), NULL,
                &t_row[socket_tbl_col_remote_af],
                &t_row[socket_tbl_col_remote_addr],
                &t_row[socket_tbl_col_remote_port]))
        goto err_exit;

    json_object *jo, *jo1; /* ownership transferred to parent on _add */

    /* TABLE CONTENT */
    jres_tbl_content = json_object_new_object();  /* shall contain function, column, row arrays */
    if (!jres_tbl_content)
        goto err_exit;

    /* table function object list */
    jo = json_object_new_array();
    jo1 = json_object_new_object();
    assert(jo && jo1); /* FIXME */
    json_object_object_add(jo1, "uri", json_object_new_string(metric_name));
    json_object_array_add(jo, jo1);
    json_object_object_add(jres_tbl_content, "function", jo);
    jo = jo1 = NULL;

    /* table columns list */
    jo = json_object_new_array();
    assert(jo); /* FIXME */
    for (unsigned int i = 0; i < SOCK_TBL_COL_MAX; i++) {
        json_object_array_add(jo, json_object_new_string(socket_report_col_names[i]));
    };
    json_object_object_add(jres_tbl_content, "column", jo);
    jo = NULL;

    /* one table row with our result data */
    jo = json_object_new_object();
    jo1 = json_object_new_array();
    assert(jo && jo1); /* FIXME */
    for (unsigned int i = 0; i < SOCK_TBL_COL_MAX; i++) {
        json_object_array_add(jo1, json_object_new_string(t_row[i] ? t_row[i] : ""));
    };
    json_object_object_add(jo, "value", jo1);
    jo1 = NULL;

    /* table rows list */
    jo1 = json_object_new_array();
    assert(jo1);
    json_object_array_add(jo1, jo);
    jo = NULL;
    json_object_object_add(jres_tbl_content, "row", jo1);
    jo1 = NULL;

err_exit:
    for (unsigned int i = 0; i < SOCK_TBL_COL_MAX; i++)
        free((void *)t_row[i]);

    return jres_tbl_content;
}

int report_socket_metrics(TWAMPReport *report, int sockfd, int proto)
{
    struct twamp_report_private *rp;
    json_object *jor;

    if (!report)
        return EINVAL;
    if (!report->privdata)
        return EINVAL;
    rp = (struct twamp_report_private *)report->privdata;
    if (!rp->lmap_root)
        rp->lmap_root = json_object_new_array();
    if (!rp->lmap_root)
        return ENOMEM;

    jor = xx_report_socket_metric(sockfd, proto);
    if (!jor)
        return ENOMEM;

    json_object_array_add(rp->lmap_root, jor);
    return 0;
}

int twamp_report(TWAMPReport *report, TWAMPParameters *param)
{
    char metric_name[256];

    print_msg(MSG_DEBUG, "Printing raw data Table");
    assert(param);

    snprintf(metric_name, sizeof(metric_name),
        "urn:ietf:metrics:perf:Priv_MPMonitor_Active_UDP-Periodic-"
        "LossThresholdUs%u-IntervalDurationUs%u-"
        "PacketCount%u-PacketSizeBytes%u__Multiple_Raw",
        param->packets_timeout_us, param->packets_interval_us,
        param->packets_count, param->payload_size);

    json_object *jo, *jo1, *jo2;  /* Used when we will transfer ownership via *_add */

    /* create objects and build the topology for the result table */
    /* FIXME: abort if the _add() calls return non-zero, etc */
    /* TABLE CONTENT */
    json_object * jres_tbl_content = json_object_new_object();  /* shall contain function, column, row arrays */
    assert(jres_tbl_content);

    /* table1 function object list */
    jo = json_object_new_array();
    jo1 = json_object_new_object();
    jo2 = json_object_new_array();
    assert(jo && jo1 && jo2);
    json_object_object_add(jo1, "uri", json_object_new_string(metric_name));
    json_object_array_add(jo2, json_object_new_string("Src"));
    json_object_object_add(jo1, "role", jo2);
    json_object_array_add(jo, jo1);
    json_object_object_add(jres_tbl_content, "function", jo);
    jo = jo1 = jo2 = NULL;

    /* table1 columns list */
    jo = json_object_new_array();
    for (unsigned int i = 0; i < TWAMP_R_NUMCOLS; i++) {
        json_object_array_add(jo, json_object_new_string(twamp_report_col_names[i]));
    };
    json_object_object_add(jres_tbl_content, "column", jo);
    jo = NULL;

    /* table1 rows (result data) */
    /* each member of the tbl_rows below be a single "value: ["cell", "cell"]" array object? */
    json_object * jarray_res_tbl_rows = json_object_new_array();

    /*
     * NOTE: we do not report the sentinel packet
     */
    unsigned int np = (report && report->result) ? report->result->packets_received : 0;
    if (np == param->packets_max && np > 0)
        np--;
    print_msg(MSG_DEBUG, "Number of row of raw data to output: %u", np);
    for (unsigned int it = 0; it < np; it++) {
        ReportPacket pkg;

        uint64_t sendTime = timestamp_to_microsec(report->result->raw_data[it].data.SenderTime);
        uint64_t reflRecvTime = timestamp_to_microsec(report->result->raw_data[it].data.RecvTime);
        uint64_t reflReturnTime = timestamp_to_microsec(report->result->raw_data[it].data.Time);
        uint64_t returnTime = timestamp_to_microsec(report->result->raw_data[it].time);

        uint64_t processTime = reflReturnTime - reflRecvTime;

        pkg.senderSeqNumber = report->result->raw_data[it].data.SenderSeqNumber;
        pkg.reflectorSeqNumber = report->result->raw_data[it].data.SeqNumber;
        pkg.receiverSeqNumber = it;

        pkg.senderTime_us = sendTime;
        pkg.reflectorRecvTime_us = reflRecvTime;
        pkg.reflectorSendTime_us = reflReturnTime;
        pkg.receiverTime_us = returnTime;

        pkg.rtt_us = returnTime - sendTime - processTime;

#if 0
        /* THIS CODE CANNOT BE DISABLED FOR HOMOLOGATION V1.X CLIENTS */

        /* drop packets above the per-packet rtt from report */
        if (pkg.rtt_us > param->packets_timeout_us) {
            report->result->packets_dropped_timeout++;
            continue;
        }
#endif

        /* this row (object), will be inserted into the row array later, it is a list of cells */
        json_object * jcurrow = json_object_new_array();

        /* WARNING: keep the same insert order as in twamp_report_col_names[] ! */
        xx_json_object_array_add_uint64_as_str(jcurrow, pkg.senderSeqNumber);
        xx_json_object_array_add_uint64_as_str(jcurrow, pkg.reflectorSeqNumber);
        xx_json_object_array_add_uint64_as_str(jcurrow, pkg.receiverSeqNumber);
        xx_json_object_array_add_uint64_as_str(jcurrow, pkg.senderTime_us);
        xx_json_object_array_add_uint64_as_str(jcurrow, pkg.reflectorRecvTime_us);
        xx_json_object_array_add_uint64_as_str(jcurrow, pkg.reflectorSendTime_us);
        xx_json_object_array_add_uint64_as_str(jcurrow, pkg.receiverTime_us);
        xx_json_object_array_add_uint64_as_str(jcurrow, pkg.rtt_us);

        /* add row to list of rows */
        jo = json_object_new_object();
        json_object_object_add(jo, "value", jcurrow);
        json_object_array_add(jarray_res_tbl_rows, jo);
        jo = NULL;
    }

    json_object_object_add(jres_tbl_content, "row", jarray_res_tbl_rows);
    jarray_res_tbl_rows = NULL;

    if (report && report->privdata) {
        jo = ((struct twamp_report_private *)(report->privdata))->lmap_root;
    } else {
        jo = NULL;
    }
    if (!jo)
        jo = json_object_new_array();
    assert(jo);

    json_object_array_add(jo, jres_tbl_content);

    if (!param->lmap_report_mode) {
        /* we need to serialize the root array, but we don't want to output its delimiters [ ],
         * and we need to omit the "," after the last member of the array */
        size_t al = json_object_array_length(jo);
        for (size_t i = 0; i < al ; i++) {
            fprintf(stdout, "%s%s",
                      json_object_to_json_string_ext(json_object_array_get_idx(jo, i),
                                          JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_SPACED),
                      (i + 1 < al) ? ",\n" : "\n");
        }
    } else {
        fprintf(stdout, "%s\n", json_object_to_json_string_ext(jo,
                                JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_SPACED));
    }
    fflush(stdout);

    return 0;
}

/**
 * twamp_report_init() - allocates and initializes a TWAMPReport struct
 *
 * Allocates TWAMPReport, and TWAMPReport->result.  The allocations are
 * zero-filled.
 *
 * Returns NULL on ENOMEM.
 */
TWAMPReport * twamp_report_init(const sa_family_t family, const char * const host)
{
    struct twamp_report_private *rp = NULL;
    TWAMPResult *tr = NULL;
    TWAMPReport *r = NULL;

    tr = malloc(sizeof(TWAMPResult));
    if (!tr) {
        print_err("Error allocating memory for TWAPResult");
        goto err_exit;
    }
    memset(tr, 0, sizeof(TWAMPResult));

    rp = malloc(sizeof(struct twamp_report_private));
    if (!rp) {
        print_err("Error allocating memory for twamp_report_private");
        goto err_exit;
    }
    memset(rp, 0, sizeof(struct twamp_report_private));

    r = malloc(sizeof(TWAMPReport));
    if (!r) {
        print_err("Error allocating memory for TWAMPReport");
        goto err_exit;
    }
    memset(r, 0, sizeof(TWAMPReport));

    r->result = tr;
    r->privdata = rp;

    r->family = family;
    r->host = host;

    return r;

err_exit:
    free(rp);
    free(tr);
    free(r);
    return NULL;
}

/**
 * twamp_report_done - deallocates a TWAMPReport
 *
 * frees all substructures/arrays and the TWAMPReport
 *
 * Handles NULL structs just fine.
 */
void twamp_report_done(TWAMPReport *r)
{
    struct twamp_report_private *p;
    if (r) {
        p = (struct twamp_report_private *)(r->privdata);
        if (p) {
            if (p->lmap_root)
                json_object_put(p->lmap_root);
            free(p);
            }
        if (r->result) {
            free(r->result->raw_data);
            free(r->result);
        }
        free(r);
    }
}

/* vim: set et ts=4 sw=4 : */
