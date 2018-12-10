/*
 * Copyright (c) 2018 NIC.br <medicoes@simet.nic.br>
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
#include "report.h"

#include "logger.h"

#include "json-c/json.h"
#include <unistd.h>
#include <stdio.h>

#include <assert.h>
#include <errno.h>

#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>

struct tcpbw_report_private {
    json_object *root;
    json_object *sockrows;
};

enum {
    socket_tbl_col_observer = 0,
    socket_tbl_col_local_af,
    socket_tbl_col_local_addr,
    socket_tbl_col_local_port,
    socket_tbl_col_remote_af,
    socket_tbl_col_remote_addr,
    socket_tbl_col_remote_port,
    SOCK_TBL_COL_MAX
};
const char * const socket_report_col_names[SOCK_TBL_COL_MAX] = {
    [socket_tbl_col_observer] = "observer",
    [socket_tbl_col_local_af] = "local-address-family",
    [socket_tbl_col_local_addr] = "local-address",
    [socket_tbl_col_local_port] = "local-port",
    [socket_tbl_col_remote_af] = "remote-address-family",
    [socket_tbl_col_remote_addr] = "remote-address",
    [socket_tbl_col_remote_port] = "remote-port",
};

static const char *str_ip46(int ai_family)
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

    if (sa->ss_family == AF_UNSPEC || getnameinfo((struct sockaddr *)sa, sl,
                                            namebuf, sizeof(namebuf), portbuf, sizeof(portbuf),
					    NI_NUMERICHOST | NI_NUMERICSERV)) {
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

int report_socket_metrics(struct tcpbw_report *report, int sockfd, int proto)
{
    char metric_name[256];
    const char *t_row[SOCK_TBL_COL_MAX];
    struct sockaddr_storage ss_local, ss_remote;
    socklen_t ss_len;
    int rc = ENOMEM;

    if (!report)
        return EINVAL;
    struct tcpbw_report_private *rp = (struct tcpbw_report_private *)report;
    if (!rp->root)
        return EINVAL;

    if (sockfd == -1 || (proto != IPPROTO_TCP && proto != IPPROTO_UDP))
	return EINVAL;

    ss_len = sizeof(ss_local);
    memset(&ss_local, 0, ss_len);
    if (getsockname(sockfd, (struct sockaddr*) &ss_local, &ss_len))
	return EINVAL;
    ss_len = sizeof(ss_remote);
    memset(&ss_remote, 0, ss_len);
    if (getpeername(sockfd, (struct sockaddr*) &ss_remote, &ss_len))
	return EINVAL;

    memset(t_row, 0, sizeof(t_row));
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

    /* On first call, create table.  Once created, just add further rows */
    if (!rp->sockrows) {
        json_object *jres_tbl_content;

        snprintf(metric_name, sizeof(metric_name),
                "urn:ietf:metrics:perf:Priv_MPMonitor_Active_%s-ConnectionEndpoints__Multiple_Raw",
                (proto == IPPROTO_TCP) ? "TCP" : "UDP" );

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

        /* table rows list */
        jo = json_object_new_array();
        assert(jo); /* FIXME */

        rp->sockrows = json_object_get(jo); /* lock it by reference count... */
        json_object_object_add(jres_tbl_content, "row", jo);

        json_object_array_add(rp->root, jres_tbl_content);
    }

    /* fill in data row */
    jo = json_object_new_object();
    jo1 = json_object_new_array();
    assert(jo && jo1); /* FIXME */
    for (unsigned int i = 0; i < SOCK_TBL_COL_MAX; i++) {
        json_object_array_add(jo1, json_object_new_string(t_row[i] ? t_row[i] : ""));
    };
    json_object_object_add(jo, "value", jo1);
    jo1 = NULL;
    json_object_array_add(rp->sockrows, jo);
    jo = NULL;

    rc = 0;

err_exit:
    for (unsigned int i = 0; i < SOCK_TBL_COL_MAX; i++)
        free((void *)t_row[i]);

    return rc;
}

static void xx_json_object_array_add_uin64_as_str(json_object *j, uint64_t v)
{
    char buf[32];

    snprintf(buf, sizeof(buf), "%" PRIu64, v);
    json_object_array_add(j, json_object_new_string(buf));
}


/**
 * createReport - create the JSON LMAP-like report snippet
 *
 * if @jresults is not NULL, include it (upload direction measurement results).
 * Then, render the rows for DownResult[] (download direction measurement results), if any.
 *
 * @jresults MUST use the same column ordering as we do:
 * sequence; bits; streams; interval (ms); direction
 */
static json_object *createReport(json_object *jresults,
			  DownResult *downloadRes, uint32_t counter,
			  MeasureContext *ctx)
{
    char metric_name[256];

    assert(downloadRes);
    assert(ctx);

    snprintf(metric_name, sizeof(metric_name),
	    "urn:ietf:metrics:perf:Priv_OWBTC_Active_TCP-SustainedBurst-MultipleStreams-"
	    "TCPOptsUndefined-SamplePeriodMs%u-StreamDurationMs%u000__Multiple_Raw",
	    ctx->sample_period_ms, ctx->test_duration);

    /* FIXME: handle NULL returns as error... */

    json_object *jo, *jo1; /* used when transfering ownership via _add */

    /* shall contain function, column, row arrays */
    json_object *jtable = json_object_new_object();
    assert(jtable);

    if (!json_object_is_type(jresults, json_type_array))
    {
        print_warn("Received unusable data from server, ignoring...");
        jresults = NULL;
    }

    /* function object list */
    jo = json_object_new_array();
    jo1 = json_object_new_object();
    assert(jo && jo1);
    json_object_object_add(jo1, "uri", json_object_new_string(metric_name));
    json_object_array_add(jo, jo1);
    json_object_object_add(jtable, "function", jo);
    jo = jo1 = NULL;

    /* columns list */
    jo = json_object_new_array();
    assert(jo);
    json_object_array_add(jo, json_object_new_string("sequence"));
    json_object_array_add(jo, json_object_new_string("bits"));
    json_object_array_add(jo, json_object_new_string("streams"));
    json_object_array_add(jo, json_object_new_string("intervalMs"));
    json_object_array_add(jo, json_object_new_string("direction"));
    json_object_object_add(jtable, "column", jo);
    jo = NULL;

    /* rows (result data) */
    json_object *jrows = (jresults) ? jresults : json_object_new_array();
    assert(jrows);

    for (unsigned int i = 0; i < counter; i++)
    {
        json_object *jrow = json_object_new_array();
        assert(jrow);

        /* WARNING: keep the same order as in the columns list! */
        xx_json_object_array_add_uin64_as_str(jrow, i + 1);
        xx_json_object_array_add_uin64_as_str(jrow, downloadRes[i].bytes * 8U);
        xx_json_object_array_add_uin64_as_str(jrow, downloadRes[i].nstreams);
        xx_json_object_array_add_uin64_as_str(jrow, (uint64_t)downloadRes[i].interval / 1000UL);
        json_object_array_add(jrow, json_object_new_string("download"));

        /* add row to list of rows */
        jo = json_object_new_object();
        json_object_object_add(jo, "value", jrow);
        json_object_array_add(jrows, jo);
        jo = NULL;
    }

    json_object_object_add(jtable, "row", jrows);
    jrows = NULL;

    return jtable;
}

int tcpbw_report(struct tcpbw_report *report,
                 const char *upload_results_json,
                 DownResult *downloadRes, uint32_t counter,
                 MeasureContext *ctx)
{
    struct tcpbw_report_private *rp;
    assert(report && upload_results_json && downloadRes && ctx);

    rp = (struct tcpbw_report_private *)report;

    json_object *j_obj_upload = json_tokener_parse(upload_results_json);
    json_object *report_obj = createReport(j_obj_upload, downloadRes, counter, ctx);

    if (report_obj)
        json_object_array_add(rp->root, report_obj);

    /* we need to serialize the root array, but we don't want to output its delimiters [ ],
     * and we need to omit the "," after the last member of the array */
    int al = json_object_array_length(rp->root);
    for (int i = 0; i < al ; i++) {
        fprintf(stdout, "%s%s",
                  json_object_to_json_string_ext(json_object_array_get_idx(rp->root, i),
                                      JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_SPACED),
                  (i + 1 < al) ? ",\n" : "\n");
    }
    fflush(stdout);

    return 0;
}

/**
 * tcpbw_report_init() - allocates and initializes a tcpbw_report struct
 *
 * Returns NULL on ENOMEM.
 */
struct tcpbw_report * tcpbw_report_init(void)
{
    struct tcpbw_report_private *p = malloc(sizeof(struct tcpbw_report_private));
    json_object *jo = NULL;
    if (!p)
	return NULL;

    memset(p, 0, sizeof(struct tcpbw_report_private));

    jo = json_object_new_array();
    if (!jo)
	goto err_exit;
    p->root = jo;

    return (struct tcpbw_report *)p;

err_exit:
    free(jo);
    free(p);
    return NULL;
}

/**
 * tcpbw_report_done - deallocates a tcpbw_report struct
 *
 * frees all substructures and private data
 *
 * Handles NULL structs just fine.
 */
void tcpbw_report_done(struct tcpbw_report *r)
{
    struct tcpbw_report_private *rp;
    if (r) {
        rp = (struct tcpbw_report_private *)r;
	if (rp->sockrows)
            json_object_put(rp->sockrows);
	if (rp->root)
            json_object_put(rp->root);
    }
    free(r);
}

