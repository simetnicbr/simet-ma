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

#include "tcpbwc_config.h"
#include "report.h"
#include "timespec.h"

#include "logger.h"

#include "json-c/json.h"
#include <unistd.h>
#include <stdio.h>

#include <assert.h>
#include <errno.h>

#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include "tcpinfo.h"

struct tcpbw_report_private {
    json_object *root;
    json_object *sockrows;
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

int report_socket_metrics(ReportContext *rctx, int sockfd, int proto)
{
    char metric_name[256];
    const char *t_row[SOCK_TBL_COL_MAX];
    struct sockaddr_storage ss_local, ss_remote;
    socklen_t ss_len;
    int rc = ENOMEM;

    if (!rctx || !rctx->report)
        return EINVAL;
    struct tcpbw_report_private *rp = (struct tcpbw_report_private *)(rctx->report);
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

static void xx_json_object_array_add_uint64_as_str(json_object *j, uint64_t v)
{
    char buf[32];

    snprintf(buf, sizeof(buf), "%" PRIu64, v);
    json_object_array_add(j, json_object_new_string(buf));
}

static void xx_json_object_add_int(json_object *j, const char *field, int64_t value)
{
    json_object_object_add(j, field, json_object_new_int64(value));
}

static void xx_json_object_add_u64(json_object *j, const char *field, uint64_t value)
{
    json_object_object_add(j, field, json_object_new_int64(value & INT64_MAX));
}

#if HAVE_DECL_SK_MEMINFO_VARS != 0
static json_object * render_skmem(const tcpbw_skmeminfo_t * const meminfo)
{
    if (!meminfo)
	return NULL;

    json_object *jo = json_object_new_object();
    if (!jo)
	return NULL;

    xx_json_object_add_int(jo, "rmem_alloc", (*meminfo)[SK_MEMINFO_RMEM_ALLOC]);
    xx_json_object_add_int(jo, "rcv_buf", (*meminfo)[SK_MEMINFO_RCVBUF]);
    xx_json_object_add_int(jo, "wmem_alloc", (*meminfo)[SK_MEMINFO_WMEM_ALLOC]);
    xx_json_object_add_int(jo, "snd_buf", (*meminfo)[SK_MEMINFO_SNDBUF]);
    xx_json_object_add_int(jo, "fwd_alloc", (*meminfo)[SK_MEMINFO_FWD_ALLOC]);
    xx_json_object_add_int(jo, "wmem_queued", (*meminfo)[SK_MEMINFO_WMEM_QUEUED]);
    xx_json_object_add_int(jo, "opt_mem", (*meminfo)[SK_MEMINFO_OPTMEM]);
    xx_json_object_add_int(jo, "backlog_mem", (*meminfo)[SK_MEMINFO_BACKLOG]);
#if HAVE_DECL_SK_MEMINFO_DROPS != 0
    xx_json_object_add_int(jo, "dropped_pkts", (*meminfo)[SK_MEMINFO_DROPS]);
#endif

    return jo;
}
#else /* HAVE_DECL_SK_MEMINFO_VARS */
static json_object * render_skmem(const tcpbw_skmeminfo_t * const meminfo)
{
    (void) meminfo;
    return NULL;
}
#endif /* HAVE_DECL_SK_MEMINFO_VARS */


static json_object * render_tcpi(const struct simet_tcp_info * const tcpi)
{
    if (!tcpi)
	return NULL;

    json_object *jo = json_object_new_object();
    if (!jo)
	return NULL;

    xx_json_object_add_int(jo, "state", tcpi->tcpi_state);
    xx_json_object_add_int(jo, "ca_state", tcpi->tcpi_ca_state);
    xx_json_object_add_int(jo, "retransmits", tcpi->tcpi_retransmits);
    xx_json_object_add_int(jo, "probes", tcpi->tcpi_probes);
    xx_json_object_add_int(jo, "backoff", tcpi->tcpi_backoff);
    xx_json_object_add_int(jo, "options", tcpi->tcpi_options);
    xx_json_object_add_int(jo, "snd_wscale", (uint8_t)tcpi->tcpi_snd_wscale);
    xx_json_object_add_int(jo, "rcv_wscale", (uint8_t)tcpi->tcpi_rcv_wscale);
    xx_json_object_add_int(jo, "delivery_rate_app_limited", (uint8_t)tcpi->tcpi_delivery_rate_app_limited);
#ifdef HAVE_STRUCT_TCP_INFO_TCPI_FASTOPEN_CLIENT_FAIL
    xx_json_object_add_int(jo, "fastopen_client_fail", (uint8_t)tcpi->tcpi_fastopen_client_fail);
#endif
    xx_json_object_add_int(jo, "rto", tcpi->tcpi_rto);
    xx_json_object_add_int(jo, "ato", tcpi->tcpi_ato);
    xx_json_object_add_int(jo, "snd_mss", tcpi->tcpi_snd_mss);
    xx_json_object_add_int(jo, "rcv_mss", tcpi->tcpi_rcv_mss);
    xx_json_object_add_int(jo, "unacked", tcpi->tcpi_unacked);
    xx_json_object_add_int(jo, "sacked", tcpi->tcpi_sacked);
    xx_json_object_add_int(jo, "lost", tcpi->tcpi_lost);
    xx_json_object_add_int(jo, "retrans", tcpi->tcpi_retrans);
    xx_json_object_add_int(jo, "fackets", tcpi->tcpi_fackets);
    xx_json_object_add_int(jo, "last_data_sent", tcpi->tcpi_last_data_sent);
    xx_json_object_add_int(jo, "last_ack_sent", tcpi->tcpi_last_ack_sent);
    xx_json_object_add_int(jo, "last_data_recv", tcpi->tcpi_last_data_recv);
    xx_json_object_add_int(jo, "last_ack_recv", tcpi->tcpi_last_ack_recv);
    xx_json_object_add_int(jo, "pmtu", tcpi->tcpi_pmtu);
    xx_json_object_add_int(jo, "rcv_ssthresh", tcpi->tcpi_rcv_ssthresh);
    xx_json_object_add_int(jo, "rtt", tcpi->tcpi_rtt);
    xx_json_object_add_int(jo, "rttvar", tcpi->tcpi_rttvar);
    xx_json_object_add_int(jo, "snd_ssthresh", tcpi->tcpi_snd_ssthresh);
    xx_json_object_add_int(jo, "snd_cwnd", tcpi->tcpi_snd_cwnd);
    xx_json_object_add_int(jo, "advmss", tcpi->tcpi_advmss);
    xx_json_object_add_int(jo, "reordering", tcpi->tcpi_reordering);
    xx_json_object_add_int(jo, "rcv_rtt", tcpi->tcpi_rcv_rtt);
    xx_json_object_add_int(jo, "rcv_space", tcpi->tcpi_rcv_space);
    xx_json_object_add_int(jo, "total_retrans", tcpi->tcpi_total_retrans);
    xx_json_object_add_u64(jo, "pacing_rate", tcpi->tcpi_pacing_rate);
    if (tcpi->tcpi_max_pacing_rate < UINT64_MAX) /* if it is UINT64_MAX, it is disabled... */
	xx_json_object_add_u64(jo, "max_pacing_rate", tcpi->tcpi_max_pacing_rate);
    xx_json_object_add_u64(jo, "bytes_acked", tcpi->tcpi_bytes_acked);
    xx_json_object_add_u64(jo, "bytes_received", tcpi->tcpi_bytes_received);
    xx_json_object_add_int(jo, "segs_out", tcpi->tcpi_segs_out);
    xx_json_object_add_int(jo, "segs_in", tcpi->tcpi_segs_in);
    xx_json_object_add_int(jo, "notsent_bytes", tcpi->tcpi_notsent_bytes);
    xx_json_object_add_int(jo, "min_rtt", tcpi->tcpi_min_rtt);
    xx_json_object_add_int(jo, "data_segs_in", tcpi->tcpi_data_segs_in);
    xx_json_object_add_int(jo, "data_segs_out", tcpi->tcpi_data_segs_out);
    xx_json_object_add_u64(jo, "delivery_rate", tcpi->tcpi_delivery_rate);
    xx_json_object_add_u64(jo, "busy_time", tcpi->tcpi_busy_time);
    xx_json_object_add_u64(jo, "rwnd_limited", tcpi->tcpi_rwnd_limited);
    xx_json_object_add_u64(jo, "sndbuf_limited", tcpi->tcpi_sndbuf_limited);
    xx_json_object_add_int(jo, "delivered", tcpi->tcpi_delivered);
    xx_json_object_add_int(jo, "delivered_ce", tcpi->tcpi_delivered_ce);
    xx_json_object_add_u64(jo, "bytes_sent", tcpi->tcpi_bytes_sent);
    xx_json_object_add_u64(jo, "bytes_retrans", tcpi->tcpi_bytes_retrans);
    xx_json_object_add_int(jo, "dsack_dups", tcpi->tcpi_dsack_dups);
    xx_json_object_add_int(jo, "reord_seen", tcpi->tcpi_reord_seen);
    xx_json_object_add_int(jo, "rcv_ooopack", tcpi->tcpi_rcv_ooopack);
    xx_json_object_add_int(jo, "snd_wnd", tcpi->tcpi_snd_wnd);

    return jo;
}

/*
 * { "stream_tcpi_upload": [
 *     { "sample_id": <int>, "timestamp": <int64>, "stream_id": <int>, "tcp_info": { ... }, "skmem": { ... } }
 *   ],
 *  "stream_tcpi_download": [
 *     { "sample_id": <int>, "timestamp": <int64>, "stream_id": <int>, "??": <int64>, "tcp_info": { ... }, "skmem": { ... } }
 *   ],
 *   "stream_skmem_upload": [
 *     { "sample_id": <int>, "timestamp": <int64>, "stream_id": <int>, "skmem": { ... } }
 *   ],
 *   "stream_skmem_download": [
 *     { "sample_id": <int>, "timestamp": <int64>, "stream_id": <int>, "skmem": { ... } }
 *   ]
 * }
 */
static json_object * render_tcpi_samples(const TcpInfoSample *samples, unsigned long int num_samples)
{
    unsigned int sc = 0;

    json_object *ja = json_object_new_array();
    if (!ja)
	return NULL;

    while (num_samples > 0) {
	const int64_t ts = (int64_t)TIMESPEC_NANOSECONDS(samples->timestamp) / 1000;
	json_object *jo = json_object_new_object();
	if (jo) {
	    json_object_object_add(jo, "sample_id", json_object_new_int64(sc));
	    json_object_object_add(jo, "stream_id", json_object_new_int64(samples->stream_id));
	    json_object_object_add(jo, "timestamp", json_object_new_int64(ts));
	    json_object_object_add(jo, "tcp_info", render_tcpi(&samples->tcpi));
	    json_object_array_add(ja, jo);
	} else {
	    goto err_exit;
	}
	samples++;
	num_samples--;
	sc++;
    }

    return ja;

err_exit:
    json_object_put(ja);
    return NULL;
}

static json_object * render_skmem_samples(const SkmemSample *samples, unsigned long int num_samples)
{
    unsigned int sc = 0;

    json_object *ja = json_object_new_array();
    if (!ja)
	return NULL;

    while (num_samples > 0) {
	const int64_t ts = (int64_t)TIMESPEC_NANOSECONDS(samples->timestamp) / 1000;
	json_object *jo = json_object_new_object();
	if (jo) {
	    json_object_object_add(jo, "sample_id", json_object_new_int64(sc));
	    json_object_object_add(jo, "stream_id", json_object_new_int64(samples->stream_id));
	    json_object_object_add(jo, "timestamp", json_object_new_int64(ts));
	    json_object_object_add(jo, "skmem", render_skmem(&samples->sk_meminfo));

	    json_object_array_add(ja, jo);
	} else {
	    goto err_exit;
	}
	samples++;
	num_samples--;
	sc++;
    }

    return ja;

err_exit:
    json_object_put(ja);
    return NULL;
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

    assert(ctx);
    assert(counter == 0 || downloadRes);

    snprintf(metric_name, sizeof(metric_name),
	    "urn:ietf:metrics:perf:Priv_OWBTC_Active_TCP-SustainedBurst-MultipleParallelStreams-"
	    "TCPOptsUndefined-SamplePeriodMs%u-StreamDurationMs%u000__Multiple_Raw",
	    ctx->sample_period_ms, ctx->test_duration);

    /* FIXME: handle NULL returns as error... */

    json_object *jo, *jo1, *jo2; /* used when transfering ownership via _add */

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
    jo2 = json_object_new_array();
    assert(jo && jo1 && jo2);

    json_object_object_add(jo1, "uri", json_object_new_string(metric_name));
    json_object_array_add(jo2, json_object_new_string("Client"));
    json_object_object_add(jo1, "role", jo2);
    json_object_array_add(jo, jo1);
    json_object_object_add(jtable, "function", jo);
    jo = jo1 = jo2 = NULL;

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
        xx_json_object_array_add_uint64_as_str(jrow, i + 1);
        xx_json_object_array_add_uint64_as_str(jrow, downloadRes[i].bytes * 8U);
        xx_json_object_array_add_uint64_as_str(jrow, downloadRes[i].nstreams);
	/* round to nearest millisecond. this is important.  do it like lround() would. */
        xx_json_object_array_add_uint64_as_str(jrow, downloadRes[i].interval_ns / 1000000UL + ((downloadRes[i].interval_ns % 1000000UL >= 500000UL)? 1 : 0));
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

int tcpbw_report(ReportContext *rctx, const char *upload_results_json, MeasureContext *ctx)
{
    struct tcpbw_report_private *rp;

    if (!rctx || !rctx->report || !ctx)
	return -EINVAL;

    rp = (struct tcpbw_report_private *)(rctx->report);

    json_object *j_obj_upload = upload_results_json ? json_tokener_parse(upload_results_json) : NULL;
    json_object *report_obj = createReport(j_obj_upload, rctx->summary_samples, rctx->summary_sample_count, ctx);

    if (report_obj)
        json_object_array_add(rp->root, report_obj);

    if (!ctx->report_mode) {
        /* we need to serialize the root array, but we don't want to output its delimiters [ ],
         * and we need to omit the "," after the last member of the array */
        size_t al = json_object_array_length(rp->root);
        for (size_t i = 0; i < al ; i++) {
            fprintf(stdout, "%s%s",
                      json_object_to_json_string_ext(json_object_array_get_idx(rp->root, i),
                                          JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_SPACED),
                      (i + 1 < al) ? ",\n" : "\n");
        }
    } else {
        fprintf(stdout, "%s\n", json_object_to_json_string_ext(rp->root,
                                    JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_SPACED));
    }
    fflush(stdout);

    /* free some RAM */
    if (rp->sockrows)
	json_object_put(rp->sockrows);
    rp->sockrows = NULL;
    if (rp->root)
	json_object_put(rp->root);
    rp->root = NULL;

    if (ctx->streamdata_file) {
	json_object *auxreport_obj = json_object_new_object();
	if (auxreport_obj) {
	    if (rctx->download_tcpi) {
		json_object_object_add(auxreport_obj, "stream_tcpi_download",
		    render_tcpi_samples(rctx->download_tcpi, rctx->download_tcpi_count));
	    }
	    if (rctx->upload_tcpi) {
		json_object_object_add(auxreport_obj, "stream_tcpi_upload",
		    render_tcpi_samples(rctx->upload_tcpi, rctx->upload_tcpi_count));
	    }
	    if (rctx->download_skmem) {
		json_object_object_add(auxreport_obj, "stream_skmem_download",
		    render_skmem_samples(rctx->download_skmem, rctx->download_skmem_count));
	    }
	    if (rctx->upload_skmem) {
		json_object_object_add(auxreport_obj, "stream_skmem_upload",
		    render_skmem_samples(rctx->upload_skmem, rctx->upload_skmem_count));
	    }
	    fprintf(ctx->streamdata_file, "%s", json_object_to_json_string_ext(auxreport_obj, JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_SPACED));
	    json_object_put(auxreport_obj); auxreport_obj = NULL;
	}
    }

    return 0;
}

/**
 * tcpbw_report_init() - allocates and initializes a report context
 *
 * Returns NULL on ENOMEM.
 */
ReportContext *tcpbw_report_init(void)
{
    struct tcpbw_report_private *rp = NULL;
    json_object *jo = NULL;

    ReportContext *rctx = calloc(1, sizeof(ReportContext));
    if (!rctx)
	return NULL;

    rp = calloc(1, sizeof(struct tcpbw_report_private));
    if (!rp)
	goto err_exit;

    jo = json_object_new_array();
    if (!jo)
	goto err_exit;
    rp->root = jo;

    rctx->report = (struct tcpbw_report *)(rp);
    return rctx;

err_exit:
    free(jo);
    free(rp);
    free(rctx);

    return NULL;
}

/**
 * tcpbw_report_done - deallocates a report context
 *
 * frees all substructures and private data.
 *
 * Handles NULL structs just fine.
 */
void tcpbw_report_done(ReportContext *rctx)
{
    struct tcpbw_report_private *rp;

    if (rctx) {
	if (rctx->report) {
	    rp = (struct tcpbw_report_private *)(rctx->report);
	    if (rp->sockrows)
		json_object_put(rp->sockrows);
	    if (rp->root)
		json_object_put(rp->root);
	    free(rctx->report);
	}
	free(rctx->download_tcpi);
	free(rctx->upload_tcpi);
	free(rctx->download_skmem);
	free(rctx->upload_skmem);
	free(rctx->summary_samples);
    }

    free(rctx);
}

