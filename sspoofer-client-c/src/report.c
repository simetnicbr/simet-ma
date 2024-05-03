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

#include "sspooferc_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include <stdbool.h>

#include <limits.h>
#include <string.h>
#include <errno.h>

#include <assert.h>
#if !defined(static_assert) && defined(__STDC_VERSION__) && (__STDC_VERSION__ < 202301L)
#  define static_assert _Static_assert
#endif

#include <netinet/in.h>

#include "sspooferc.h"
#include "simet_err.h"
#include "logger.h"
#include "timespec.h"

#ifdef HAVE_JSON_JSON_H
#include <json/json.h>
#elif HAVE_JSON_C_JSON_H
#include <json-c/json.h>
#else
#include <json.h>
#endif

#include "report.h"

/* LMAP report:
 *
 * connection metric (tcp)
 * connection metric (udp) -> probe measurement
 */

struct sspoof_report_ctx {
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

enum {
    msmt_tbl_col_connid = 0,
    msmt_tbl_col_msmtid,
    msmt_tbl_col_msmtsum,
    msmt_tbl_col_sa_f,
    msmt_tbl_col_mpaddr,
    msmt_tbl_col_mpname,
    msmt_tbl_col_mpcluster,
    msmt_tbl_col_mpdesc,
    MSMT_TBL_COL_MAX
};
const char * const msmt_report_col_names[MSMT_TBL_COL_MAX] = {
    [msmt_tbl_col_connid] = "connection-id",
    [msmt_tbl_col_msmtid] = "measurement-id",
    [msmt_tbl_col_sa_f] = "ip-family",
    [msmt_tbl_col_mpaddr] = "mp-ip-address",
    [msmt_tbl_col_mpname] = "mp-hostname",
    [msmt_tbl_col_mpcluster] = "mp-clustername",
    [msmt_tbl_col_mpdesc] = "mp-description",
    [msmt_tbl_col_msmtsum] = "measurement-summary",
};

static struct json_object * xx_json_object_new_int64_as_str(const int64_t v)
{
    char buf[32];
    snprintf(buf, sizeof(buf), "%" PRIi64, v);
    return json_object_new_string(buf);
}

static json_object * xx_json_object_new_string_opt(const char *s)
{
    if (s) {
        return json_object_new_string(s); /* not necessarily NULL-aware */
    } else {
        return NULL;
    }
}

#if 0
/* returns NZ on error */
static int xx_json_add_int64str(json_object *jo, const char * const tag, const int64_t v)
{
    if (jo && tag) {
        struct json_object *js = xx_json_object_new_int64_as_str(v);
        if (!js || json_object_object_add(jo, tag, js)) {  /* FIXME: old json-c has (void) json_o_o_add */
            errno = ENOMEM;
            return -ENOMEM;
        }
    }
    return 0;
}
#endif

/* returns NZ on error */
static int xx_json_object_opt_string_add(struct json_object *jo, const char *tag, const char *value)
{
    if (jo && tag && value) {
        struct json_object *js = json_object_new_string(value);
        if (!js) {
            errno = ENOMEM;
            return -ENOMEM;
        }
        json_object_object_add(jo, tag, js); /* (void) in json-c before 0.13 */
    }
    return 0;
}

/* returns NZ on error */
static int xx_json_array_opt_string_add(struct json_object *jarray, const char *value)
{
    if (jarray && value) {
        struct json_object *js = json_object_new_string(value);
        if (!js || json_object_array_add(jarray, js)) {
            errno = ENOMEM;
            return -ENOMEM;
        }
    }
    return 0;
}

/* returns NZ on error, does nothing if string already in array */
static int xx_json_array_stringset_add(struct json_object *jarray, const char *value)
{
    if (jarray && value) {
        size_t al = json_object_array_length(jarray);
        while (al > 0) {
            --al;
            const char *setmember = json_object_get_string(json_object_array_get_idx(jarray, al));
            if (!xstrcmp(value, setmember))
                return 0; /* already in set */
        }
        return xx_json_array_opt_string_add(jarray, value);
    }
    return 0;
}

/* returns NZ on error */
static int xx_json_array_int64str_add(json_object *ja, const int64_t v)
{
    if (ja) {
        struct json_object *js = xx_json_object_new_int64_as_str(v);
        if (!js || json_object_array_add(ja, js)) {
            errno = ENOMEM;
            return -ENOMEM;
        }
    }
    return 0;
}

static int xx_json_object_int64_add(struct json_object *jo, const char *tag, int64_t value)
{
    if (jo && tag) {
        struct json_object *jv = json_object_new_int64(value);
        if (!jv) {
            errno = ENOMEM;
            return -ENOMEM;
        }
        json_object_object_add(jo, tag, jv); /* (void) in json-c before 0.13 */
    }
    return 0;
}

static int xx_json_object_bool_add(struct json_object *jo, const char *tag, bool value)
{
    if (jo && tag) {
        struct json_object *jv = json_object_new_boolean(value);
        if (!jv) {
            errno = ENOMEM;
            return -ENOMEM;
        }
        json_object_object_add(jo, tag, jv); /* (void) in json-c before 0.13 */
    }
    return 0;
}

static int report_socket_metrics(struct sspoof_report_ctx * const rctx, const struct sspoof_server * const sctx)
{
    const char *t_row[SOCK_TBL_COL_MAX];
    int rc = -ENOMEM;

    if (!rctx || !sctx)
        return -EINVAL;
    if (!rctx->root)
        return -EINVAL;

    memset(t_row, 0, sizeof(t_row));

    char conn_id_str[30];
    snprintf(conn_id_str, sizeof(conn_id_str), "%u", sctx->connection_id);
    t_row[socket_tbl_col_connid] = conn_id_str;
    t_row[socket_tbl_col_observer] = "ma"; /* measurement-agent */

    t_row[socket_tbl_col_local_af] = str_ip46(sctx->local_family);
    t_row[socket_tbl_col_local_addr] = sctx->local_name;
    t_row[socket_tbl_col_local_port] = sctx->local_port;

    t_row[socket_tbl_col_remote_af] = str_ip46(sctx->peer_family);
    t_row[socket_tbl_col_remote_addr] = sctx->peer_name;
    t_row[socket_tbl_col_remote_port] = sctx->peer_port;

    /* ownership transferred to parent on _add */
    json_object *jres_tbl_content = NULL;
    json_object *jo1 = NULL;
    json_object *jo = NULL;

    const int proto = IPPROTO_TCP; /* so that the code below remains generic */

    /* On first call, create table.  Once created, just add further rows */
    if (!rctx->sockrows) {
        char metric_name[256];

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
        if (!jo || !jo1)
            goto err_exit;
        json_object_object_add(jo1, "uri", json_object_new_string(metric_name));
        json_object_array_add(jo, jo1);
        json_object_object_add(jres_tbl_content, "function", jo);
        jo = jo1 = NULL;

        /* table columns list */
        jo = json_object_new_array();
        if (!jo)
            goto err_exit;
        for (unsigned int i = 0; i < SOCK_TBL_COL_MAX; i++) {
            json_object_array_add(jo, json_object_new_string(socket_report_col_names[i]));
        };
        json_object_object_add(jres_tbl_content, "column", jo);
        jo = NULL;

        /* table rows list */
        jo = json_object_new_array();
        if (!jo)
            goto err_exit;

        rctx->sockrows = json_object_get(jo); /* lock it by reference count... */
        json_object_object_add(jres_tbl_content, "row", jo);

        json_object_array_add(rctx->root, jres_tbl_content);
        jres_tbl_content = NULL;
    }

    /* fill in data row */
    jo = json_object_new_object();
    jo1 = json_object_new_array();
        if (!jo || !jo1)
            goto err_exit;
    for (unsigned int i = 0; i < SOCK_TBL_COL_MAX; i++) {
        json_object_array_add(jo1, json_object_new_string(t_row[i] ? t_row[i] : ""));
    };
    json_object_object_add(jo, "value", jo1);
    jo1 = NULL;
    json_object_array_add(rctx->sockrows, jo);
    jo = NULL;

    rc = 0;

err_exit:
    json_object_put(jo);
    json_object_put(jo1);
    json_object_put(jres_tbl_content);

    return rc;
}

/*
 * LMAP Report
 *
 * table 1:
 * ambient socket metrics (TCP control connections, by connection id) - one per row.
 *
 * table 2:
 * measurements, one per row:
 *
 * columns:
 * connection-id  (this is per "sspoof_server")
 * measurement-id (this is per msmt_ctx (MSMTREQ message))
 * ip-family      (ip family, from peer control channel dst addr)
 * mp-ip-address  (MP's IP address)
 * mp-hostname    (MP's hostname as returned in MACONFIG)
 * mp-clustername (MP's cluster name as returned in MACONFIG)
 * mp-description (MP's description as retrned in MACONFIG)
 * measurement-summary (JSON, same contents as MSMTDATA minus the measurement-id field)
 */

static json_object *sspoof_render_msmt_header(void)
{
    json_object *jo, *jo1, *jres_tbl_content;

    /* TABLE CONTENT */
    jres_tbl_content = json_object_new_object();  /* shall contain function, column, row arrays */
    if (!jres_tbl_content)
        return NULL;

    /* table function object list */
    jo = json_object_new_array();
    jo1 = json_object_new_object();
    if (!jo || !jo1)
        goto err_exit;
    json_object_object_add(jo1, "uri", json_object_new_string(
                "urn:ietf:metrics:perf:Priv_MPMonitor_Active_UDP_BCP38v2_Multiple_Raw"
            ));
    json_object_array_add(jo, jo1);
    json_object_object_add(jres_tbl_content, "function", jo);
    jo = jo1 = NULL;

    /* table columns list */
    jo = json_object_new_array();
    if (!jo)
        goto err_exit;
    for (unsigned int i = 0; i < MSMT_TBL_COL_MAX; i++) {
        json_object_array_add(jo, json_object_new_string(msmt_report_col_names[i]));
    };
    json_object_object_add(jres_tbl_content, "column", jo);
    jo = NULL;

    return jres_tbl_content;

err_exit:
    json_object_put(jo);
    json_object_put(jo1);
    json_object_put(jres_tbl_content);

    return NULL;
}


/* 
 * {
 *   "sentinel_packets_received": <int>,
 *   "spoof_packets_received": <int>,
 *   "probe_packets_received": <int>,
 *   "spoof_src_types": [ "<tag>", "<tag>"... ],
 *   "sentinel_snat": <bool>,
 *   "spoof_snat": <bool>,
 *   "probe_snat": <bool>,
 *   "sentinel_intact": <bool>,
 *   "spoof_intact": <bool>,
 *   "probe_intact": <bool>,
 *   "sentinel_snat_addr": "<ip address>",
 *   "spoof_snat_addr": "<ip address>",
 *   "probe_snat_addr": "<ip address>"
 * }
 */
static json_object *sspoof_render_summ(struct sspoof_msmt_ctx *mctx)
{
    json_object *jmsmt = json_object_new_object();
    json_object *ja_srctypes = json_object_new_array();
    if (!jmsmt || !ja_srctypes)
        goto err_exit;

    if (mctx) {
        if (xx_json_object_int64_add(jmsmt, "sentinel_packets_received", mctx->data.sentinel_rcvd_count)
                || xx_json_object_int64_add(jmsmt, "spoof_packets_received", mctx->data.spoof_rcvd_count)
                || xx_json_object_int64_add(jmsmt, "probe_packets_received", mctx->data.probe_rcvd_count))
            goto err_exit;

        if (mctx->data.sentinel_rcvd_count > 0
                && (xx_json_object_bool_add(jmsmt, "sentinel_snat", mctx->data.sentinel_snat_seen)
                    || xx_json_object_opt_string_add(jmsmt, "sentinel_snat_addr", mctx->data.last_sentinel_snat_saddr)
                    || xx_json_object_bool_add(jmsmt, "sentinel_intact", mctx->data.sentinel_intact_seen)))
            goto err_exit;

        if (mctx->data.spoof_rcvd_count > 0
                && (xx_json_object_bool_add(jmsmt, "spoof_snat", mctx->data.spoof_snat_seen)
                    || xx_json_object_opt_string_add(jmsmt, "spoof_snat_addr", mctx->data.last_spoof_snat_saddr)
                    || xx_json_object_bool_add(jmsmt, "spoof_intact", mctx->data.spoof_intact_seen)))
            goto err_exit;

        if (mctx->data.probe_rcvd_count > 0
                && (xx_json_object_bool_add(jmsmt, "probe_snat", mctx->data.probe_snat_seen)
                    || xx_json_object_opt_string_add(jmsmt, "probe_snat_addr", mctx->data.last_probe_snat_saddr)
                    || xx_json_object_bool_add(jmsmt, "probe_intact", mctx->data.probe_intact_seen)))
            goto err_exit;

        for (int i = 0; i < mctx->msmt_req_count; i++) {
            if (mctx->msmt_reqs[i].prefixtag[0] != '\0'  /* not an empty string */
                    && xx_json_array_stringset_add(ja_srctypes, mctx->msmt_reqs[i].prefixtag))
                goto err_exit;
        }
        if (json_object_array_length(ja_srctypes) > 0) {
            json_object_object_add(jmsmt, "spoof_src_types", ja_srctypes);  /* (void) in json-c before 0.13 */
            ja_srctypes = NULL; /* now owned by jmsmt */
        }
    }
    return jmsmt;

err_exit:
    json_object_put(ja_srctypes);
    json_object_put(jmsmt);
    return NULL;
}

/* Render a report with all measurements in all contextes for all servers in vector svec, size nvec */
int sspoof_render_report(struct sspoof_server **svec, unsigned int nvec, enum report_mode report_mode)
{
    struct sspoof_report_ctx rctx = {};
    json_object *jo = NULL;

    size_t arraylen;
    int rc = ENOMEM;

    if (!svec)
        return -EINVAL;
    if (!nvec)
        return -ENODATA;

    print_msg(MSG_DEBUG, "report: generating report for %u measurement peer connections", nvec);

    rctx.root = json_object_new_array();
    if (!rctx.root)
        return -ENOMEM;

    json_object *jtbl = sspoof_render_msmt_header();
    if (!jtbl)
        goto err_exit;

    json_object *jrows = json_object_new_array();
    if (!jrows)
        goto err_exit;
    json_object_object_add(jtbl, "row", jrows); /* must not json_object_put(jrows) on error */

    /* note: this does *not* allow for partial reports, they could contain partial row objects */
    for (unsigned int i = 0; svec && i < nvec; i++) {
        struct sspoof_server *s = svec[i];
        if (!s || !s->msmt_done || !s->sid.str)
            continue;

        /* if a measurement context made it to s->msmt_done, it will not be empty */

        print_msg(MSG_DEBUG, "report: generating report for connection id %u: %s", s->connection_id, s->sid.str);

        /* append to table 1: sockets metric */
        if ((rc = report_socket_metrics(&rctx, s)) < 0)
            goto err_exit;

        /* append to table 2: measurements */
        unsigned int msmt_id = 0;
        for (struct sspoof_msmt_ctx *mctx = s->msmt_done; mctx; mctx = mctx->next) {
            msmt_id++;
            print_msg(MSG_DEBUG, "report: generating report for connection id %u, msmt %u: %s", s->connection_id, msmt_id, mctx->measurement_id);

            /* open new data row, contents will go in jrowdata */
            if ((jo = json_object_new_object()) == NULL)
                goto err_exit;
            json_object *jrowdata = json_object_new_array();
            if (!jrowdata) {
                goto err_exit;
            }
            json_object_object_add(jo, "value", jrowdata);
            json_object_array_add(jrows, jo);
            jo = NULL;

            /* fill in row, note row has been added to table already */
            if (xx_json_array_int64str_add(jrowdata, s->connection_id)
                    || xx_json_array_int64str_add(jrowdata, msmt_id)
                    || xx_json_array_opt_string_add(jrowdata, str_ip46(s->peer_family))
                    || xx_json_array_opt_string_add(jrowdata, s->peer_name)
                    || xx_json_array_opt_string_add(jrowdata, s->server_hostname)
                    || xx_json_array_opt_string_add(jrowdata, s->s_cluster_hostname)
                    || xx_json_array_opt_string_add(jrowdata, s->server_description) )
                goto err_exit;

            /* summary object, its text rendering will become the content of the summary cell */
            jo = sspoof_render_summ(mctx);
            if (!jo || json_object_array_add(jrowdata,
                        xx_json_object_new_string_opt(json_object_to_json_string_ext(jo, JSON_C_TO_STRING_PLAIN) /* owned by jo */ )) )
                goto err_exit;
            json_object_put(jo);
            jo = NULL;
        }
    }

    json_object_array_add(rctx.root, jtbl);
    jtbl = NULL;

    switch (report_mode) {
    case SSPOOF_REPORT_MODE_FRAGMENT:
        /* we need to serialize the root array, but we don't want to output its delimiters [ ],
         * and we need to omit the "," after the last member of the array */
        arraylen = json_object_array_length(rctx.root);
        for (size_t i = 0; i < arraylen ; i++) {
            if (fprintf(stdout, "%s%s",
                      json_object_to_json_string_ext(json_object_array_get_idx(rctx.root, i),
                                          JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_SPACED),
                      (i + 1 < arraylen) ? ",\n" : "\n") < 0) {
                rc = -errno;
                goto err_exit;
            }
        }
        break;
    case SSPOOF_REPORT_MODE_OBJECT:
        if (fprintf(stdout, "%s\n", json_object_to_json_string_ext(rctx.root,
                                    JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_SPACED)) < 0) {
            rc = -errno;
            goto err_exit;
        }
        break;
    default:
        break;
    }

    rc = (fflush(stdout) == EOF)? -errno : 0;

err_exit:
    json_object_put(jtbl);
    json_object_put(jo);

    /* free some RAM */
    json_object_put(rctx.sockrows);
    rctx.sockrows = NULL;
    json_object_put(rctx.root);
    rctx.root = NULL;

    return rc;
}

/* vim: set et ts=8 sw=4 : */
