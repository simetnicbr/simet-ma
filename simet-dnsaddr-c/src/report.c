/*
 * SIMET2 MA - simple name resolver - reports
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
#include <stdbool.h>

#include <limits.h>
#include <string.h>
#include <errno.h>

#include <assert.h>
#if !defined(static_assert) && defined(__STDC_VERSION__) && (__STDC_VERSION__ < 202301L)
#  define static_assert _Static_assert
#endif

#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>

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

struct sdnsa_report_ctx {
    json_object *root;
};

/* Measurement metrics and LMAP tables */
#define SIMET_DNS_REFLECT_METRIC_URN "urn:ietf:metrics:perf:Priv_MPMonitor_Active_UDP_DNSReflect_Multiple_Raw"
enum {
    msmt_tbl_col_type = 0,
    msmt_tbl_col_sa_f,
    msmt_tbl_col_addr,
    msmt_tbl_col_querytime,
    MSMT_TBL_COL_MAX
};
const char * const msmt_report_col_names[MSMT_TBL_COL_MAX] = {
    [msmt_tbl_col_type] = "measurement-type",
    [msmt_tbl_col_sa_f] = "ip-family",
    [msmt_tbl_col_addr] = "resolver-ip-address",
    [msmt_tbl_col_querytime] = "query-time-microseconds",
};

/*
 * generic helpers
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

/* strcmp with defined semanthics for NULL */
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

/* For control protocol and reporting purposes */
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

/*
 * json-c helpers
 */

static json_object * xx_json_object_new_int64_as_str(const int64_t v)
{
    char buf[32];
    snprintf(buf, sizeof(buf), "%" PRIi64, v);
    return json_object_new_string(buf);
}

static json_object * xx_json_object_new_sockaddr_as_str(const sockaddr_any_t_ *v)
{
    char buf[INET6_ADDRSTRLEN];

    if (v && !getnameinfo(&v->sa, sizeof(*v), buf, sizeof(buf), NULL, 0, NI_NUMERICHOST)) {
            return json_object_new_string(buf);
    }
    return NULL;
}

#if 0
static json_object * xx_json_object_new_string_opt(const char *s)
{
    if (s) {
        return json_object_new_string(s); /* not necessarily NULL-aware */
    } else {
        return NULL;
    }
}

/* returns NZ on error */
static int xx_json_add_int64str(json_object *jo, const char * const tag, const int64_t v)
{
    if (jo && tag) {
        json_object *js = xx_json_object_new_int64_as_str(v);
        if (!js || json_object_object_add(jo, tag, js)) {  /* FIXME: old json-c has (void) json_o_o_add */
            errno = ENOMEM;
            return -ENOMEM;
        }
    }
    return 0;
}

/* returns NZ on error */
static int xx_json_object_opt_string_add(json_object *jo, const char *tag, const char *value)
{
    if (jo && tag && value) {
        json_object *js = json_object_new_string(value);
        if (!js) {
            errno = ENOMEM;
            return -ENOMEM;
        }
        json_object_object_add(jo, tag, js); /* (void) in json-c before 0.13 */
    }
    return 0;
}
#endif

/* returns NZ on error */
static int xx_json_array_opt_string_add(json_object *jarray, const char *value)
{
    if (jarray && value) {
        json_object *js = json_object_new_string(value);
        if (!js || json_object_array_add(jarray, js)) {
            errno = ENOMEM;
            return -ENOMEM;
        }
    }
    return 0;
}

/* returns NZ on error */
static int xx_json_array_int64str_add(json_object *ja, const int64_t v)
{
    if (ja) {
        json_object *js = xx_json_object_new_int64_as_str(v);
        if (!js || json_object_array_add(ja, js)) {
            errno = ENOMEM;
            return -ENOMEM;
        }
    }
    return 0;
}

/* returns NZ on error */
static int xx_json_array_sockaddr_add(json_object *ja, const sockaddr_any_t_ *value)
{
    json_object *js = xx_json_object_new_sockaddr_as_str(value);
    if (!js || json_object_array_add(ja, js)) {
        errno = EINVAL;
        return -EINVAL;
    }
    return 0;
}

#if 0
/* returns NZ on error, does nothing if string already in array */
static int xx_json_array_stringset_add(json_object *jarray, const char *value)
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
static int xx_json_object_int64_add(json_object *jo, const char *tag, int64_t value)
{
    if (jo && tag) {
        json_object *jv = json_object_new_int64(value);
        if (!jv) {
            errno = ENOMEM;
            return -ENOMEM;
        }
        json_object_object_add(jo, tag, jv); /* (void) in json-c before 0.13 */
    }
    return 0;
}

/* returns NZ on error */
static int xx_json_object_bool_add(json_object *jo, const char *tag, bool value)
{
    if (jo && tag) {
        json_object *jv = json_object_new_boolean(value);
        if (!jv) {
            errno = ENOMEM;
            return -ENOMEM;
        }
        json_object_object_add(jo, tag, jv); /* (void) in json-c before 0.13 */
    }
    return 0;
}
#endif

/*
 * LMAP Report
 *
 * table 1:
 * measurements, one per row:
 *
 * columns:
 * measurement-type  ("reflect-cold", "reflect-cached")
 * ip-family         ("ip4", "ip6")
 * resolver IPs      ("ip address")
 * query-time-us     ("<number>", in microseconds)
 */
static json_object *sdnsa_render_msmt_header(void)
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
    json_object_object_add(jo1, "uri", json_object_new_string(SIMET_DNS_REFLECT_METRIC_URN));
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

static int sdnsa_render_reflect(json_object * const jrows,
                                const char * const mtype,
                                struct dns_addrinfo_head * const data)
{
    json_object *jo = NULL;
    int rc = -EINVAL;

    if (!jrows || !mtype || !data)
        return -EINVAL;

    print_msg(MSG_DEBUG, "report: generating report for %s", mtype);

    unsigned long rowcount = 0;
    for (struct dns_addrinfo_result *r = data->head; r != NULL; r = r->next) {
        /* open new data row, contents will go in jrowdata */
        if ((jo = json_object_new_object()) == NULL)
            goto err_exit;
        json_object *jrowdata = json_object_new_array();
        if (!jrowdata) {
            goto err_exit;
        }
        json_object_object_add(jo, "value", jrowdata); /* jo owns jrowdata */

        /* fill in row through jrowdata */
        if (xx_json_array_opt_string_add(jrowdata, mtype)
                || xx_json_array_opt_string_add(jrowdata, str_ip46(r->last_resolver.sa.sa_family))
                || xx_json_array_sockaddr_add(jrowdata, &r->last_resolver)
                || xx_json_array_int64str_add(jrowdata, r->query_time_us))
            goto err_exit;

        /* add row to table */
        json_object_array_add(jrows, jo); /* jrows owns jo and jrowdata */
        jo = NULL;

        rowcount++;
    }

    print_msg(MSG_DEBUG, "report: %s: added %lu rows to report", mtype, rowcount);

    rc = (rowcount > 0)? 0 : -ENODATA;

err_exit:
    json_object_put(jo);
    return rc;
}

int sdnsa_render_report(struct dns_addrinfo_head * const data_nocache,
                        struct dns_addrinfo_head * const data_cached,
                        enum report_mode report_mode)
{
    struct sdnsa_report_ctx rctx = {};

    size_t arraylen;
    int rc = ENOMEM;

    if (!data_nocache && !data_cached)
        return -ENODATA;

    rctx.root = json_object_new_array();
    if (!rctx.root)
        return -ENOMEM;

    /*
     * Table 1: REFLECT measurement
     */
    json_object *jtbl = sdnsa_render_msmt_header();
    if (!jtbl)
        goto err_exit;

    json_object *jrows = json_object_new_array();
    if (!jrows)
        goto err_exit;
    json_object_object_add(jtbl, "row", jrows); /* must not json_object_put(jrows) on error */

    /* Fill in rows with REFLECT measurement data */
    if (data_nocache) {
        rc = sdnsa_render_reflect(jrows, "reflect-nocache", data_nocache);
        if (rc)
            goto err_exit;
    }
    if (data_cached) {
        rc = sdnsa_render_reflect(jrows, "reflect-cached", data_cached);
        if (rc)
            goto err_exit;
    }

    json_object_array_add(rctx.root, jtbl);
    jtbl = NULL;

    /* other tables here... */

    /*
     * Close report
     */
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

    /* free some RAM */
    json_object_put(rctx.root);
    rctx.root = NULL;

    return rc;
}

/* vim: set et ts=8 sw=4 : */
