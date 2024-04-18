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

#include <stdbool.h>

#include <json-c/json.h>
#include <assert.h>
#include <errno.h>

#include <limits.h>
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
    json_object *lmap_root;     /* json array */
    json_object *summary_root;  /* json object */
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

static json_object* xx_report_connection_metric(int sockfd, int proto, struct twamp_connection_info *report_conn_info)
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

    if (report_conn_info) {
        report_conn_info->protocol = proto;
        /* transfer ownership */
        report_conn_info->local_endpoint.family = t_row[socket_tbl_col_local_af];   t_row[socket_tbl_col_local_af] = NULL;
        report_conn_info->local_endpoint.addr = t_row[socket_tbl_col_local_addr];   t_row[socket_tbl_col_local_addr] = NULL;
        report_conn_info->local_endpoint.port = t_row[socket_tbl_col_local_port];   t_row[socket_tbl_col_local_port] = NULL;
        report_conn_info->remote_endpoint.family = t_row[socket_tbl_col_remote_af]; t_row[socket_tbl_col_remote_af] = NULL;
        report_conn_info->remote_endpoint.addr = t_row[socket_tbl_col_remote_addr]; t_row[socket_tbl_col_remote_addr] = NULL;
        report_conn_info->remote_endpoint.port = t_row[socket_tbl_col_remote_port]; t_row[socket_tbl_col_remote_port] = NULL;
    }

err_exit:
    for (unsigned int i = 0; i < SOCK_TBL_COL_MAX; i++)
        free((void *)t_row[i]);

    return jres_tbl_content;
}

int twamp_report_testsession_connection(TWAMPReport *report, int sockfd)
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

    jor = xx_report_connection_metric(sockfd, IPPROTO_UDP, (report->result) ? &(report->result->test_session_endpoints) : NULL);
    if (!jor)
        return ENOMEM;

    json_object_array_add(rp->lmap_root, jor);
    return 0;
}

static int xx_serialize_partial_report(const char * const what, const enum report_mode mode,
                                const char * const path, FILE * const output,
                                json_object * const jo)
{
    FILE *outstream = output;
    if (path) {
        outstream = fopen(path, "w");
        if (!outstream) {
            print_err("%s: could not open output '%s': %s", what, path, strerror(errno));
            return EIO;
        }
    }
    if (outstream) {
        switch (mode) {
        case TWAMP_REPORT_MODE_FRAGMENT:
            /* we need to serialize the root array, but we don't want to output its delimiters [ ],
             * and we need to omit the "," after the last member of the array */
            if (json_object_get_type(jo) == json_type_array) {
                const size_t al = json_object_array_length(jo);
                for (size_t i = 0; i < al ; i++) {
                    if (fprintf(outstream, "%s%s",
                              json_object_to_json_string_ext(json_object_array_get_idx(jo, i),
                                                  JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_SPACED),
                              (i + 1 < al) ? ",\n" : "\n") < 0) {
                        errno = EIO;
                        goto ioerr_exit;
                    }
                }
                break;
            }
            /* fallthrough */
        case TWAMP_REPORT_MODE_OBJECT:
            if (fprintf(outstream, "%s\n", json_object_to_json_string_ext(jo,
                                    JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_SPACED)) < 0) {
                errno = EIO;
                goto ioerr_exit;
            }
            break;
        default:
            break;
        }

        if (fflush(outstream) == EOF) {
            goto ioerr_exit;
        }

        if (outstream != output && fclose(outstream) == EOF) {
            print_err("%s: failed to close output: %s", what, strerror(errno));
            goto ioerr_exit2;
        }
    }

    return 0;

ioerr_exit:
    print_err("could not write LMAP report to output: %s", strerror(errno));
    if (outstream != output) {
       fclose(outstream);
    }
ioerr_exit2:
    return EIO;
}

int twamp_report_render_lmap(TWAMPReport *report, TWAMPParameters *param)
{
    char metric_name[256];

    assert(param);

    if (!(param->reports_enabled & TWAMP_REPORT_ENABLED_LMAP)) {
        print_msg(MSG_DEBUG, "LMAP report generation disabled by LMAP report mode");
        return 0;
    }

    print_msg(MSG_DEBUG, "generating LMAP report");

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
        const ReportPacket * const pktd = &report->result->pkt_data[it];

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
        xx_json_object_array_add_uint64_as_str(jcurrow, pktd->senderSeqNumber);
        xx_json_object_array_add_uint64_as_str(jcurrow, pktd->reflectorSeqNumber);
        xx_json_object_array_add_uint64_as_str(jcurrow, pktd->receiverSeqNumber);
        xx_json_object_array_add_uint64_as_str(jcurrow, pktd->senderTime_us);
        xx_json_object_array_add_uint64_as_str(jcurrow, pktd->reflectorRecvTime_us);
        xx_json_object_array_add_uint64_as_str(jcurrow, pktd->reflectorSendTime_us);
        xx_json_object_array_add_uint64_as_str(jcurrow, pktd->receiverTime_us);
        xx_json_object_array_add_uint64_as_str(jcurrow, pktd->rtt_us);

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

    if (report && report->privdata)
        ((struct twamp_report_private *)(report->privdata))->lmap_root = jo;

    return xx_serialize_partial_report("LMAP report", param->lmap_report_mode,
            param->lmap_report_path, param->lmap_report_output, jo);
}

/* updates report->result */
int twamp_report_statistics(TWAMPReport *report, TWAMPParameters *param)
{
    struct twpktstat {
        uint64_t rtt;
        int seen; /* 0b00 = not seen, 0b01 = seen, 0b11 = valid */
    };
    struct twpktstat * pktstat_storage = NULL;

    unsigned int packet_valid_count = 0; /* valid for statistics */
    unsigned int packet_invalid_count = 0;
    unsigned int packet_dupe_count = 0;
    unsigned int packet_late_count = 0;

    assert(param);

    unsigned int np = (report && report->result) ? report->result->packets_received : 0;
    /* skip guard packet, it is never reported or used */
    if (np == param->packets_max && np > 0)
        np--;

    if (!np) {
        report->result->packets_lost = report->result->packets_sent;
        print_msg(MSG_IMPORTANT, "stats: no packets were received");
        return 0;
    }

    const unsigned int maxseq = report->result->packets_sent; /* note: seq starts on zero */
    print_msg(MSG_DEBUG, "stats: inspecting %u received packets (%u sent)", np, maxseq);

    /* pktstat_storage holds the statistics indexed by sender sequence number */
    pktstat_storage = calloc(sizeof(struct twpktstat), maxseq);
    if (!pktstat_storage)
        return ENOMEM;

    int err = 0;

    for (unsigned int it = 0; it < np; it++) {
        const ReportPacket * const pktd = &report->result->pkt_data[it];

        unsigned int sender_seq    = pktd->senderSeqNumber;
        unsigned int reflector_seq = pktd->reflectorSeqNumber;

        /* sender_seq MUST NOT index into pktstat_storage[maxseq] if out-of-bounds */
        if (sender_seq >= maxseq || reflector_seq >= maxseq) {
            packet_invalid_count++;
            continue;
        }

        pktstat_storage[sender_seq].seen |= 1; /* for lost-packet tracking */

        if (! pktd->rtt_us) {
            /* we need to ensure it is actually zero, and not an error */

            uint64_t send_time = pktd->senderTime_us;
            uint64_t refl_RecvTime = pktd->reflectorRecvTime_us;
            uint64_t refl_ReturnTime = pktd->reflectorSendTime_us;
            uint64_t receive_time = pktd->receiverTime_us;

            if (refl_RecvTime > refl_ReturnTime || send_time > receive_time) {
                packet_invalid_count++;
                continue;
            }

            uint64_t reflector_time = refl_ReturnTime - refl_RecvTime;
            uint64_t rtt_us = receive_time - send_time;
            if (reflector_time > rtt_us) {
                packet_invalid_count++;
                continue;
            }
        }

        if (pktstat_storage[sender_seq].seen & 2) {
            /* duplicate: count and skip */
            packet_dupe_count++;
            continue;
        }

        if (pktd->rtt_us > param->packets_timeout_us) {
            /* arrived late and not a duplicate: count and proceed */
            packet_late_count++;
        }

        pktstat_storage[sender_seq].seen = 3; /* valid for statistics */
        pktstat_storage[sender_seq].rtt = pktd->rtt_us;
        packet_valid_count++;
    }

    print_msg(MSG_DEBUG, "stats: received packets breakdown: %u valid (%u late), %u duplicate(s), %u invalid",
              packet_valid_count, packet_late_count, packet_dupe_count, packet_invalid_count);

    if (np != packet_invalid_count + packet_dupe_count + packet_valid_count) {
        print_err("stats: internal error: inconsistent packet counts, aborting...");
        err = EFAULT;
        goto err_exit;
    }

    report->result->packets_valid = packet_valid_count;
    report->result->packets_duplicated = packet_dupe_count;
    report->result->packets_invalid = packet_invalid_count;
    report->result->packets_late = packet_late_count;

    unsigned int packet_lost_count;
    uint64_t rtt_min_us = UINT_MAX;
    uint64_t rtt_max_us = 0;
    uint64_t rtt_median_us = 0;
    if (packet_valid_count > 0) {
        packet_lost_count = 0;
        for (unsigned int is = 0; is < maxseq; is++) {
            packet_lost_count += (pktstat_storage[is].seen == 0) ? 1 : 0;
            if (pktstat_storage[is].seen & 2) {
                /* valid for statistics... */
                if (pktstat_storage[is].rtt > rtt_max_us)
                    rtt_max_us = pktstat_storage[is].rtt;
                if (pktstat_storage[is].rtt < rtt_min_us)
                    rtt_min_us = pktstat_storage[is].rtt;
            }
        }

        /* Median, algorithm by Torben Mogensen, original code by N. Devillard
         *
         * needs the min/max pass above. Not the fastest: does multiple
         * passes over the array, but it doesn't modify the array and it
         * does not need any extra memory.
         */
        const unsigned int n  = packet_valid_count;
        const unsigned int hn = (n+1)/2;
        uint64_t pmin = rtt_min_us;
        uint64_t pmax = rtt_max_us;
        uint64_t guess, gmaxl, gming;
        unsigned int lcnt, gcnt, ecnt; /* element counters */
        unsigned int passes = 0; /* for debugging */
        while (1) {
            passes++;

            lcnt = 0, gcnt = 0, ecnt = 0;
            gmaxl = pmin;
            gming = pmax;
            guess = (pmin + pmax)/2; /* FIXME: should we round to nearest ? */

            /* we could iterate through report->result instead and get the seqnum
             * to index pktstat_storage, but that'd be better only when there's a
             * large packet loss, on a large sample, and not many duplicates.
             * Instead, do what is simpler, less error-prone, and likely to be
             * more cache-friendly */
            for (unsigned int is = 0; is < maxseq; is++) {
                if (!(pktstat_storage[is].seen & 2))
                    continue; /* invalid entry for statistics */

                if (pktstat_storage[is].rtt < guess) {
                    if (pktstat_storage[is].rtt > gmaxl)
                        gmaxl = pktstat_storage[is].rtt;
                    lcnt++;
                } else if (pktstat_storage[is].rtt > guess) {
                    if (pktstat_storage[is].rtt < gming)
                        gming = pktstat_storage[is].rtt;
                    gcnt++;
                } else {
                    ecnt++;
                }
            }
            if (lcnt <= hn && gcnt <= hn) {
                break; /* no need to further partition */
            } else if (lcnt > gcnt) {
                pmax = gmaxl;
            } else {
                pmin = gming;
            }
        }
        if (lcnt >= hn) {
            pmin = gmaxl;
        } else if (lcnt + ecnt >= hn) {
            pmin = guess;
        } else {
            pmin = gming;
        }
        if (n & 1) {
            /* n odd: pmin is our median */
            rtt_median_us = pmin;
        } else {
            /* n even: calculate the pmax, and average */
            if (gcnt >= hn) {
                pmax = gming;
            } else if (gcnt + ecnt >= hn) {
                pmax = guess;
            } else {
                pmax = gmaxl;
            }
            rtt_median_us = (pmin + pmax + 1)/2; /* round(a/b) == trunc(a + (b/2)/b) for sign(a)=sign(b) */
        }
        print_msg(MSG_DEBUG, "stats: needed %u passes to find median for %u points", passes, n);

        report->result->rtt_min = rtt_min_us;
        report->result->rtt_max = rtt_max_us;
        report->result->rtt_median = rtt_median_us;
    } else {
        packet_lost_count = report->result->packets_sent - packet_invalid_count - packet_dupe_count;
        print_msg(MSG_IMPORTANT, "stats: no valid packets were received");
    }
    report->result->packets_lost = packet_lost_count;

    print_msg(MSG_NORMAL, "stats: %u packets sent, %u packets lost (not including packets arriving too late)", report->result->packets_sent, packet_lost_count);
    print_msg(MSG_NORMAL, "stats: RTT (microseconds): min=%" PRIu64 ", max=%" PRIu64 ", median=%" PRIu64, rtt_min_us, rtt_max_us, rtt_median_us);

err_exit:
    free(pktstat_storage);
    return err;
}

/*
 * { "metadata": {
 *      "ip_family": "ip4"|"ip6",
 *      "server": "<hostname or ip, same as command line>",
 *      "server_port": "<port or service, same as command line",
 *      "test_session_connection": {
 *        "ip_family": "ip4"|"ip6",
 *        "sender_addr": "<ip address>"
 *        "sender_port": "<numeric port>"
 *        "reflector_addr": "<ip address>",
 *        "reflector_port": "<numeric port",
 *      }
 *   },
 *   "parameters": {
 *      "packet_delay_us": <int64>,
 *      "packet_timeout_us": <int64>,
 *      "packet_count": <int64>,
 *      "packet_payload_size": <uint16>,  // UDP payload size, no UDP+IP headers
 *      "discard_on_timeout": <bool>,
 *   },
 *   "results_summary": {
 *      "packets_sent": <int64>,
 *      "packets_received_valid": <int64>,
 *      "packets_received_invalid": <int64>,
 *      "packets_received_late": <int64>,     // discard_on_timeout false
 *      "packets_discarded_timeout": <int64>, // discard_on_timeout true
 *      "packets_received_duplicates": <int64>,
 *      "packets_lost": <int64>,
 *      // only if packets_received_valid > 0:
 *      "rtt": {
 *         "rtt_min_us": <int64>,
 *         "rtt_max_us": <int64>,
 *         "rtt_median_us": <int64>
 *      }
 *   }
 * }
 */
int twamp_report_render_summary(TWAMPReport *report, TWAMPParameters *param)
{
    json_object *jo, *jo1;

    assert(param);

    if (!report || !report->result)
        return ENODATA;
    if (!report->privdata)
        return EINVAL;

    if (!(param->reports_enabled & TWAMP_REPORT_ENABLED_SUMMARY))
        return 0; /* report disabled */

    /* FIXME: not implemented (yet?) */
    const bool param_discard_on_timeout = false;

    json_object *jsummary = NULL;
    if (report && report->privdata) {
        jsummary = ((struct twamp_report_private *)(report->privdata))->summary_root;
    }
    if (!jsummary)
        jsummary = json_object_new_object();
    assert(jsummary);

    const struct twamp_result * const r = report->result;

    if (param->reports_enabled & TWAMP_REPORT_ENABLED_TMETADATA) {
        /* metadata, FIXME: socket metrics refactoring */
        jo = json_object_new_object();
        json_object_object_add(jo, "ip_family", json_object_new_string(str_ip46(param->family)));
        json_object_object_add(jo, "server", json_object_new_string(param->host));
        json_object_object_add(jo, "server_port", json_object_new_string(param->port));
        jo1 = json_object_new_object();

        const struct twamp_connection_info * const rtse = &(r->test_session_endpoints);
        json_object_object_add(jo1, "ip_family", json_object_new_string(rtse->local_endpoint.family));
        json_object_object_add(jo1, "sender_addr", json_object_new_string(rtse->local_endpoint.addr));
        json_object_object_add(jo1, "sender_port", json_object_new_string(rtse->local_endpoint.port));
        json_object_object_add(jo1, "reflector_addr", json_object_new_string(rtse->remote_endpoint.addr));
        json_object_object_add(jo1, "reflector_port", json_object_new_string(rtse->remote_endpoint.port));
        json_object_object_add(jo, "test_session_connection", jo1); jo1 = NULL;

        json_object_object_add(jsummary, "metadata", jo); jo = NULL;
    }

    if (param->reports_enabled & TWAMP_REPORT_ENABLED_TPARAMETERS) {
        /* parameters */
        jo = json_object_new_object();
        json_object_object_add(jo, "packet_count", json_object_new_int64(param->packets_count));
        json_object_object_add(jo, "packet_payload_size", json_object_new_int64(param->payload_size));
        json_object_object_add(jo, "packet_timeout_us", json_object_new_int64(param->packets_timeout_us));
        json_object_object_add(jo, "packet_delay_us", json_object_new_int64(param->packets_interval_us));
        json_object_object_add(jo, "discard_on_timeout", json_object_new_boolean(param_discard_on_timeout));
        json_object_object_add(jsummary, "parameters", jo); jo = NULL;
    }

    if (param->reports_enabled & TWAMP_REPORT_ENABLED_RSTATS) {
        /* summary */
        jo = json_object_new_object();
        json_object_object_add(jo, "packets_sent", json_object_new_int64(r->packets_sent));
        json_object_object_add(jo, "packets_received_valid", json_object_new_int64(r->packets_valid));
        json_object_object_add(jo, (param_discard_on_timeout) ? "packets_discarded_timeout" : "packets_received_late", json_object_new_int64(r->packets_late));
        json_object_object_add(jo, "packets_received_invalid", json_object_new_int64(r->packets_invalid));
        json_object_object_add(jo, "packets_received_duplicates", json_object_new_int64(r->packets_duplicated));
        json_object_object_add(jo, "packets_lost", json_object_new_int64(r->packets_lost));

        if (r->packets_valid > 0) {
            json_object *jrtt = json_object_new_object();
            json_object_object_add(jrtt, "rtt_min_us", json_object_new_int64((int64_t)r->rtt_min));
            json_object_object_add(jrtt, "rtt_max_us", json_object_new_int64((int64_t)r->rtt_max));
            json_object_object_add(jrtt, "rtt_median_us", json_object_new_int64((int64_t)r->rtt_median));
            json_object_object_add(jo, "rtt", jrtt);
        }
        json_object_object_add(jsummary, "results_summary", jo); jo = NULL;
    }

    return xx_serialize_partial_report("summary report", TWAMP_REPORT_MODE_OBJECT,
            param->summary_report_path, param->summary_report_output, jsummary);
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
            if (p->summary_root)
                json_object_put(p->summary_root);
            free(p);
            }
        if (r->result) {
            free(r->result->pkt_data);
            free(r->result);
        }
        free(r);
    }
}

/* vim: set et ts=4 sw=4 : */
