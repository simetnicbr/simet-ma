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

#include "twamp.h"
#include "report.h"
#include "message.h"
#include "logger.h"

#include <json-c/json.h>
#include <assert.h>

#define TWAMP_R_NUMCOLS 8
const char const * twamp_report_col_names[TWAMP_R_NUMCOLS] = {
	"senderSeqNum", "reflectorSeqNum", "receiverSeqNum",
	"senderTimeUs", "reflectorRecvTimeUs",
	"reflectorSendTimeUs", "receiverTimeUs",
	"rttUs"
};

static void xx_json_object_array_add_uin64_as_str(json_object *j, uint64_t v)
{
	char buf[32];
	snprintf(buf, sizeof(buf), "%" PRIu64, v);
        json_object_array_add(j, json_object_new_string(buf));
}

int twamp_report(TWAMPReport *report, TWAMPParameters *param)
{
    char metric_name[256];

    assert(report);
    assert(param);

    snprintf(metric_name, sizeof(metric_name),
	    "Priv_MPMonitor_Active_UDP-Periodic-IntervalDurationMs%u-PackageCount%u-PackageSizeBytes%u__Multiple_Raw",
	    param->packets_interval_ns / 1000, param->packets_count, TST_PKT_SIZE);

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
    json_object_array_add(jo2, json_object_new_string("client"));
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

    for (unsigned int it = 0; it < report->result->received_packets; it++) {
        ReportPacket pkg;

        struct timeval tv_sender = timestamp_to_timeval(&(report->result->raw_data[it].data.SenderTime));
        uint64_t sendTime = timeval_to_microsec(&tv_sender);

        struct timeval tv_reflector_recv = timestamp_to_timeval(&(report->result->raw_data[it].data.RecvTime));
        uint64_t reflRecvTime = timeval_to_microsec(&tv_reflector_recv);

        struct timeval tv_reflector_ret = timestamp_to_timeval(&(report->result->raw_data[it].data.Time));
        uint64_t reflReturnTime = timeval_to_microsec(&tv_reflector_ret);

        struct timeval tv_ret = timestamp_to_timeval(&(report->result->raw_data[it].time));
        uint64_t returnTime = timeval_to_microsec(&tv_ret);

        uint64_t processTime = reflReturnTime - reflRecvTime;

        pkg.senderSeqNumber = report->result->raw_data[it].data.SenderSeqNumber;
        pkg.reflectorSeqNumber = report->result->raw_data[it].data.SeqNumber;
        pkg.receiverSeqNumber = it;

        pkg.senderTime_us = sendTime;
        pkg.reflectorRecvTime_us = reflRecvTime;
        pkg.reflectorSendTime_us = reflReturnTime;
        pkg.receiverTime_us = returnTime;

        pkg.rtt_us = returnTime - sendTime - processTime;

        /* this row (object), will be inserted into the row array later, it is a list of cells */
        json_object * jcurrow = json_object_new_array();

        /* WARNING: keep the same insert order as in twamp_report_col_names[] ! */
        xx_json_object_array_add_uin64_as_str(jcurrow, pkg.senderSeqNumber);
        xx_json_object_array_add_uin64_as_str(jcurrow, pkg.reflectorSeqNumber);
        xx_json_object_array_add_uin64_as_str(jcurrow, pkg.receiverSeqNumber);
        xx_json_object_array_add_uin64_as_str(jcurrow, pkg.senderTime_us);
        xx_json_object_array_add_uin64_as_str(jcurrow, pkg.reflectorRecvTime_us);
        xx_json_object_array_add_uin64_as_str(jcurrow, pkg.reflectorSendTime_us);
        xx_json_object_array_add_uin64_as_str(jcurrow, pkg.receiverTime_us);
        xx_json_object_array_add_uin64_as_str(jcurrow, pkg.rtt_us);

        /* add row to list of rows */
        jo = json_object_new_object();
        json_object_object_add(jo, "value", jcurrow);
        json_object_array_add(jarray_res_tbl_rows, jo);
        jo = NULL;
    }

    json_object_object_add(jres_tbl_content, "row", jarray_res_tbl_rows);
    jarray_res_tbl_rows = NULL;

    fprintf(stdout, "%s\n", json_object_to_json_string_ext(jres_tbl_content, JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_SPACED));
    fflush(stdout);

    return 0;
}

