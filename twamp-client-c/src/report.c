#include "report.h"

#include "logger.h"

#include <json-c/json.h>
#include <assert.h>

#if 0
int twamp_report_old(TWAMPReport * report)
{
    assert(report);

    //Creating a json object
    json_object * jobj = json_object_new_object();
    assert(jobj);  /* FIXME: proper ENOMEM handling */

    //Creating a json string
    json_object * j_device_id = json_object_new_string(report->device_id);
    json_object * j_host = json_object_new_string(report->host);
    json_object * j_test_server = json_object_new_string(report->address);
    json_object * j_server_port = json_object_new_int64(report->serverPort);
    json_object * j_family = json_object_new_int(report->family);
    
    json_object_object_add(jobj,"deviceID", j_device_id);
    json_object_object_add(jobj,"host", j_host);
    json_object_object_add(jobj,"testServer", j_test_server);
    json_object_object_add(jobj,"serverPort", j_server_port);
    json_object_object_add(jobj,"family", j_family);


    json_object * jresult = json_object_new_object();

    json_object * j_pkg_sent = json_object_new_int64(report->result->packets_sent);
    json_object * j_pkg_recv = json_object_new_int64(report->result->received_packets);

    json_object_object_add(jresult,"sent", j_pkg_sent);
    json_object_object_add(jresult,"received", j_pkg_recv);

    json_object * jarray_results = json_object_new_array();

    for (int it=0; it < report->result->received_packets; it++) {
        
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

        //DEBUG_LOG("[RTT] [%d] %"PRIu64" usec", it, returnTime - sendTime - processTime);

        pkg.senderSeqNumber = report->result->raw_data[it].data.SenderSeqNumber;
        pkg.reflectorSeqNumber = report->result->raw_data[it].data.SeqNumber;
        pkg.receiverSeqNumber = it;

        pkg.senderTime_us = sendTime;
        pkg.reflectorRecvTime_us = reflRecvTime;
        pkg.reflectorSendTime_us = reflReturnTime;
        pkg.receiverTime_us = returnTime;

        pkg.rtt_us = returnTime - sendTime - processTime;

        json_object * j_sender_seqnum = json_object_new_int64(pkg.senderSeqNumber);
        json_object * j_reflector_seqnum = json_object_new_int64(pkg.reflectorSeqNumber);
        json_object * j_receiver_seqnum = json_object_new_int64(pkg.receiverSeqNumber);

        json_object * j_sender_time = json_object_new_int64(pkg.senderTime_us);
        json_object * j_reflector_recv_time = json_object_new_int64(pkg.reflectorRecvTime_us);
        json_object * j_reflector_send_time = json_object_new_int64(pkg.reflectorSendTime_us);
        json_object * j_receiver_time = json_object_new_int64(pkg.receiverTime_us);

        json_object * j_rtt = json_object_new_int64(pkg.rtt_us);

        json_object * jpacket = json_object_new_object();

        json_object_object_add(jpacket,"senderSeqNum", j_sender_seqnum);
        json_object_object_add(jpacket,"reflectorSeqNum", j_reflector_seqnum);
        json_object_object_add(jpacket,"receiverSeqNum", j_receiver_seqnum);

        json_object_object_add(jpacket,"senderTimeUs", j_sender_time);
        json_object_object_add(jpacket,"reflectorRecvTimeUs", j_reflector_recv_time);
        json_object_object_add(jpacket,"reflectorSendTimeUs", j_reflector_send_time);
        json_object_object_add(jpacket,"receiverTimeUs", j_receiver_time);

        json_object_object_add(jpacket,"rttUs", j_rtt);

        json_object_array_add(jarray_results,jpacket);
    }

    json_object_object_add(jobj,"result", jarray_results);

    fprintf(stdout, "%s\n", json_object_to_json_string(jobj));
    fflush(stdout);
}
#endif

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

int twamp_report(TWAMPReport * report)
{
    assert(report);

    json_object *jo, *jo1;  /* Used when we will transfer ownership via *_add */

    json_object * jobj = json_object_new_object();
    assert(jobj);  /* FIXME: proper ENOMEM handling for everything in this module... */

    /* Create some objects we will add to the topology later */
    json_object * j_device_id = json_object_new_string(report->device_id); /* twamp agent_id */
    json_object * j_host = json_object_new_string(report->host);
    json_object * j_test_server = json_object_new_string(report->address);
    json_object * j_server_port = json_object_new_int64(report->serverPort);
    json_object * j_family = json_object_new_int(report->family);

#if 0 /* FIXME: need to become metadata somehow, likely parameters and args */
    json_object_object_add(jobj,"deviceID", j_device_id);
    json_object_object_add(jobj,"host", j_host);
    json_object_object_add(jobj,"testServer", j_test_server);
    json_object_object_add(jobj,"serverPort", j_server_port);
    json_object_object_add(jobj,"family", j_family);

    /* FIXME, need to go somewhere in the report as metadata */
    json_object * j_pkg_sent = json_object_new_int64(report->result->packets_sent);
    json_object * j_pkg_recv = json_object_new_int64(report->result->received_packets);
    json_object_object_add(jobj,"sent", j_pkg_sent);
    json_object_object_add(jobj,"received", j_pkg_recv);
#endif

    /* create objects and build the topology for the result table */
    /* FIXME: abort if the _add() calls return non-zero, etc */
    json_object * jres_tbl_a = json_object_new_array(); /* array of jres_tbl1..n */

    /* TABLE 1 */
    json_object * jres_tbl1 = json_object_new_object();  /* shall contain function, column, row arrays */

    /* table1 function object list */
    jo = json_object_new_array();
    jo1 = json_object_new_object();
    json_object_object_add(jo1, "uri", json_object_new_string("TWAMP_raw_simet_v1"));
    json_object_object_add(jo1, "role", json_object_new_string("client"));
    json_object_array_add(jo, jo1);
    json_object_object_add(jres_tbl1, "function", jo);
    jo = jo1 = NULL;

    /* table1 columns list */
    jo = json_object_new_array();
    for (unsigned int i = 0; i < TWAMP_R_NUMCOLS; i++) {
        json_object_array_add(jo, json_object_new_string(twamp_report_col_names[i]));
    };
    json_object_object_add(jres_tbl1, "column", jo);
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

    json_object_object_add(jres_tbl1, "row", jarray_res_tbl_rows);
    jarray_res_tbl_rows = NULL;
    json_object_array_add(jres_tbl_a, jres_tbl1);
    jres_tbl1 = NULL;
    json_object_object_add(jobj, "table", jres_tbl_a);
    jres_tbl_a = NULL;

    fprintf(stdout, "%s\n", json_object_to_json_string_ext(jobj, JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_SPACED));
    fflush(stdout);

    return 0;
}

