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

#include "twampc_config.h"
#include "timestamp.h"
#include "message.h"

typedef struct report_packet {
    unsigned int senderSeqNumber;
    unsigned int reflectorSeqNumber;
    unsigned int receiverSeqNumber;

    uint64_t senderTime_us;
    uint64_t reflectorRecvTime_us;
    uint64_t reflectorSendTime_us;
    uint64_t receiverTime_us;

    uint64_t rtt_us;
} ReportPacket;

struct twamp_socket_info {
    const char *family;
    const char *addr;
    const char *port;
};

struct twamp_connection_info {
    int protocol; /* IPPROTO_* */
    struct twamp_socket_info local_endpoint;
    struct twamp_socket_info remote_endpoint;
};

typedef struct twamp_result {
    unsigned int packets_sent;     /* updated by sending thread at exit */
    unsigned int packets_received; /* updated by receiving thread at exit */

    /* updated through twamp_report_socket_metrics() */
    struct twamp_connection_info test_session_endpoints;

    /* analysis
     *
     * duplicates:
     *
     * 1. The first packet received [with a given sender sequence number]
     *    is not a duplicate, however any other packets received later with
     *    that same sender sequence number later are duplicates/"dupes".
     *
     * 2. Late-arriving duplicates are counted as duplicates, not as late-
     *    arriving packets.  The fact that there was a duplicate is more
     *    important for network behavior analysis.
     *
     * 3. Duplicates are skipped when calculating statistics such as RTT
     *    min/max/median.  We assume any application would have processed
     *    it at the time the first (non-duplicate) copy arrived.
     *
     * lost packets, late-arriving packets:
     *
     * 1. Late-arriving packets are supposed to be considered *lost* as
     *    far as analysis is concerned (per RFC), unless they're duplicates
     *    (see above).  But that is highly confusing to anyone that is not
     *    a TWAMP-expert, so we do not do that.
     *
     *    Late-arriving packets are accounted as valid, received, and
     *    contribute to RTT statistics.
     *
     * 2. Late-arriving packets increase packets_received, packets_late,
     *    packets_valid (if lateness is the packet's only problem).
     *
     * 3. Lost packets are packets that were sent and never received by
     *    the time the receiver was shutdown, as tracked by sender sequence
     *    number.  It does not include invalid packets.
     *
     * invalid packets:
     *
     * 1. Usually the number of invalid packets will be zero, as packets
     *    that are obviously corrupted / malformed are discarded at
     *    receive time.  The usual reason for a packet to be invalid are
     *    incorrect timestamps.
     *
     * 2. Reflected packets with bad signatures are not considered invalid,
     *    they are assumed to be *fakes* and discarded at receive time.
     *
     * Note that this is for *analysis* pruposes. Raw data reports have
     * everything that was received, as received, in the order it was
     * received, including invalid packets that were not so corrupt as to
     * be discarted as not-a-valid-reply-packet.
     *
     * medians, min, max:
     *
     * 1. ignores duplicated packets
     * 2. rounds fractions to nearest integer (for odd sample count)
     */
    unsigned int packets_valid;
    unsigned int packets_late;
    unsigned int packets_invalid;
    unsigned int packets_duplicated;
    unsigned int packets_lost; /* does NOT include packets_late */
    /* FIXME: count reordered packets */

    /* rtt, microseconds */
    uint64_t rtt_min;
    uint64_t rtt_max;
    uint64_t rtt_median;

    ReportPacket * pkt_data;
} TWAMPResult;

typedef struct twamp_report {
    const char *host;
    const char *address;
    unsigned int serverPort;
    sa_family_t family;

    TWAMPResult * result;
    void * privdata;
} TWAMPReport;

#endif /* REPORT_H_ */
