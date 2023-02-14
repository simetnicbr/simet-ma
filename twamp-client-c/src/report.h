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

typedef struct twamp_raw_data {
    Timestamp time;
    UnauthReflectedPacket data;
} TWAMPRawData;

typedef struct twamp_result {
    unsigned int packets_sent;
    unsigned int packets_received;
    unsigned int packets_dropped_timeout; /* FIXME: remove or repurpose */
    /* FIXME: duplicates, out-of-sequence */
    TWAMPRawData * raw_data;
} TWAMPResult;

typedef struct twamp_report {
    const char *host;
    const char *address;
    unsigned int serverPort;
    sa_family_t family;

    TWAMPResult * result;
    void * privdata;
} TWAMPReport;

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

#endif /* REPORT_H_ */
