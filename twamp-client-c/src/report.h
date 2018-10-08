/*
 * Copyright (c) 2018 NIC.br  <medicoes@simet.nic.br>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef REPORT_H_
#define REPORT_H_

#include "twampc_config.h"
#include "timestamp.h"
#include "message.h"

typedef struct twamp_raw_data {
    UnauthReflectedPacket data;
    Timestamp time;
} TWAMPRawData;

typedef struct twamp_result {
    unsigned int packets_sent;
    unsigned int received_packets;
    TWAMPRawData * raw_data;
} TWAMPResult;

typedef struct twamp_report {
    char *device_id;
    
    char *host;
    char *address;
    unsigned int serverPort;
    int family;

    TWAMPResult * result;
} TWAMPReport;

typedef struct report_packet {
    unsigned int senderSeqNumber;
    unsigned int reflectorSeqNumber;
    unsigned int receiverSeqNumber;

    unsigned int senderTime_us;
    unsigned int reflectorRecvTime_us;
    unsigned int reflectorSendTime_us;
    unsigned int receiverTime_us;

    unsigned int rtt_us;
} ReportPacket;

int twamp_report(TWAMPReport*);

#endif /* REPORT_H_ */
