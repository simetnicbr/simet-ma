#ifndef REPORT_H_
#define REPORT_H_

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