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

#ifndef MESSAGE_H_
#define MESSAGE_H_

#include "twampc_config.h"
#include "timestamp.h"

#include <stddef.h>
#include <inttypes.h>
#include <sys/types.h>
#include <assert.h>

#if !defined(static_assert) && defined(__STDC_VERSION__) && (__STDC_VERSION__ < 202301L)
#  define static_assert _Static_assert
#endif

/********************/
/* CONTROL MESSAGES */
/********************/

// Server Greetings message
typedef struct server_greetings {
    uint8_t Unused[12];
    uint32_t Modes;
    uint8_t Challenge[16];
    uint8_t Salt[16];
    uint32_t Count;
    uint8_t MBZ[12];
} ServerGreeting;

// Set-Up Response message
typedef struct setup_response {
    uint32_t Mode;
    uint8_t KeyID[80];
    uint8_t Token[64];
    uint8_t ClientIV[16];
} SetupResponse;

// Server Start message
typedef struct server_start {
    uint8_t MBZ1[15];
    uint8_t Accept;
    uint8_t ServerIV[16];
    Timestamp StartTime;
    uint8_t MBZ2[8];
} ServerStart;

/********************/
/* SESSION MESSAGES */
/********************/

// Request Session message
typedef struct request_session {
    uint8_t Type;
    uint8_t IPVN;
    uint8_t ConfSender;
    uint8_t ConfReceiver;
    uint32_t SlotsNo;
    uint32_t PacketsNo;
    uint16_t SenderPort;
    uint16_t ReceiverPort;
    uint32_t SenderAddress;
    uint8_t MBZ1[12];
    uint32_t ReceiverAddress;
    uint8_t MBZ2[12];
    uint8_t SID[16];
    uint32_t PaddingLength;
    Timestamp StartTime;
    Timestamp Timeout;
    uint32_t TypePDescriptor;
    uint8_t MBZ3[8];
    uint8_t HMAC[16];
} RequestSession;

// Accept Session message
typedef struct accept_session {
    uint8_t Accept;
    uint8_t MBZ1;
    uint16_t Port;
    uint8_t SID[16];
    uint8_t MBZ2[12];
    uint8_t HMAC[16];
} AcceptSession;

// Start Sessions message
typedef struct start_sessions {
    uint8_t Type;
    uint8_t MBZ[15];
    uint8_t HMAC[16];
} StartSessions;

// Start Ack message
typedef struct start_ack {
    uint8_t Accept;
    uint8_t MBZ[15];
    uint8_t HMAC[16];
} StartAck;

// Stop Sessions message
typedef struct twamp_stop {
    uint8_t Type;
    uint8_t Accept;
    uint8_t MBZ1[2];
    uint32_t SessionsNo;
    uint8_t MBZ2[8];
    uint8_t HMAC[16];
} StopSessions;

/*****************/
/* TEST MESSAGES */
/*****************/

#define MAX_TSTPKT_SIZE 65400
#define MIN_TSTPKT_SIZE 128     /* large enough for twamp, stamp, twamp light, all modes */
#define DFL_TSTPKT_SIZE 128     /* packet size for the SIMET2 basic measurement */
#define OWAMP_PAD_OFFSET 14     /* where the "padding" in OWAMP-based messages start */

/* RFC-6038, RFC-7750, symmetric-mode, reflect-octets-compatible packet */
typedef struct __attribute__((__packed__)) {
    uint32_t SeqNumber;
    Timestamp Time;
    uint16_t ErrorEstimate;
    uint8_t MBZ1[27];  /* STAMP and RFC-6038 symmetric mode. RFC-7750 has data in offset 2 */
    uint8_t MBZ2[3];   /* Extra alignment zone required by STAMP and by SIMET cookies */
    uint8_t Padding[]; /* TLV area for STAMP or start of SIMET cookie, padding for twamp/light */
} UnauthPacket;

typedef struct __attribute__((__packed__)) {
    uint32_t SeqNumber;
    Timestamp Time;
    uint16_t ErrorEstimate;
    uint8_t MBZ1[2];
    Timestamp RecvTime;
    uint32_t SenderSeqNumber;
    Timestamp SenderTime;
    uint16_t SenderErrorEstimate;
    uint8_t MBZ2[2];
    uint8_t SenderTTL;
    uint8_t MBZ3[3];   /* STAMP-required, don't-care for twamp/light */
    uint8_t Padding[]; /* TLV area for STAMP, padding for twamp/light */
} UnauthReflectedPacket;

static_assert(sizeof(UnauthPacket) < MIN_TSTPKT_SIZE, "MIN_TSTPKT_SIZE too small for type UnauthPacket");
static_assert(offsetof(UnauthPacket, Padding) == offsetof(UnauthReflectedPacket, Padding), "types UnauthPacket and UnauthReflectedPacket are not compatible");

/***********/
/* DEFINES */
/***********/

#define MAX_SIZE_MESSAGE 1024
#define SERVER_GREETINGS_SIZE sizeof(ServerGreeting)
#define SETUP_RESPONSE_SIZE sizeof(SetupResponse)
#define SERVER_START_SIZE sizeof(ServerStart)
#define REQUEST_SESSION_SIZE sizeof(RequestSession)
#define ACCEPT_SESSION_SIZE sizeof(AcceptSession)
#define START_SESSIONS_SIZE sizeof(StartSessions)
#define START_ACK_SIZE sizeof(StartAck)

/********************/
/* MESSAGES READERS */
/********************/

/* all of these return -1 on error, errno set.  Returns size of message otherwise */
ssize_t message_server_greetings(const int socket, const int timeout, ServerGreeting * const srvGreetings);
ssize_t message_server_start(const int socket, const int timeout, ServerStart * const srvStart);
ssize_t message_accept_session(const int socket, const int timeout, AcceptSession * const actSession);
ssize_t message_start_ack(const int socket, const int timeout, StartAck * const strAck);

/********************/
/* MESSAGES SENDERS */
/********************/

ssize_t message_send(const int socket, const int timeout, void * const message, const size_t len);

/***********************/
/* MESSAGES VALIDATORS */
/***********************/

int message_validate_server_greetings(ServerGreeting *srvGreetings);

/***********************/
/* MESSAGES FORMATTERS */
/***********************/

int message_format_setup_response(ServerGreeting *srvGreetings, SetupResponse *stpResponse);
int message_format_request_session(int ipvn, size_t padding_size, uint16_t sender_port, RequestSession *rqtSession);

int message_format_stop_sessions(StopSessions *stpSessions);

#endif /* MESSAGE_H_ */
