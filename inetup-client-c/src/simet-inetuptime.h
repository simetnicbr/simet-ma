/*
 * SIMET2 MA Internet Availability Measurement (inetup) client
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

#ifndef SIMET_INETUPTIME_H
#define SIMET_INETUPTIME_H

#include <stdint.h>
#include <time.h>
#include <sys/socket.h>

#include "tcpaq.h"

#define SIMET_UPTIME2_DEFAULT_PORT	"22000"

/* SIMET2 Uptime2 defaults and limits */
#define SIMET_UPTIME2_DEFAULT_TIMEOUT    60    /* seconds */
#define SIMET_UPTIME2_SHORTEST_TIMEOUT   15    /* seconds, lower limit on acceptable timeouts */
#define SIMET_UPTIME2_LONGEST_TIMEOUT    86400 /* seconds, upper limit on acceptable timeouts */
#define SIMET_UPTIME2_DEFAULT_KEEPALIVE  30    /* at least one keepalive per default timeout */
#define SIMET_UPTIME2_LONGEST_KEEPALIVE  (SIMET_UPTIME2_LONGEST_TIMEOUT / 2)
#define SIMET_UPTIME2_SHORTEST_KEEPALIVE (SIMET_UPTIME2_SHORTEST_TIMEOUT / 2)
#define SIMET_UPTIME2_DISCONNECT_BACKOFF 1    /* connection tries before can reconnect to same peer */

#define SIMET_UPTIME2_DFL_MSR_PERIOD     300  /* desired base measurement period, seconds */

/* SIMET2 Uptime2 protocol constants */
#define SIMET_INETUP_P_MSGTYPE_CONNECT      0x0000U
#define SIMET_INETUP_P_MSGTYPE_KEEPALIVE    0x0001U
#define SIMET_INETUP_P_MSGTYPE_EVENTS       0x0002U
#define SIMET_INETUP_P_MSGTYPE_MACONFIG     0x0003U
#define SIMET_INETUP_P_MSGTYPE_DISCONNECT   0x0004U
#define SIMET_INETUP_P_MSGTYPE_MEASUREMENT  0x0005U
#define SIMET_ENGINE_NAME "nic_simet2_simet-ma"

enum simet_inetup_protocol_state {
    SIMET_INETUP_P_C_INIT = 0,		/* Initial setup */
    SIMET_INETUP_P_C_RECONNECT,		/* TCP (re)connection with backoff control */
    SIMET_INETUP_P_C_CONNECT,		/* Loop over DNS results, TCP nonblock connect() */
    SIMET_INETUP_P_C_CONNECTWAIT,	/* Wait TCP connect() reply */
    SIMET_INETUP_P_C_CONNECTED,		/* TCP connected, sent CONNECT message */
    SIMET_INETUP_P_C_WAITCONFIG,	/* wait for MA_CONFIG, go to mainloop */
    SIMET_INETUP_P_C_MAINLOOP,		/* keepalive and events loop */
    SIMET_INETUP_P_C_DISCONNECT,	/* send shutdown notification */
    SIMET_INETUP_P_C_DISCONNECT_WAIT,	/* wait for queue drain, force connection shutdown */
    SIMET_INETUP_P_C_SHUTDOWN,		/* do nothing, terminal state */

    SIMET_INETUP_P_C_MAX
};

struct simet_inetup_msghdr {
    /* network byte order in the wire */
    uint16_t message_type;
    uint32_t message_size;
    /* the message goes here */
} __attribute__((__packed__));

struct simet_inetup_server_cluster {
    struct simet_inetup_server_cluster *next;
    const char * cluster_name;
    const char * cluster_port;
};

struct simet_inetup_server {
    struct tcpaq_conn conn;

    enum simet_inetup_protocol_state state;
    time_t keepalive_clock;
    time_t remote_keepalive_clock;
    time_t disconnect_clock;
    unsigned int backoff_level;
    time_t backoff_clock;
    time_t backoff_reset_clock;

    unsigned int connection_id;
    const struct simet_inetup_server_cluster *cluster;  /* not owned */

    /* state CONNECTING metadata */
    struct addrinfo *peer_gai;	        /* result from getaddrinfo() */
    struct addrinfo *peer_ai;	         /* current peers_gai member */

    /* post connect() metadata */
    time_t connect_timestamp;
    sa_family_t peer_family;
    const char *peer_name;
    const char *peer_port;
    sa_family_t local_family;
    const char *local_name;
    const char *local_port;
    unsigned int peer_noconnect_ttl;

    /* server-configurable parameters */
    unsigned int ma_config_count;   /* 0 (not yet), 1 (once) or 2 (reconfig) */
    unsigned int client_timeout;     /* client times out the server, seconds */
    unsigned int server_timeout;     /* server times out the client, seconds */
    int remote_keepalives_enabled;           /* capability server-keepalives */
    int client_seqnum_enabled;                /* capability client-seqnum-v1 */
    unsigned int measurement_period;    /* base (desired) measurement period */
    const char *uptime_group;     /* availability group, e.g. IX.br location */
    const char *server_hostname;                          /* server hostname */
    const char *server_description;        /* server description, for humans */
    const char *s_cluster_hostname;      /* server-informed cluster hostname */
};

/* message handler, returns 0 if not handled, < 0 error, 1 if handled */
typedef int (* simet_inetup_msghandler)(struct simet_inetup_server * const s,
                                        const struct simet_inetup_msghdr * const hdr,
                                        const void * const data);
struct simet_inetup_msghandlers {
    uint32_t type;                      /* > 0xffff means EOL */
    simet_inetup_msghandler handler;    /* NULL means (possibly zero-copy) discard of payload */
};

#endif /* SIMET_INETUPTIME_H */
