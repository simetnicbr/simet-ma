/*
 * SIMET2 MA SIMET Spoofer client (sspooferc)
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

#ifndef SSPOOFC_H
#define SSPOOFC_H

#include <stdint.h>
#include <time.h>

#include <sys/socket.h>
#include <netinet/in.h>

#include <stdbool.h>

#include "tcpaq.h"

/* Control channel TCP defaults */
#define SSPOOFER_DEFAULT_PORT         "22002"
#define SSPOOFER_DEFAULT_CTRL_TIMEOUT 15 /* seconds */
#define SSPOOFER_DEFAULT_MSMT_TIMEOUT 15 /* seconds */
#define SSPOOFER_SHORTEST_TIMEOUT      5 /* seconds */
#define SSPOOFER_LONGEST_TIMEOUT      60 /* seconds */

/* SIMET spoofer protocol constants */
#define SSPOOF_P_MSGTYPE_CLOSE        0x0000U  /* disconnect *this* session */
#define SSPOOF_P_MSGTYPE_DISCONNECT   0x0001U  /* disconnect *all* sessions */
#define SSPOOF_P_MSGTYPE_CONNECT      0x0002U
#define SSPOOF_P_MSGTYPE_MACONFIG     0x0003U
#define SSPOOF_P_MSGTYPE_MSMTREQ      0x0004U  /* MP request measurement */
#define SSPOOF_P_MSGTYPE_MSMTSTART    0x0005U  /* MA acks measurement (will send packets) */
#define SSPOOF_P_MSGTYPE_MSMTDATA     0x0006U  /* MP echoes received MSMT packet data */
#define SSPOOF_P_MSGTYPE_MSMTFINISH   0x0007U  /* MA signals measurement finished (wait for more MSMREQ/DISCONNECT */
#define SIMET_ENGINE_NAME "nic_simet2_simet-ma"
#define SSPOOF_MSMT_DFL_TTL           64
#define SSPOOF_MSMT_DFL_PAYLOADSZ     128
#define SSPOOF_MSMT_MIN_PAYLOADSZ     128
#define SSPOOF_MSMT_MAX_PAYLOADSZ     4000

typedef union sockaddr_any_u {
    struct sockaddr sa;
    struct sockaddr_in sin;
    struct sockaddr_in6 sin6;
    struct sockaddr_storage ss;
} sockaddr_any_t_;

struct sspoof_ctrl_msghdr {
    /* network byte order in the wire */
    uint16_t message_type;
    uint32_t message_size;
    /* the message goes here */
} __attribute__((__packed__));

/* maximum payload size of a sspoof message */
#define SIMET_SSPOOF_MAXDATASIZE (SIMET_TCPAQ_QUEUESIZE - sizeof(struct sspoof_ctrl_msghdr))

/* sanity for agent-ids, currently they are UUIDs */
#define SIMET_AGENTID_MAX_LEN 40

/* SIMET spoofer protocol session id */
#define SSPOOF_MAX_SID_BIN_LEN 32 /* typically it will be 24 bytes or less */
struct sspoof_sid {
    const char *str;  /* C-string representation (base64url, no padding) */
    uint8_t len;      /* binary sid length */
    uint8_t sid[SSPOOF_MAX_SID_BIN_LEN];
};
typedef struct sspoof_sid sspoof_sid_t_;

/*
 * Measurements
 */

struct sspoof_msmt_results {
    const char *last_sentinel_snat_saddr;
    const char *last_probe_snat_saddr;
    const char *last_spoof_snat_saddr;
    unsigned int sentinel_rcvd_count;
    unsigned int probe_rcvd_count;
    unsigned int spoof_rcvd_count;
    bool sentinel_snat_seen;
    bool probe_snat_seen;
    bool spoof_snat_seen;
    bool sentinel_intact_seen;
    bool probe_intact_seen;
    bool spoof_intact_seen;
};

enum sspoof_msmt_type {
    SSPOOF_MSMT_T_UNDEF = 0,    /* Unused. Unintialized structure/EOL mark */
    SSPOOF_MSMT_T_PROBE,        /* Probe packet, no spoofing in place */
    SSPOOF_MSMT_T_SPOOFV1,      /* Source address spoofing, v1 */

    SSPOOF_MSMT_T_MAX
};

/* One measurement */
struct sspoof_msmt_req {
    enum sspoof_msmt_type type;

    int     pkt_group_count;    /* number of packet groups *left* to send */

    uint16_t dst_port;
    uint16_t payload_size;
    uint8_t ip_ttl;             /* 0 = default */
    uint8_t ip_traffic_class;

    /* intervals: minimum 10us, max 2s */
    unsigned int pkt_interval_us;   /* intra-group interval (one packet to the next) us */
    unsigned int grp_interval_us;   /* inter-group interval (one group to the next), us */

    /* SSPOOF_MSMT_T_SPOOFV1 */
    uint8_t  prefix_length;     /* IP network prefix length, host part will be random */
    uint64_t prefix;            /* IP4: use the lowest 32 bits. IP6: /64 */

    /* measurement loop */
    struct timespec ts_next_pkt; /* when we should send the next packet */
    int pkt_sent;                /* packets sent inside the current group */
    int grp_sent;                /* groups already sent */

    void *pkt;                  /* packet buffer cache */
};

/* One parallel batch of measurements */
#define SSPOOF_MSMT_MAX_BATCH 32
struct sspoof_msmt_ctx {
    struct sspoof_msmt_ctx *next;

    const char *measurement_id; /* measurement id */

    int active;                 /* NZ: ongoing measurement */
    int done;                   /* NZ: done, waiting cleanup */

    /* measurement requests */
    int msmt_req_count;               /* number of msmt itens in this msmt ctx */
    struct sspoof_msmt_req msmt_reqs[SSPOOF_MSMT_MAX_BATCH];

    /* measurement loop */
    struct timespec ts_start;   /* when we started this measurement */
    struct timespec ts_next;    /* min(msmt_reqs[*].ts_next) */

    int             udpsocket;         /* UDP socket */
    sockaddr_any_t_ udp_sa_local;
    socklen_t       udp_sa_local_len;

    /* measurement results */
    struct sspoof_msmt_results data;
};

/*
 * Control channel and state machine
 */

enum sspoof_protocol_state {
    SSPOOF_P_C_INIT = 0,        /* Initial setup, MUST be zero */
    SSPOOF_P_C_RECONNECT,       /* TCP (re)connection with backoff control */
    SSPOOF_P_C_CONNECT,         /* Loop over DNS results, TCP nonblock connect() */
    SSPOOF_P_C_CONNECTWAIT,     /* Wait TCP connect() reply */
    SSPOOF_P_C_CONNECTED,       /* TCP connected, sent CONNECT message */
    SSPOOF_P_C_WAITCONFIG,      /* wait for MA_CONFIG, go to mainloop */
    SSPOOF_P_C_MAINLOOP,        /* keepalive and events loop */
    SSPOOF_P_C_DISCONNECT,      /* send shutdown notification */
    SSPOOF_P_C_DISCONNECT_WAIT, /* wait for queue drain, force connection shutdown */
    SSPOOF_P_C_SHUTDOWN,        /* do nothing, terminal state */

    SSPOOF_P_C_MAX
};

struct sspoof_server_cluster {
    struct sspoof_server_cluster *next;
    const char * cluster_name;
    const char * cluster_port;
};
struct sspoof_server {
    struct tcpaq_conn conn;

    enum sspoof_protocol_state state;
    time_t keepalive_clock;
    time_t remote_keepalive_clock;
    time_t disconnect_clock;
    unsigned int backoff_level;
    time_t backoff_clock;
    time_t backoff_reset_clock;

    unsigned int connection_id;
    const struct sspoof_server_cluster *cluster;  /* not owned */

    /* state CONNECTING metadata */
    struct addrinfo *peer_gai;          /* result from getaddrinfo() */
    struct addrinfo *peer_ai;           /* current peers_gai member */

    /* server-issued session id */
    struct sspoof_sid sid;

    /* MSMT tracking */
    int rawsock;                        /* IPPROTO_RAW, valid post tcp connect() */
    struct sspoof_msmt_ctx *msmt_queue; /* FIFO, MSMTREQ, START */
    struct sspoof_msmt_ctx *msmt_done;  /* FIFO, MSMTFINISH */

    /* post connect() metadata, control connection */
    time_t connect_timestamp;
    sockaddr_any_t_ sa_peer;
    socklen_t       sa_peer_len;
    sockaddr_any_t_ sa_local;
    socklen_t       sa_local_len;
    sa_family_t peer_family;
    const char *peer_name;
    const char *peer_port;
    sa_family_t local_family;
    const char *local_name;
    const char *local_port;
    unsigned int peer_noconnect_ttl;

    /* server-configurable parameters */
    unsigned int ma_config_count;   /* 0 (not yet), 1 (once) or 2 (reconfig) */
    unsigned int control_timeout;        /* control channel timeout, seconds */
    unsigned int measurement_timeout;        /* measurement timeout, seconds */
    const char *server_hostname;                          /* server hostname */
    const char *server_description;        /* server description, for humans */
    const char *s_cluster_hostname;      /* server-informed cluster hostname */
};

/* msmtpkt.c */

#define SSPOOF_PKT_F_RAW       0x01   /* packet was sent through RAW socket */
#define SSPOOF_PKT_F_SRCSPOOF  0x02   /* packet source address was spoofed  */

#define SSPOOF_PKT_MAGIC       "SIMET BCP38 PKT"  /* 16 bytes, NUL-padded */

/* everything is network-byte-order */
struct sspoof_pkt_payload {
    uint64_t magic[2];      /* SSPOOF_PKT_MAGIC */

    uint8_t  version;    /* 1 */
    uint8_t  flags;      /* SSPOOF_PKT_F_* */
    uint16_t pad1;       /* padding */

    /* client data, server just echoes it back */
    uint32_t grp_number;
    uint32_t pkt_number;

    /* NAT detection */
    uint16_t ma_src_port;
    uint16_t pad2;      /* padding */
    uint8_t  ma_src_addr[16]; /* IPv4 or IPv6 address */

    /* session id, zero-padded */
    uint8_t sid_len;
    uint8_t pad3[2];    /* padding */
    uint8_t sid[SSPOOF_MAX_SID_BIN_LEN];
} __attribute__((__packed__));

long sspoof_msmt_txpkt(struct sspoof_server * const sctx, 
                       struct sspoof_msmt_ctx * const mctx,
                       struct sspoof_msmt_req * const mreq);

/* misc.c */

/* For control protocol and reporting purposes */
const char *str_ip46(int ai_family);

/* For user display purposes */
const char *str_ipv46(int ai_family);

/* resolve sa into *sa_f (string: *family), *hostname and *hostport) */
int sspoof_nameinfo(const sockaddr_any_t_ * const sa, /* input */
                    sa_family_t * const family,
                    const char ** const hostname, const char ** const hostport);

/* compatible with spoof_nameinfo() */
int sspoof_cmpnameinfo(const struct addrinfo * const ai,
                       const sa_family_t family, const char * const hostname);

/* inlines */

static inline void free_const(const void * const cp) __attribute__((__unused__));
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
static inline int xstrcmp(const char * const s1, const char * const s2) __attribute__((__unused__));
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

static uint16_t sockaddr_any_get_port_nbo(const sockaddr_any_t_ * const sa) __attribute__((__unused__));
static uint16_t sockaddr_any_get_port_nbo(const sockaddr_any_t_ * const sa)
{
    if (sa && sa->sa.sa_family == AF_INET)
        return sa->sin.sin_port;
    else if (sa && sa->sa.sa_family == AF_INET6)
        return sa->sin6.sin6_port;

    return 0;
}

#endif /* SSPOOFC_H */
/* vim: set et ts=8 sw=4 : */
