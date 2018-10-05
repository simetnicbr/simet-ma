#ifndef SIMET_INETUPTIME_H
#define SIMET_INETUPTIME_H

#include <unistd.h>
#include <inttypes.h>
#include <time.h>
#include <sys/socket.h>

/* SIMET2 Uptime2 protocol constants */
#define SIMET_INETUP_P_MSGTYPE_CONNECT    0x0000U
#define SIMET_INETUP_P_MSGTYPE_KEEPALIVE  0x0001U
#define SIMET_INETUP_P_MSGTYPE_EVENTS     0x0002U

enum simet_inetup_protocol_state {
    SIMET_INETUP_P_C_INIT = 0,		/* Initial setup, go to connect */
    SIMET_INETUP_P_C_RECONNECT,		/* TCP (re)connection with backoff control, go to refresh */
    SIMET_INETUP_P_C_REFRESH,		/* (re-)send full state, go to mainloop */
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

#define SIMET_INETUP_QUEUESIZE 8192U
struct simet_tcpqueue {
    char *buffer;
    size_t buffer_size;
    size_t rd_pos;
    size_t wr_pos_reserved;
    size_t wr_pos;
};

struct simet_inetup_server {
    struct simet_tcpqueue queue;

    int ai_family;
    int socket;

    enum simet_inetup_protocol_state state;
    time_t keepalive_clock;
    time_t disconnect_clock;
    unsigned int backoff_level;
    time_t backoff_clock;
    time_t backoff_reset_clock;

    unsigned int connection_id;

    /* post connect() metadata */
    sa_family_t peer_family;
    const char *peer_name;
    const char *peer_port;
    sa_family_t local_family;
    const char *local_name;
    const char *local_port;
};

#endif /* SIMET_INETUPTIME_H */
