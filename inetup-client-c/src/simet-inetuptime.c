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

#include "simet-inetuptime_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <limits.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <assert.h>

#include <fcntl.h>
#include <sys/poll.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include "netinet-tcp-compat.h"
#include <netdb.h>

#include <time.h>
#include <signal.h>

#include "simet-inetuptime.h"
#include "simet_err.h"
#include "logger.h"

#ifdef HAVE_JSON_JSON_H
#include <json/json.h>
#elif HAVE_JSON_C_JSON_H
#include <json-c/json.h>
#else
#include <json.h>
#endif

#include "sys-linux.h"

int  log_level = 2;
const char *progname = PACKAGE_NAME;

static struct simet_inetup_server **servers = NULL;
static struct simet_inetup_server *telemetry_server = NULL;
static const char *agent_id_file = NULL;
static const char *agent_id = NULL;
static const char *agent_token_file = NULL;
static const char *agent_token = NULL;
static const char *boot_id = NULL;
static const char *agent_mac = NULL;
static const char *task_name = NULL;
static const char *monitor_netdev_file = NULL;
static const char *monitor_netdev = NULL;

static unsigned int simet_uptime2_tcp_timeout = SIMET_UPTIME2_DEFAULT_TIMEOUT;

static time_t client_start_timestamp;
static time_t client_eventrec_start_timestamp;

static const int simet_uptime2_request_remotekeepalive = 1;

static volatile int got_exit_signal = 0;    /* SIGTERM, SIGQUIT */
static volatile int got_reload_signal = 0;  /* SIGHUP */

static int got_disconnect_msg = 0;          /* MSG_DISCONNECT */

#define BACKOFF_LEVEL_MAX 8
static const unsigned int backoff_times[BACKOFF_LEVEL_MAX] =
    { 1, 10, 10, 30, 30, 60, 60, 300 };

/* time we wait to flush queue to kernel before we drop it during disconnect */
#define SIMET_DISCONNECT_WAIT_TIMEOUT 5

/* maximum payload size of a Uptime2 message */
#define SIMET_UPTIME2_MAXDATASIZE (SIMET_INETUP_QUEUESIZE - sizeof(struct simet_inetup_msghdr))

/*
 * helpers
 */

/* lets not blind the type system just to squash a false-positive */
static inline void free_constchar(const char *p) { free((void *)p); }

static void simet_uptime2_reconnect(struct simet_inetup_server * const s);

static time_t timeout_to_keepalive(const time_t timeout) __attribute__((__pure__));
static time_t timeout_to_keepalive(const time_t timeout)
{
    time_t i = timeout / 2;
    if (i < SIMET_UPTIME2_SHORTEST_KEEPALIVE)
        i = SIMET_UPTIME2_SHORTEST_KEEPALIVE;
    else if (i > SIMET_UPTIME2_LONGEST_KEEPALIVE)
        i = SIMET_UPTIME2_LONGEST_KEEPALIVE;
    return i;
}

/*
 * events that can tolerate it, will oportunistically fire
 * if called up to timefuzz seconds before they are scheduled
 */
static time_t timeout_to_timefuzz(const time_t timeout) __attribute__((__pure__));
static time_t timeout_to_timefuzz(const time_t timeout)
{
    if (!timeout)
        return 0;
    time_t i = timeout / 20;
    return (i > 0) ? i : 1;
}

static time_t reltime(void)
{
    struct timespec now;

    if (!clock_gettime(CLOCK_MONOTONIC, &now)) {
        return (now.tv_sec > 0)? now.tv_sec : 0;  /* this helps the optimizer and squashes several warnings */
    } else {
        print_err("clock_gettime(CLOCK_MONOTONIC) failed!");
        /* FIXME: consider abort(EXIT_FAILURE) */
        return 0; /* kaboom! most likely :-( */
    }
}

/* returns: 0 = expired, otherwise seconds left to time out
 * written for clarity, and no integer overflows */
static time_t timer_check_full(const time_t timestamp, const time_t rel_timeout)
{
    if (timestamp <= 0 || rel_timeout <= 0)
        return 0; /* timer expired as fail-safe */
    const time_t now = reltime();
    if (now < timestamp)
        return 0; /* timer expired due to wrap or timestamp in the future */
    const time_t now_rel = now - timestamp;
    return (rel_timeout > now_rel)? rel_timeout - now_rel : 0;
}
/* same as timer_check, but saturates at INT_MAX */
static int timer_check(const time_t timestamp, const time_t rel_timeout)
{
    const time_t dt = timer_check_full(timestamp, rel_timeout);
    return (dt <= INT_MAX) ? (int) dt : INT_MAX;
}


/* For simet2 inetup protocol purposes */
static const char *str_ip46(int ai_family)
{
    switch (ai_family) {
        case AF_INET:
            return "ip4";
        case AF_INET6:
            return "ip6";
    }
    return "ip";
}

/* For user display purposes */
static const char *str_ipv46(int ai_family)
{
    switch (ai_family) {
        case AF_INET:
            return "IPv4";
        case AF_INET6:
            return "IPv6";
    }
    return "IP";
}

#define protocol_trace(protocol_stream, format, arg...) \
    do { \
        if (log_level >= MSG_TRACE) { \
            fflush(stdout); \
            fprintf(stderr, "%s: trace@%lds: %s(%u)@%lds: " format "\n", progname, \
                    (long int)reltime() - client_start_timestamp, \
                    str_ipv46(protocol_stream->ai_family), protocol_stream->connection_id, \
                    (protocol_stream->connect_timestamp) ? \
                        (long int)reltime() - protocol_stream->connect_timestamp : \
                        0, \
                    ## arg); \
        } \
    } while (0)

#define protocol_info(protocol_stream, format, arg...) \
    do { \
        if (log_level >= MSG_NORMAL) { \
            fflush(stdout); \
            fprintf(stderr, "%s: trace@%lds: %s(%u)@%lds: " format "\n", progname, \
                    (long int)reltime() - client_start_timestamp, \
                    str_ipv46(protocol_stream->ai_family), protocol_stream->connection_id, \
                    (protocol_stream->connect_timestamp) ? \
                        (long int)reltime() - protocol_stream->connect_timestamp : \
                        0, \
                    ## arg); \
        } \
    } while (0)

#if 0
static struct json_object * xx_json_object_new_in64_as_str(const int64_t v)
{
    char buf[32];
    snprintf(buf, sizeof(buf), "%" PRIi64, v);
    return json_object_new_string(buf);
}
#endif

static int fits_u64_i64(const uint64_t v64u, int64_t * const p64d)
{
    *p64d = v64u & INT64_MAX;
    return !!(v64u <= INT64_MAX);
}

/*
 * Signal handling
 */

static void handle_exitsig(const int sig)
{
    got_exit_signal = sig;
}

static void handle_reloadsig(const int sig)
{
    got_reload_signal = sig;
}

static void init_signals(void)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = &handle_exitsig;

    if (sigaction(SIGQUIT, &sa, NULL) || sigaction(SIGTERM, &sa, NULL))
        print_warn("failed to set signal handlers, precision during restarts will suffer");

    sa.sa_handler = &handle_reloadsig;
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGHUP, &sa, NULL))
        print_warn("failed to set SIGHUP handler");
}


/*
 * TCP async queueing
 *
 * 1. reserve space in the local queue, if not available, try again later (so that
 *    we can be message-atomic at the higher level)
 * 2. commit message to the local queue, we can now return success no matter what.
 * 3. attempt to send() to kernel buffer immediately and return even if nothing or
 *    partial send.  Whatever is left will get sent async by calls to
 *    tcpaq_send_nowait() -- which we call in the program main loop.
 *
 * 1. zero-copy discard of received data available
 * 2. only read from socket buffer when ready to consume something
 * 3. do nothing if the entire object is not available yet
 *    (objects are limited to the queue buffer size)
 */

static void tcpaq_close(struct simet_inetup_server * const s)
{
    assert(s);
    if (s->socket != -1) {
        shutdown(s->socket, SHUT_RDWR);
        close(s->socket);
        s->socket = -1;
    }
    s->out_queue.rd_pos = 0;
    s->out_queue.wr_pos = s->out_queue.wr_pos_reserved = 0;
    s->in_queue.rd_pos = 0;
    s->in_queue.wr_pos = s->in_queue.wr_pos_reserved = 0;
}

static int tcpaq_reserve(struct simet_inetup_server * const s, size_t size)
{
    assert(s);

    /* paranoia */
    if (s->out_queue.wr_pos > s->out_queue.wr_pos_reserved)
        s->out_queue.wr_pos_reserved = s->out_queue.wr_pos;

    if (s->out_queue.wr_pos_reserved + size >= s->out_queue.buffer_size)
        return -ENOSPC;

    s->out_queue.wr_pos_reserved += size;
    return 0;
}

/* can unreserve *and* also unqueue unsent data */
static int tcpaq_unreserve(struct simet_inetup_server * const s, size_t size)
{
    assert(s);

    /* paranoia */
    if (s->out_queue.wr_pos > s->out_queue.wr_pos_reserved)
        s->out_queue.wr_pos_reserved = s->out_queue.wr_pos;

    if (s->out_queue.rd_pos + size <= s->out_queue.wr_pos_reserved) {
        s->out_queue.wr_pos_reserved -= size;
        if (s->out_queue.wr_pos_reserved > s->out_queue.wr_pos)
            s->out_queue.wr_pos = s->out_queue.wr_pos_reserved; /* discard unsent */
    } else {
        return -EINVAL;
    }

    return 0;
}

/**
 * tcpaq_queue: queue a message for transmisson, does *not* flush
 *
 * @reserved: true if tcpaq_reserve() already done for this message
 *
 * returns: 0, -ENOSPC...
 */
static int tcpaq_queue(struct simet_inetup_server * const s, void *data, size_t size, int reserved)
{
    assert(s && s->out_queue.buffer);

    if (!size)
        return 0;
    if (!reserved && tcpaq_reserve(s, size))
        return -ENOSPC;
    if (s->out_queue.wr_pos + size >= s->out_queue.buffer_size)
        return -ENOSPC; /* defang the bug */

    memcpy(&s->out_queue.buffer[s->out_queue.wr_pos], data, size);
    s->out_queue.wr_pos += size;

    if (s->out_queue.wr_pos > s->out_queue.wr_pos_reserved) {
        print_warn("internal error: stream %u went past reservation, coping with it", s->connection_id);
        s->out_queue.wr_pos_reserved = s->out_queue.wr_pos;
    }

    return 0;
}

static int tcpaq_is_out_queue_empty(struct simet_inetup_server * const s)
{
    /* do it in a fail-safe manner against queue accounting bugs */
    return (s->out_queue.rd_pos >= s->out_queue.wr_pos || s->out_queue.rd_pos >= s->out_queue.buffer_size);
}

static void xx_tcpaq_compact(struct simet_inetup_server * const s)
{
    /* FIXME: also compact partially transmitted using a watermark */
    if (s->out_queue.rd_pos >= s->out_queue.wr_pos) {
        if (s->out_queue.wr_pos_reserved > s->out_queue.rd_pos) {
            s->out_queue.wr_pos_reserved -= s->out_queue.rd_pos;
        } else {
            s->out_queue.wr_pos_reserved = 0;
        }
        s->out_queue.wr_pos = 0;
        s->out_queue.rd_pos = 0;
    }
}

static int tcpaq_send_nowait(struct simet_inetup_server * const s)
{
    size_t  send_sz;
    ssize_t sent;

    assert(s && s->out_queue.buffer);

    if (s->socket == -1)
        return -ENOTCONN;
    if (s->out_queue.wr_pos == 0)
        return 0;
    if (tcpaq_is_out_queue_empty(s)) {
        xx_tcpaq_compact(s);
        return 0;
    }

    send_sz = s->out_queue.wr_pos - s->out_queue.rd_pos;
    sent = send(s->socket, &s->out_queue.buffer[s->out_queue.rd_pos], send_sz, MSG_DONTWAIT | MSG_NOSIGNAL);
    if (sent < 0) {
        int err = errno;
        if (err == EAGAIN || err == EWOULDBLOCK || err == EINTR)
            return 0;
        protocol_trace(s, "send() error: %s", strerror(err));
        return -err;
    }
    s->out_queue.rd_pos += sent;

#if 0
    /* commented out - we can tolerate 200ms extra delay from Naggle just fine,
     * and we already asked for TCP_NODELAY after connect() */

    const int zero = 0;
    const int one = 1;
    /* Ask kernel to flush buffer every time our local queue is empty */
    if (s->out_queue.wr_pos <= s->out_queue.rd_pos) {
        setsockopt(s->socket, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        setsockopt(s->socket, IPPROTO_TCP, TCP_NODELAY, &zero, sizeof(zero));
    }
#endif
    /* protocol_trace(s, "send() %zd out of %zu bytes", sent, send_sz); */

    xx_tcpaq_compact(s);
    return 0;
}

#if 0
/* Tries hard to flush queue, but only up to timeout seconds */
static int tcpaq_send_timeout(struct simet_inetup_server * const s, time_t timeout)
{
    const time_t tstart = reltime();
    int rc = -EAGAIN;

    while (rc && !tcpaq_is_queue_empty(s) && timer_check_full(tstart, timeout)) {
        rc = tcpaq_send_nowait(s);
    }

    return rc;
}
#endif

/* you'd better remember about wr_pos_reserved..., so xx_ */
static int xx_tcpaq_is_in_queue_empty(struct simet_inetup_server * const s)
{
    /* do it in a fail-safe manner against queue accounting bugs */
    return (s->in_queue.rd_pos >= s->in_queue.wr_pos || s->in_queue.rd_pos >= s->in_queue.buffer_size);
}

/* discards all pending receive data, returns 0 for nothing discarded, NZ for something, <0 error */
static int tcpaq_drain(struct simet_inetup_server * const s)
{
    size_t remaining = 0;
    int res = 0;

    assert(s);

    if (s->in_queue.rd_pos < s->in_queue.wr_pos)
        remaining = s->in_queue.wr_pos - s->in_queue.rd_pos;
    s->in_queue.rd_pos = s->in_queue.wr_pos = s->in_queue.wr_pos_reserved = 0;

    if (s->socket != -1) {
        do {
            res = recv(s->socket, NULL, SSIZE_MAX, MSG_DONTWAIT | MSG_TRUNC);
        } while (res == -1 && errno == EINTR);
        if (res == -1) {
            int err = errno;
            if (err == EAGAIN || err == EWOULDBLOCK)
                return 0;
            protocol_trace(s, "tcpaq_drain: recv() error: %s", strerror(err));
            return -err;
        }
    }
    return (remaining > 0 || res > 0);
}

/* discards object, <0 error; 0 : still need to receive more data; NZ: discarded */
static int tcpaq_discard(struct simet_inetup_server * const s, size_t object_size)
{
    assert(s);

    object_size += s->in_queue.wr_pos_reserved;
    s->in_queue.wr_pos_reserved = 0;

    /* discard from unread buffer */
    size_t unread_bufsz = 0;
    if (s->in_queue.wr_pos > s->in_queue.rd_pos)
        unread_bufsz = s->in_queue.wr_pos - s->in_queue.rd_pos;
    if (unread_bufsz >= object_size) {
        s->in_queue.rd_pos += object_size;
        if (xx_tcpaq_is_in_queue_empty(s))
            s->in_queue.rd_pos = s->in_queue.wr_pos = 0; /* compress */
        return 1;
    }

    /* discard buffer */
    s->in_queue.rd_pos = s->in_queue.wr_pos = 0;
    s->in_queue.wr_pos_reserved = object_size - unread_bufsz;

    /* try to discard wr_pos_reserved bytes from socket buffer */
    if (s->socket != -1) {
        int res;

        do {
            res = recv(s->socket, NULL, s->in_queue.wr_pos_reserved,
                       MSG_DONTWAIT | MSG_TRUNC);
        } while (res == -1 && errno == EINTR);
        if (res == -1) {
            int err = errno;
            if (err == EAGAIN || err == EWOULDBLOCK)
                return 0;
            protocol_trace(s, "tcpaq_discard: recv() error: %s", strerror(err));
            return -err;
        }
        s->in_queue.wr_pos_reserved -= res; /* recv() ensures 0 < res <= wr_pos_reserved */
    }

    return (s->in_queue.wr_pos_reserved == 0);
}

/* < 0: error, 0: need to receive more data; > 0: object ready for tcpaq_receive() */
static int tcpaq_request_receive_nowait(struct simet_inetup_server * const s, size_t object_size)
{
    int res;

    assert(s && s->in_queue.buffer);

    /* skip any cruft we are still discarding */
    res = tcpaq_discard(s, 0);
    if (res <= 0)
        return res;

    /* note: tcpaq_discard() > 0 ensures s->in_queue.wr_pos_reserved = 0 */

    if (object_size > SIMET_INETUP_QUEUESIZE)
        return -EFAULT; /* we can't do it */

    size_t unread_bufsz = 0;
    if (s->in_queue.wr_pos > s->in_queue.rd_pos)
        unread_bufsz = s->in_queue.wr_pos - s->in_queue.rd_pos;

    if (unread_bufsz >= object_size)
        return 1; /* we have enough buffered data */

    object_size -= unread_bufsz;
    if (s->in_queue.wr_pos + object_size > SIMET_INETUP_QUEUESIZE) {
        /* compress buffer */
        memmove(s->in_queue.buffer, s->in_queue.buffer + s->in_queue.rd_pos, unread_bufsz);
        s->in_queue.wr_pos = unread_bufsz;
        s->in_queue.rd_pos = 0;
    }

    /* paranoia, must not happen */
    if (s->in_queue.wr_pos + object_size > SIMET_INETUP_QUEUESIZE)
        return -EFAULT;

    do {
        res = recv(s->socket, s->in_queue.buffer + s->in_queue.wr_pos, object_size, MSG_DONTWAIT);
    } while (res == -1 && errno == EINTR);
    if (res == -1) {
        int err = errno;
        if (err == EAGAIN || err == EWOULDBLOCK)
            return 0;
        protocol_trace(s, "tcpaq_request: recv() error: %s", strerror(err));
        return -err;
    }
    s->in_queue.wr_pos += res; /* recv() ensures 0 <= res <= wr_pos */
    object_size -= res;  /* recv() ensures 0 <= res <= wr_pos */

    return (object_size == 0);
}

/**
 * tcpaq_receive_nowait() - receive an exactly-sized object
 *
 * Size is limited to SIMET_INETUP_QUEUESIZE.  Does not wait,
 * returns 0 if there is not enough received buffer yet.  If
 * buf is NULL, discards the data.
 *
 * Returns:
 *   < 0: -errno
 *   0  : not enough data buffered
 *   NZ : requested object is in *buf
 */
static int tcpaq_receive_nowait(struct simet_inetup_server * const s, size_t object_size, void *buf) __attribute__((__unused__));
static int tcpaq_receive_nowait(struct simet_inetup_server * const s, size_t object_size, void *buf)
{
    if (!buf)
        return tcpaq_discard(s, object_size);

    int res = tcpaq_request_receive_nowait(s, object_size);
    if (res <= 0)
        return res;

    memcpy(buf, s->in_queue.buffer + s->in_queue.rd_pos, object_size);
    s->in_queue.rd_pos += object_size;

    if (xx_tcpaq_is_in_queue_empty(s))
        s->in_queue.wr_pos = s->in_queue.rd_pos = 0;

    return 1;
}

/**
 * tcpaq_peek_nowait() - receve in-queue and peek at an object
 *
 * Size is limited to SIMET_INETUP_QUEUESIZE.  Does not wait,
 * returns 0 if there is not enough received buffer yet.  If
 * pbuf is not NULL, it will be set to either NULL or to the
 * (const char *) internal buffer (do NOT modify or free()).
 *
 * Does not advance the read pointer, so a tcpaq_receive()
 * will get the same data, use tcpaq_receive with a NULL buffer
 * (or tcpaq_discard() directly) to "skip" the peeked object.
 *
 * Returns:
 *   < 0: -errno
 *   0  : not enough data buffered
 *   NZ : pointer to requested object is in *buf,
 *        do not modify the contents!  valid until the
 *        next call to tcpaq_* on the same "server"
 */
static int tcpaq_peek_nowait(struct simet_inetup_server * const s, size_t object_size, const char **pbuf)
{
    int res = tcpaq_request_receive_nowait(s, object_size);
    if (pbuf)
        *pbuf = (res > 0) ? s->in_queue.buffer + s->in_queue.rd_pos : NULL;
    return res;
}

/*
 * SIMET2 Uptime2 protocol helpers
 */

static void xx_set_tcp_timeouts(struct simet_inetup_server * const s)
{
    /* The use of SO_SNDTIMEO for blocking connect() timeout is not
     * mandated by POSIX and it is implemented only in [non-ancient]
     * Linux */
    const struct timeval so_timeout = {
        .tv_sec = s->client_timeout,
        .tv_usec = 0,
    };
    if (setsockopt(s->socket, SOL_SOCKET, SO_SNDTIMEO, &so_timeout, sizeof(so_timeout)) ||
        setsockopt(s->socket, SOL_SOCKET, SO_RCVTIMEO, &so_timeout, sizeof(so_timeout))) {
        protocol_trace(s, "failed to set socket timeouts using SO_*TIMEO");
    }

    /*
     * RFC-0793/RFC-5482 user timeout.
     *
     * WARNING: Linux had for a *very* long time an innacurate
     * implementation of TCP_USER_TIMEOUT, as per comments in merge
     * commit d1afdc51399c53791ad9affbef67ba3aa206c379 (Merge branch
     * 'tcp-improve-setsockopt-TCP_USER_TIMEOUT-accuracy').
     *
     * "The issue is that in order for the timeout to occur, the
     * retransmit timer needs to fire again.  If the user timeout check
     * happens after the 9th retransmit for example, it needs to wait
     * for the 10th retransmit timer to fire in order to evaluate
     * whether a timeout has occurred or not.  If the interval is large
     * enough then the timeout will be very inaccurate."
     *
     * Fixed in: Linux v4.19
     */
    const unsigned int ui = (unsigned int)s->client_timeout * 1000U;
    if (setsockopt(s->socket, IPPROTO_TCP, TCP_USER_TIMEOUT, &ui, sizeof(unsigned int))) {
        print_warn("failed to enable TCP timeouts, measurement error will increase");
    }

#if 0
    /* RFC-1122 TCP keep-alives as a fallback for timeouts.
     *
     * Cheap bug defense against application-layer keepalive messages not being sent, but otherwise
     * useless as the kernel resets the TCP Keep-Alive timers on socket send().
     *
     * Linux seems to do the expected with this one, and timeout at
     * KEEPIDLE + KEEPINTVL * KEEPCNT.
     *
     * Note: we don't account for KEEPIDLE in the code below
     */
    const int tcp_keepcnt = 3;
    int tcp_keepintvl = simet_uptime2_tcp_timeout / tcp_keepcnt;
    if (tcp_keepintvl < 5)
        tcp_keepintvl = 5;
    int tcp_keepidle = simet_uptime2_tcp_timeout / tcp_keepcnt;
    if (tcp_keepidle < 5)
        tcp_keepidle = 5;
    if (setsockopt(s->socket, IPPROTO_TCP, TCP_KEEPCNT, &tcp_keepcnt, sizeof(int)) ||
        setsockopt(s->socket, IPPROTO_TCP, TCP_KEEPIDLE, &tcp_keepidle, sizeof(int)) ||
        setsockopt(s->socket, IPPROTO_TCP, TCP_KEEPINTVL, &tcp_keepintvl, sizeof(int)) ||
        setsockopt(s->socket, SOL_SOCKET, SO_KEEPALIVE, &int_one, sizeof(int_one))) {
        print_warn("failed to enable TCP Keep-Alives, measurement error might increase");
    } else {
        protocol_trace(s, "RFC-1122 TCP Keep-Alives enabled, idle=%ds, intvl=%ds, count=%d", tcp_keepidle, tcp_keepintvl, tcp_keepcnt);
    }
#endif
}

static int xx_simet_uptime2_sndmsg(struct simet_inetup_server * const s,
                               const uint16_t msgtype, const size_t msgsize,
                               const char * const msgdata)
{
    struct simet_inetup_msghdr hdr;

    if (msgsize > SIMET_UPTIME2_MAXDATASIZE) {
        protocol_info(s, "internal error: tried to send too large a message, discarded it instead");
        return 0; /* or abort the program, which would be worse */
    }

    size_t reserve_sz = msgsize + sizeof(hdr);
    if (tcpaq_reserve(s, reserve_sz))
        return -EAGAIN; /* can't send right now */

    memset(&hdr, 0, sizeof(hdr));
    hdr.message_type = htons(msgtype);
    hdr.message_size = htonl(msgsize); /* safe, < SIMET_UPTIME2_MAXDATASIZE */

    if (tcpaq_queue(s, &hdr, sizeof(hdr), 1) || tcpaq_queue(s, (void *)msgdata, msgsize, 1)) {
        /* should not happen, but if it does, try to recover */
        if (tcpaq_unreserve(s, reserve_sz))
            return -EINVAL; /* internal error?! */
        return -EAGAIN;
    }

    return tcpaq_send_nowait(s);
}

/* update remote keepalive timer, we can do that every time we hear from remote */
static void simet_uptime2_remotekeepalive_update(struct simet_inetup_server * const s)
{
    s->remote_keepalive_clock = reltime();
}

static int uptimeserver_drain(struct simet_inetup_server * const s)
{
    int res = tcpaq_drain(s);
    if (res > 0) {
            /* we did discard something, so remote is alive */
            protocol_trace(s, "drain: remote watchdog updated");
            simet_uptime2_remotekeepalive_update(s);
            return 0;
    }
    return res;
}

#define SIMET_INETUP_MSGHANDLER_EOL 0xffffffff

/* 0: did nothing; < 0 : error */
static int simet_uptime2_recvmsg(struct simet_inetup_server * const s,
                const struct simet_inetup_msghandlers *handlers)
{
    struct simet_inetup_msghdr hdr;
    const char *data = NULL;
    int res;

    /* we do some dances to reduce buffer copying, and to avoid give backs */
    res = tcpaq_peek_nowait(s, sizeof(hdr), &data);
    if (res <= 0 || !data)
        return res;
    hdr.message_type = ntohs(((struct simet_inetup_msghdr *)data)->message_type);
    hdr.message_size = ntohl(((struct simet_inetup_msghdr *)data)->message_size);

    /* messages larger than 64KiB are illegal and must cause a connection drop */
    if (hdr.message_size > 65535) {
        protocol_info(s, "recvmsg: message too large (%u bytes), sync might have been lost",
                (unsigned int) hdr.message_size);
        return -EFAULT;
    }

    protocol_trace(s, "recvmsg: remote watchdog updated");
    simet_uptime2_remotekeepalive_update(s);

    /* either tcpaq_discard the whole thing, or tcpaq_peek hdr and data */
    int processed = 0;
    if (handlers && hdr.message_size <= SIMET_UPTIME2_MAXDATASIZE) {
        while (handlers->type != hdr.message_type && !(handlers->type & 0xffff0000U))
            handlers++;
        if (handlers->type == hdr.message_type) {
            if (handlers->handler) {
                /* single-threaded, so we can peek to avoid an extra copy... */
                res = tcpaq_peek_nowait(s, hdr.message_size + sizeof(hdr), &data);
                if (res > 0 && data)
                    res = (* handlers->handler)(s, &hdr, data + sizeof(hdr));
                if (tcpaq_discard(s, hdr.message_size + sizeof(hdr)) <= 0)
                    protocol_trace(s, "recvmsg: unexpected result for discard-after-peek");
            } else {
                /* silent discard the whole thing */
                res = tcpaq_discard(s, hdr.message_size + sizeof(hdr));
            }
            if (res < 0) {
                protocol_trace(s, "error processing message type 0x%04x, size %" PRIu32 ": %s",
                        (unsigned int) hdr.message_type, hdr.message_size,
                        strerror(-res));
                return res;
            }
            processed = 1;
        }
    }
    if (!processed) {
        /* unexpected discard */
        res = tcpaq_discard(s, hdr.message_size + sizeof(hdr));
        if (res < 0)
            return res;
        protocol_trace(s, "%s message with type 0x%04x and size %" PRIu32,
                       (res) ? "discarded" : "will discard",
                       (unsigned int) hdr.message_type, hdr.message_size);
    }
    return res;
}

static int uptimeserver_flush(struct simet_inetup_server * const s)
{
    if (s && s->out_queue.buffer && s->socket != -1 && s->state != SIMET_INETUP_P_C_SHUTDOWN)
        return tcpaq_send_nowait(s);

    return 0;
}

/* update keepalive timer every time we send a message of any time */
static void simet_uptime2_keepalive_update(struct simet_inetup_server * const s)
{
   s->keepalive_clock = reltime();
}

static int xx_simet_uptime2_sndevent(struct simet_inetup_server * const s,
                                     const time_t when, const char * const name)
{
    json_object *jroot;
    json_object *jarray;
    json_object *jo;
    int rc = -ENOMEM;

    protocol_trace(s, "sending %s event", name);

    jo = json_object_new_object();
    jroot = json_object_new_object();
    jarray = json_object_new_array();
    if (!jroot || !jarray || !jo)
        goto err_exit;

    json_object_object_add(jo, "name", json_object_new_string(name));
    json_object_object_add(jo, "timestamp-seconds", json_object_new_int64(when));

    if (json_object_array_add(jarray, jo))
        goto err_exit;
    jo = NULL;

    json_object_object_add(jroot, "events", jarray);
    jarray = NULL;

    const char *jsonstr = json_object_to_json_string(jroot);
    if (jsonstr) {
        /* protocol_trace(s, "ma_event message: %s", jsonstr); */
        rc = xx_simet_uptime2_sndmsg(s, SIMET_INETUP_P_MSGTYPE_EVENTS, strlen(jsonstr), jsonstr);
        if (!rc)
            simet_uptime2_keepalive_update(s);
    } else {
        rc = -EFAULT;
    }

    /* free(jsonstr); -- not! it is managed by json-c */

err_exit:
    json_object_put(jo);
    json_object_put(jarray);
    json_object_put(jroot);

    return rc;
}

/*
 * SIMET2 Uptime2 client message processing
 */

static int xx_maconfig_getuint(struct simet_inetup_server * const s,
                        struct json_object * const jconf,
                        const char * const param_name,
                        unsigned int * const param,
                        const unsigned int low, const unsigned int high)
{
    struct json_object *jo;

    if (json_object_object_get_ex(jconf, param_name, &jo)) {
        if (json_object_is_type(jo, json_type_int)) {
            errno = 0;
            int64_t val = json_object_get_int64(jo);
            if (errno == 0 && val >= low && val <= high) {
                const unsigned int uival = (unsigned int)val; /* safe: 0 <= low <= val <= high <= UINT_MAX */
                if (*param != uival) {
                    *param = uival;
                    protocol_info(s, "ma_config: set %s to %u", param_name, *param);
                }
                return 1;
            }
        }
        protocol_trace(s, "ma_config: invalid %s: %s",
                      param_name, json_object_to_json_string(jo));
        return -EINVAL;
    }

    return 0;
}

/*
 * MA_CONFIG message:
 *
 * { "config": {
 *   "capabilities-enabled": [ "..." ]
 *   "client-timeout": 60
 *   "server-timeout": 60
 *    } }
 *
 * all fields optional.  fields completely override previous settings.
 * implementation detail: we ignore trailing crap to avoid json-c internals
 */
static int simet_uptime2_msghdl_maconfig(struct simet_inetup_server * const s,
                    const struct simet_inetup_msghdr * const hdr,
                    const void * const data)
{
    struct json_tokener *jtok;
    struct json_object *jroot = NULL;
    struct json_object *jconf, *jo;
    int res = 2;

    if (hdr->message_size < 2) {
        protocol_trace(s, "ma_config: ignoring small message");
        return 1;
    }

    protocol_trace(s, "ma_config: processing message: %.*s",
            (int) hdr->message_size, (const char *)data);

    jtok = json_tokener_new();
    if (!jtok)
        return -ENOMEM;

    jroot = json_tokener_parse_ex(jtok, data, hdr->message_size); /* 2 <= message_size <= 8192 verified */
    if (!json_object_object_get_ex(jroot, "config", &jconf))
        goto err_exit;
    if (!json_object_is_type(jconf, json_type_object))
        goto err_exit;

    if (json_object_object_get_ex(jconf, "capabilities-enabled", &jo)) {
        int al;

        /* check syntax before we reset any capabilities */
        if (!json_object_is_type(jo, json_type_array))
            goto err_exit;
        al = json_object_array_length(jo);
        while (--al >= 0) {
            if (!json_object_is_type(json_object_array_get_idx(jo, al), json_type_string))
                goto err_exit;
        }

        /* reset all capabilities */
        s->remote_keepalives_enabled = 0;

        /* set any capabilities we know about, warn of others */
        al = json_object_array_length(jo);
        while (--al >= 0) {
            const char *cap = json_object_get_string(json_object_array_get_idx(jo, al));
            if (!strcasecmp("server-keepalive", cap)) {
                /* this one we should enable even if we did not request it */
                s->remote_keepalives_enabled = 1;
            /* else if (!strcasecmp("other key", cap)) ... */
            } else {
                protocol_trace(s, "ma_config: ignoring capability %s", cap ? cap : "(empty)");
            }
        }
    }

    if (xx_maconfig_getuint(s, jconf, "client-timeout-seconds", &s->client_timeout, 0, 86400) > 0)
        xx_set_tcp_timeouts(s);
    xx_maconfig_getuint(s, jconf, "server-timeout-seconds", &s->server_timeout, 0, 86400);

    res = 1;

err_exit:
    if (json_tokener_get_error(jtok) != json_tokener_success) {
        protocol_trace(s, "ma_config: ignoring invalid message: %s",
                      json_tokener_error_desc(json_tokener_get_error(jtok)));
    } else if (res > 1) {
        protocol_trace(s, "ma_config: received malformed message");
    }
    json_tokener_free(jtok);
    if (jroot)
        json_object_put(jroot);
    return res;
}

/*
 * EVENTS message:
 *
 * { "events": [ { "name": "<event>", "timestamp-seconds": <event timestamp> }, ... ] }
 *
 */
static int simet_uptime2_msghdl_serverevents(struct simet_inetup_server * const s,
                    const struct simet_inetup_msghdr * const hdr,
                    const void * const data)
{
    struct json_tokener *jtok;
    struct json_object *jroot = NULL;
    struct json_object *jevents, *jev, *jo, *jt;
    int res = 2;
    int al, i;

    if (hdr->message_size < 13) {
        protocol_trace(s, "events: ignoring small message");
        return 1;
    }

    protocol_trace(s, "events: processing message: %.*s",
            (int) hdr->message_size, (const char *)data);

    jtok = json_tokener_new();
    if (!jtok)
        return -ENOMEM;

    jroot = json_tokener_parse_ex(jtok, data, hdr->message_size); /* 13 <= message_size <= 8192 verified */
    if (!json_object_object_get_ex(jroot, "events", &jevents))
        goto err_exit;
    if (!json_object_is_type(jevents, json_type_array))
        goto err_exit;
    al = json_object_array_length(jevents);
    for (i = 0; i < al; i++) {
        jev = json_object_array_get_idx(jevents, i);
        if (!json_object_is_type(jev, json_type_object) ||
            !json_object_object_get_ex(jev, "name", &jo) ||
            !json_object_object_get_ex(jev, "timestamp-seconds", &jt) ||
            !json_object_is_type(jo, json_type_string) ||
            !json_object_is_type(jt, json_type_int))
            goto err_exit;

        const char *event_name = json_object_get_string(jo);
        if (!event_name)
            goto err_exit;
        protocol_trace(s, "events: received server event \"%s\"", event_name);

        /* handle events */
        if (!strcmp(event_name, "mp_disconnect")) {
            /* server told us to disconnect, and not reconnect back for a while */
            protocol_info(s, "server closing connection... trying to change servers");
            s->peer_noconnect_ttl = SIMET_UPTIME2_DISCONNECT_BACKOFF;
            simet_uptime2_reconnect(s);
            /* no further event processing after this */
            /* FIXME: queue a "we got a server disconnect event" event for next connection */
            break;
        } /* else if (!strcmp(... */
    }

    res = 1;

err_exit:
    if (json_tokener_get_error(jtok) != json_tokener_success) {
        protocol_info(s, "events: ignoring invalid message: %s",
                      json_tokener_error_desc(json_tokener_get_error(jtok)));
    } else if (res > 1) {
        protocol_info(s, "events: received malformed message");
    }
    json_tokener_free(jtok);
    if (jroot)
        json_object_put(jroot);
    return res;
}

static int simet_uptime2_msghdl_serverdisconnect(struct simet_inetup_server * const s,
                    const struct simet_inetup_msghdr * const hdr,
                    const void * const data)
{
    protocol_info(s, "received global disconnection message from server");
    got_disconnect_msg = 1;
    return 1;
}

/* State: MAINLOOP */
const struct simet_inetup_msghandlers simet_uptime2_messages_mainloop[] = {
    { .type = SIMET_INETUP_P_MSGTYPE_KEEPALIVE,   .handler = NULL },
    { .type = SIMET_INETUP_P_MSGTYPE_MACONFIG,    .handler = &simet_uptime2_msghdl_maconfig },
    { .type = SIMET_INETUP_P_MSGTYPE_EVENTS,      .handler = &simet_uptime2_msghdl_serverevents },
    { .type = SIMET_INETUP_P_MSGTYPE_DISCONNECT,  .handler = &simet_uptime2_msghdl_serverdisconnect },
    { .type = SIMET_INETUP_P_MSGTYPE_MEASUREMENT, .handler = NULL },
    { .type = SIMET_INETUP_MSGHANDLER_EOL }
};

/*
 * SIMET2 Uptime2 general messages
 *
 * Returns: 0 or -errno
 */

static int simet_uptime2_msg_clientlifetime(struct simet_inetup_server * const s, int is_start)
{
    /* FIXME: ma_clientstart/stop actually tracks event recording,
     * we need to update/change this code when we implement event recording */
    if (is_start && !client_eventrec_start_timestamp) {
        client_eventrec_start_timestamp = reltime();
    } else if (!is_start) {
        client_eventrec_start_timestamp = 0;
    }

    return xx_simet_uptime2_sndevent(s, (is_start)? client_eventrec_start_timestamp : reltime(),
                                        (is_start)? "ma_clientstart" : "ma_clientstop");
}

static int simet_uptime2_msg_link(struct simet_inetup_server * const s, int link_is_up)
{
    return xx_simet_uptime2_sndevent(s, reltime(), (link_is_up)? "ma_link" : "ma_nolink");
}

static int simet_uptime2_msg_keepalive(struct simet_inetup_server * const s)
{
    protocol_trace(s, "sending ma_keepalive event");
    return xx_simet_uptime2_sndmsg(s, SIMET_INETUP_P_MSGTYPE_KEEPALIVE, 0, NULL);
}

static int simet_uptime2_msg_maconnect(struct simet_inetup_server * const s)
{
    json_object *jo = NULL;
    json_object *jcap = NULL;
    int rc = -ENOMEM;

    assert(s);

    protocol_trace(s, "sending ma_connect event");

    jo = json_object_new_object();
    jcap = json_object_new_array();
    if (!jo || !jcap) {
        free(jo);
        free(jcap);
        return -ENOMEM;
    }

    /*
     * Protocol v1: no capabilities field
     *    - client->server unidirectional channel
     *    - server must not send any data to client
     *
     * Protocol v2: bidirectional channel
     *    - capabilities support on CONNECT message
     *    - client drains return channel (server->client)
     *    - client ignores unknown messages
     *    - client accepts MA_CONFIG message from server
     *
     * Protocol v2: msg-disconnect capability
     *    - client accepts MSG_DISCONNECT (global disconnect)
     *      Disconnects (cleanly) from all servers, all protocols
     *      Switches immediately to worst-case backoff timer
     *      Tries to reconnect at worst-case backoff
     *      Continues measuring/collecting events (where supported)
     */
    if (simet_uptime2_request_remotekeepalive) {
        json_object_array_add(jcap, json_object_new_string("server-keepalive"));
    }
    json_object_array_add(jcap, json_object_new_string("msg-disconnect"));
    json_object_object_add(jo, "capabilities", jcap);
    jcap = NULL;

    if (agent_id)
        json_object_object_add(jo, "agent-id", json_object_new_string(agent_id));
    if (agent_token)
        json_object_object_add(jo, "agent-token", json_object_new_string(agent_token));
    if (boot_id)
        json_object_object_add(jo, "boot-id", json_object_new_string(boot_id));

    if (s->local_family != AF_UNSPEC || s->peer_family != AF_UNSPEC) {
        json_object *jconn = json_object_new_object();
        if (!jconn)
            goto err_exit;

        if (s->local_family != AF_UNSPEC) {
            json_object_object_add(jconn, "local-address-family", json_object_new_string(str_ip46(s->local_family)));
            json_object_object_add(jconn, "local-address", json_object_new_string(s->local_name));
            json_object_object_add(jconn, "local-port", json_object_new_string(s->local_port));
        }
        if (s->peer_family != AF_UNSPEC) {
            json_object_object_add(jconn, "remote-address-family", json_object_new_string(str_ip46(s->peer_family)));
            json_object_object_add(jconn, "remote-address", json_object_new_string(s->peer_name));
            json_object_object_add(jconn, "remote-port", json_object_new_string(s->peer_port));
        }
        json_object_object_add(jo, "connection", jconn);
        jconn = NULL;
    }
    if (agent_mac)
        json_object_object_add(jo, "mac", json_object_new_string(agent_mac));
    if (task_name) {
        json_object_object_add(jo, "task-name", json_object_new_string(task_name));
        json_object_object_add(jo, "task-version", json_object_new_string(PACKAGE_VERSION));
    }
    json_object_object_add(jo, "engine-name", json_object_new_string(SIMET_ENGINE_NAME));
    json_object_object_add(jo, "engine-version", json_object_new_string(PACKAGE_VERSION));
#ifdef IS_SIMETBOX_BUILD
    json_object_object_add(jo, "agent-family", json_object_new_string("embedded"));
#else
    json_object_object_add(jo, "agent-family", json_object_new_string("system_service"));
#endif
    if (s->connect_timestamp)
        json_object_object_add(jo, "timestamp-seconds", json_object_new_int64(s->connect_timestamp));

    const char *jsonstr = json_object_to_json_string(jo);
    if (jsonstr) {
        protocol_trace(s, "ma_connect message: %s", jsonstr);
        rc = xx_simet_uptime2_sndmsg(s, SIMET_INETUP_P_MSGTYPE_CONNECT, strlen(jsonstr), jsonstr);
    } else {
        rc = -EFAULT;
    }

err_exit:
    /* free(jsonstr); -- not! it is managed by json-c */
    json_object_put(jo);

    return rc;
}

/*
 * telemetry/measurement stream tracking
 */

/* returns true if s is the main telemetry server */
static inline int is_telemetry_server(struct simet_inetup_server * const s)
{
    return (telemetry_server == s && s
            && s->state == SIMET_INETUP_P_C_MAINLOOP) ? 1 : 0;
}
/* ensures s is not the main telemetry server anymore */
static void decline_as_telemetry_server(struct simet_inetup_server * const s)
{
    if (s && s == telemetry_server) {
        telemetry_server = NULL;
        protocol_trace(s, "no longer the main telemetry server");
    }
}
/* propose s as the main telemetry server, s must be in MAINLOOP state */
static void propose_as_telemetry_server(struct simet_inetup_server * const s)
{
    if (s && s->state == SIMET_INETUP_P_C_MAINLOOP) {
        if (telemetry_server && telemetry_server->state == SIMET_INETUP_P_C_MAINLOOP)
            return; /* no reason to change it */
        telemetry_server = s;
        protocol_trace(s, "selected as main telemetry server");
    }
}
static inline int need_telemetry_server(void)
{
    return (!telemetry_server || telemetry_server->state != SIMET_INETUP_P_C_MAINLOOP);
}

/*
 * MEASUREMENT messages:
 *
 * { "measurements": [
 *   { "name": "<measurement name>",
 *     "timestamp-seconds": <event timestamp trunctated to seconds>,
 *     "timestamp-microssecond-from-seconds": <event timestamp microsseconds, 0-999999>
 *     ... (measurement data fields depend on <measurement name>)
 *   }, ...
 *   ] }
 *
 *
 * Warning: we use struct timeval to carry the timestamps, but they *must* be *already*
 * normalized so that microsecconds is not bigger than 999999 usec.
 */

/* t1 comes earlier than t2, dtx and drx are the deltas */
static int simet_uptime2_msg_measurement_wantxrx(struct simet_inetup_server * const s,
        const time_t t1_s, const long int t1_us, const time_t t2_s, const long int t2_us,
        const uint64_t tx, const uint64_t rx,
        const uint64_t dtx, const uint64_t drx)
{
    json_object *jroot;
    json_object *jarray;
    json_object *jo;
    int rc = -ENOMEM;
    int64_t itx, irx, idtx, idrx;

    if (!s)
        return -EINVAL;

    if (!fits_u64_i64(dtx, &idtx) || !fits_u64_i64(drx, &idrx)) {
        protocol_trace(s, "wan_txrx: rx and/or tx delta too large, skipping");
        return -EINVAL;
    }

    /* these would not recover without a reboot, otherwise */
    itx = tx & INT64_MAX;
    irx = rx & INT64_MAX;

    protocol_trace(s, "wan_txrx: sending measurement message");

    jo = json_object_new_object();
    jroot = json_object_new_object();
    jarray = json_object_new_array();
    if (!jroot || !jarray || !jo)
        goto err_exit;

    json_object_object_add(jo, "name", json_object_new_string("wan_txrx"));
    json_object_object_add(jo, "tx_bytes", json_object_new_int64(itx));
    json_object_object_add(jo, "rx_bytes", json_object_new_int64(irx));
    json_object_object_add(jo, "timestamp-seconds", json_object_new_int64(t2_s));
    json_object_object_add(jo, "timestamp-microsseconds-since-second", json_object_new_int64(t2_us));
    json_object_object_add(jo, "since-timestamp-seconds", json_object_new_int64(t1_s));
    json_object_object_add(jo, "since-timestamp-microsseconds-since-second", json_object_new_int64(t1_us));
    json_object_object_add(jo, "tx_delta_bytes", json_object_new_int64(idtx));
    json_object_object_add(jo, "rx_delta_bytes", json_object_new_int64(idrx));

    if (json_object_array_add(jarray, jo))
        goto err_exit;
    jo = NULL;

    json_object_object_add(jroot, "measurements", jarray);
    jarray = NULL;

    const char *jsonstr = json_object_to_json_string(jroot);
    if (jsonstr) {
        /* protocol_trace(s, "measurement message: %s", jsonstr); */
        rc = xx_simet_uptime2_sndmsg(s, SIMET_INETUP_P_MSGTYPE_MEASUREMENT, strlen(jsonstr), jsonstr);
        if (!rc)
            simet_uptime2_keepalive_update(s);
    } else {
        rc = -EFAULT;
    }

    /* free(jsonstr); -- not! it is managed by json-c */

err_exit:
    json_object_put(jo);
    json_object_put(jarray);
    json_object_put(jroot);

    return rc;
}

/*
 * SIMET2 Uptime2 measurements
 */

static struct m_wantxrx_data {
    int initialized;
    int enabled;
    void * sys_context;
    struct timespec last_t;
    uint64_t last_tx;
    uint64_t last_rx;
} m_wantxrx_data;

/* returns 1 if enabled, 0 if not enabled */
static int xx_simet_uptime2_m_wantxrx_reconfig(const int enable_measurement)
{
    if (!enable_measurement || !monitor_netdev) {
        if (m_wantxrx_data.enabled)
            print_msg(MSG_DEBUG, "wan_txrx: disabled by configuration");
        m_wantxrx_data.enabled = 0;
        return 0;
    }

    if (!os_netdev_bytecount_supported()) {
        print_msg(MSG_DEBUG, "wan_txrx: disabled: netdev monitoring not supported");
        return 0;
    }

    /* try to enable it */

    if (!m_wantxrx_data.initialized) {
        if (os_netdev_init(monitor_netdev, &m_wantxrx_data.sys_context)) {
            goto err_exit;
        }
        m_wantxrx_data.initialized = 1;
    } else {
        int rc = os_netdev_change(monitor_netdev, m_wantxrx_data.sys_context);
        if (rc > 0 && m_wantxrx_data.enabled) {
            /* no change to netdev and already enabled: do nothing */
            return 1;
        } else if (rc < 0) {
            goto err_exit;
        }
    }

    if (clock_gettime(CLOCK_MONOTONIC, &m_wantxrx_data.last_t) ||
        os_get_netdev_counters(&m_wantxrx_data.last_tx, &m_wantxrx_data.last_rx,
                m_wantxrx_data.sys_context)) {
        goto err_exit;
    }

    /* success, we have our first data point */
    print_msg(MSG_DEBUG,"wan_txrx: now monitoring netdev %s", monitor_netdev);
    m_wantxrx_data.enabled = 1;
    return 1;

err_exit:
    print_warn("wan_txrx: disabled: failed to setup netdev monitoring");
    if (m_wantxrx_data.initialized) {
        m_wantxrx_data.initialized = 0;
        os_netdev_done(m_wantxrx_data.sys_context);
        m_wantxrx_data.sys_context = NULL;
    }
    m_wantxrx_data.enabled = 0;
    return 0;
}
static void xx_simet_uptime2_m_wantxrx_init(void)
{
    memset(&m_wantxrx_data, 0, sizeof(m_wantxrx_data));
    /* the important ones:
    m_wanttxrx_data.sys_context = NULL;
    m_wanttxrx_data.enabled = 0;
    m_wanttxrx_data.initialized = 0;
    */
}
static void xx_simet_uptime2_m_wantxrx_done(void)
{
    if (m_wantxrx_data.enabled) {
        m_wantxrx_data.enabled = 0;
        os_netdev_done(m_wantxrx_data.sys_context);
        m_wantxrx_data.sys_context = NULL;
    }
}

/* call from mainloop, returns wait time to (next?) measurement */
static int run_measurement_wantxrx(struct simet_inetup_server * const s)
{
    struct timespec now;
    uint64_t tx, rx;
    int rc;

    if (!m_wantxrx_data.enabled || !is_telemetry_server(s) || !s->measurement_period)
        return INT_MAX;

    rc = timer_check(m_wantxrx_data.last_t.tv_sec, s->measurement_period);
    if (rc > 0)
        return rc;

    if (os_get_netdev_counters(&tx, &rx, m_wantxrx_data.sys_context) || clock_gettime(CLOCK_MONOTONIC, &now))
        return (s->measurement_period <= INT_MAX) ? (int) s->measurement_period : INT_MAX; /* skip data point */

    /* we assume a new enough kernel with 64bit counters, so no rollover at 2^32 */
    /* if there is a counter reset, we reset to recover and lose the sample */

    rc = 0;
    if (m_wantxrx_data.last_tx <= tx && m_wantxrx_data.last_rx <= rx) {
        rc = simet_uptime2_msg_measurement_wantxrx(s,
                m_wantxrx_data.last_t.tv_sec, m_wantxrx_data.last_t.tv_nsec / 1000,
                now.tv_sec, now.tv_nsec / 1000,
                tx, rx, tx - m_wantxrx_data.last_tx, rx - m_wantxrx_data.last_rx);
        if (rc == -EINVAL || rc == -ENOMEM || rc == -ENOTSUP || rc == -ERANGE)
            rc = 0; /* we need to reset and skip sample */
    }

    if (!rc) {
        /* we either sent the measurement message, or need to reset */
        m_wantxrx_data.last_t = now;
        m_wantxrx_data.last_tx = tx;
        m_wantxrx_data.last_rx = rx;
    }

    return (s->measurement_period <= INT_MAX) ? (int) s->measurement_period : INT_MAX;
}

/* called right after init, and after reloading MA-side config */
static void simet_uptime2_measurements_reconfig(void)
{
    int try_to_enable = !!(monitor_netdev != NULL);

    xx_simet_uptime2_m_wantxrx_reconfig(try_to_enable);
}

static void simet_uptime2_measurements_disable_netdev(void)
{
    free_constchar(monitor_netdev);
    monitor_netdev = NULL;
    xx_simet_uptime2_m_wantxrx_reconfig(0);
}

/* protocol streams not yet setup at this point, but MA-side
 * configuration has been loaded */
static void simet_uptime2_measurements_global_init(void)
{
    xx_simet_uptime2_m_wantxrx_init();
    simet_uptime2_measurements_reconfig();
}

/* protocol streams already destroyed at this point */
static void simet_uptime2_measurements_global_done(void)
{
    xx_simet_uptime2_m_wantxrx_done();
}

/*
 * SIMET2 Uptime2 connection lifetime messages and handling
 */

/* jump to the reconnect state, used by state machine workers
 *
 * resets the backoff timer, so it should be used only after we're sure the
 * server is not doing close() because it is denying service
 */
static void simet_uptime2_reconnect(struct simet_inetup_server * const s)
{
    if (s->state != SIMET_INETUP_P_C_RECONNECT && !got_exit_signal) {
        protocol_trace(s, "will attempt to reconnect in %u seconds", backoff_times[s->backoff_level]);
        s->state = SIMET_INETUP_P_C_RECONNECT;
        s->backoff_clock = reltime();

        decline_as_telemetry_server(s);
    }
}

/* jump to the disconnect state, unless it is already disconnecting */
static void simet_uptime2_disconnect(struct simet_inetup_server * const s)
{
    if (s->state != SIMET_INETUP_P_C_DISCONNECT &&
            s->state != SIMET_INETUP_P_C_DISCONNECT_WAIT &&
            s->state != SIMET_INETUP_P_C_SHUTDOWN) {
        s->state = SIMET_INETUP_P_C_DISCONNECT;
        s->disconnect_clock = 0;

        decline_as_telemetry_server(s);

        protocol_info(s, "client disconnecting...");
    }
}

/* call this after we are sure the server likes us */
static void simet_uptime2_backoff_reset(struct simet_inetup_server * const s)
{
    s->backoff_level = 0;
    s->backoff_reset_clock = 0;
}

/*
 * protocol state machine: state workers
 *
 * returns: N < 0 : errors (-errno)
 *          N = 0 : OK, run next state ASAP
 *          N > 0 : OK, no need to run again for N seconds
 *
 * Do not close the socket without checking first if the
 * state-machine expects it, otherwise it will poll() on
 * a closed socket.
 */
static int uptimeserver_refresh(struct simet_inetup_server * const s)
{
    assert(s);
    assert(s->state == SIMET_INETUP_P_C_REFRESH);

    if (simet_uptime2_msg_maconnect(s)) {
        simet_uptime2_reconnect(s);
    } else {
        simet_uptime2_keepalive_update(s);
        s->state = SIMET_INETUP_P_C_MAINLOOP;
        /* do this only after s->state is set to MAINLOOP */
        propose_as_telemetry_server(s);
    }

    /* FIXME: this is correct, but not being done the right way */
    if (simet_uptime2_msg_clientlifetime(s, 1))
        simet_uptime2_reconnect(s);
    else if (simet_uptime2_msg_link(s, 1))
        simet_uptime2_reconnect(s);

    return 0;
}

static int uptimeserver_keepalive(struct simet_inetup_server * const s)
{
    assert(s);

    time_t interval = (s->server_timeout) ?
                            timeout_to_keepalive(s->server_timeout) :
                            INT_MAX;
    time_t waittime_left = timer_check_full(s->keepalive_clock, interval);
    if (waittime_left > timeout_to_timefuzz(s->server_timeout))
        return (waittime_left <= INT_MAX) ? (int) waittime_left : INT_MAX;

    if (simet_uptime2_msg_keepalive(s)) {
        simet_uptime2_reconnect(s);
        return 0;
    }

    simet_uptime2_keepalive_update(s);
    return (int) interval;
}

/* returns 0 if we should timeout the remote */
static int uptimeserver_remotetimeout(struct simet_inetup_server * const s)
{
    assert(s);

    if (!s->remote_keepalive_clock || !s->remote_keepalives_enabled)
        return 1; /* we are not depending on remote keepalives */

    return (timer_check_full(s->remote_keepalive_clock, s->client_timeout) > 0);
}

static int xx_nameinfo(struct sockaddr_storage *sa, socklen_t sl,
                        sa_family_t *family, const char **hostname, const char **hostport)
{
    char namebuf[256], portbuf[32];

    if (sa->ss_family == AF_UNSPEC || getnameinfo((struct sockaddr *)sa, sl,
                                                   namebuf, sizeof(namebuf), portbuf, sizeof(portbuf),
                                                   NI_NUMERICHOST | NI_NUMERICSERV)) {
        *family = AF_UNSPEC;
        *hostname = strdup("unknown");
        *hostport = strdup("error");

        return 1;
    }

    *hostname = strdup(namebuf);
    *hostport = strdup(portbuf);
    *family = sa->ss_family;

    return 0;
}

/* ensure it is compatible with xx_nameinfo()! */
static int xx_cmpnameinfo(const struct addrinfo * const ai,
                          const sa_family_t family, const char *hostname)
{
    char namebuf[256];

    if (!hostname || !ai || ai->ai_family != family || !ai->ai_addr || !ai->ai_addrlen)
        return 0;
    if (getnameinfo(ai->ai_addr, ai->ai_addrlen, namebuf, sizeof(namebuf),
                    NULL, 0, NI_NUMERICHOST | NI_NUMERICSERV))
        return 0; /* fail safe */

    return (strncmp(namebuf, hostname, sizeof(namebuf)) == 0);
}

static int uptimeserver_connect(struct simet_inetup_server * const s,
                       const char * const server_name, const char * const server_port)
{
    struct addrinfo *air = NULL, *airp;
    struct addrinfo ai;
    int backoff;
    int r;

    const int int_one = 1;

    assert(s && server_name && server_port);
    assert(s->state == SIMET_INETUP_P_C_INIT || s->state == SIMET_INETUP_P_C_RECONNECT);

    if (s->state == SIMET_INETUP_P_C_RECONNECT && s->socket != -1)
        tcpaq_close(s);

    assert(s->socket == -1);

    /* Backoff timer */
    int waittime_left = timer_check(s->backoff_clock, backoff_times[s->backoff_level]);
    if (waittime_left > 0)
        return waittime_left;
    s->backoff_clock = reltime();
    if (s->backoff_level < BACKOFF_LEVEL_MAX-1)
        s->backoff_level++;
    backoff = (int) backoff_times[s->backoff_level];

    protocol_trace(s, "attempting connection to %s, port %s", server_name, server_port);

    s->connect_timestamp = 0;

    /* per-server configuration data defaults */
    s->server_timeout = SIMET_UPTIME2_DEFAULT_TIMEOUT;
    s->client_timeout = simet_uptime2_tcp_timeout;
    s->measurement_period = SIMET_UPTIME2_DFL_MSR_PERIOD;
    s->remote_keepalives_enabled = 0;

    memset(&ai, 0, sizeof(ai));
    ai.ai_flags = AI_ADDRCONFIG;
    ai.ai_socktype = SOCK_STREAM;
    ai.ai_family = s->ai_family;
    ai.ai_protocol = IPPROTO_TCP;

    r = getaddrinfo(server_name, server_port, &ai, &air);
    if (r != 0) {
        protocol_trace(s, "getaddrinfo returned %s", gai_strerror(r));
        return backoff;
    }
    for (airp = air; airp != NULL; airp = airp->ai_next) {
        /* avoid fast reconnect to same peer */
        if (s->peer_noconnect_ttl && xx_cmpnameinfo(airp, s->ai_family, s->peer_name)) {
            protocol_trace(s, "skipping peer %s on this attempt", s->peer_name);
            continue;
        }

        s->socket = socket(airp->ai_family, airp->ai_socktype | SOCK_CLOEXEC, airp->ai_protocol);
        if (s->socket == -1)
            continue;

        xx_set_tcp_timeouts(s);

        /* Defang OOB/urgent data, we might need it to implement resync messages */
        setsockopt(s->socket, IPPROTO_TCP, SO_OOBINLINE, &int_one, sizeof(int_one));

        /* Linux TCP Thin-stream optimizations.
         *
         * Refer to: https://nnc3.com/mags/LJ_1994-2014/LJ/219/11180.html
         * Refer to: https://lwn.net/Articles/308919/
         * Refer to: http://home.ifi.uio.no/paalh/students/AndreasPetlund-phd.pdf
         * Refer to: https://github.com/torvalds/linux/blob/master/Documentation/networking/tcp-thin.txt
         */
#ifdef TCP_THIN_LINEAR_TIMEOUTS
        if (setsockopt(s->socket, IPPROTO_TCP, TCP_THIN_LINEAR_TIMEOUTS, &int_one, sizeof(int_one))) {
            print_warn("failed to enable TCP thin-stream linear timeouts, false positives may increase");
        }
#endif /* TCP_THIN_LINEAR_TIMEOUTS */
#ifdef TCP_THIN_DUPACK
        if (setsockopt(s->socket, IPPROTO_TCP, TCP_THIN_DUPACK, &int_one, sizeof(int_one))) {
            print_warn("failed to enable TCP thin-stream dupack, false positives may increase");
        }
#endif /* TCP_THIN_DUPACK */

        /* FIXME: do this using select()/poll(), but we have to make it
         * indepondent and async so that we can return to caller to process
         * other concurrent connect()s to other server streams in the
         * meantime.  And that must happen in the middle of the
         * getaddrinfo() loop */
        if (connect(s->socket, airp->ai_addr, airp->ai_addrlen) != -1)
            break;
        close(s->socket);
        s->socket = -1;
    }

    freeaddrinfo(air);
    air = airp = NULL;

    /* FIXME: backoff_clock update required because we are doing blocking connects(),
     * so several seconds will have elapsed already */
    s->backoff_clock = reltime();

    if (s->socket == -1) {
        if (s->peer_noconnect_ttl)
            s->peer_noconnect_ttl--;
        protocol_trace(s, "could not connect, will retry in %d seconds", backoff);
        return backoff;
    }

    /* Disable Naggle, we don't need it (but we can tolerate it) */
    setsockopt(s->socket, IPPROTO_TCP, TCP_NODELAY, &int_one, sizeof(int_one));

    /* Get metadata of the connected socket */
    struct sockaddr_storage sa;
    socklen_t sa_len;

    sa_len = sizeof(struct sockaddr_storage);
    sa.ss_family = AF_UNSPEC;
    if (getpeername(s->socket, (struct sockaddr *)&sa, &sa_len) || 
        xx_nameinfo(&sa, sa_len, &s->peer_family, &s->peer_name, &s->peer_port))
        print_warn("failed to get peer metadata, coping with it");
    s->peer_noconnect_ttl = 0;

    sa_len = sizeof(struct sockaddr_storage);
    sa.ss_family = AF_UNSPEC;
    if (getsockname(s->socket, (struct sockaddr *)&sa, &sa_len) ||
        xx_nameinfo(&sa, sa_len, &s->local_family, &s->local_name, &s->local_port))
        print_warn("failed to get local metadata, coping with it");

    /* done... */
    s->connect_timestamp = reltime();
    protocol_info(s, "connect: connected over %s to measurement peer %s, port %s",
            str_ipv46(s->local_family), server_name, server_port);
    protocol_info(s, "connect: local %s address [%s]:%s, remote %s address [%s]:%s",
            str_ipv46(s->local_family), s->local_name, s->local_port,
            str_ipv46(s->peer_family), s->peer_name, s->peer_port);

    s->state = SIMET_INETUP_P_C_REFRESH;
    return 0;
}

static int uptimeserver_disconnect(struct simet_inetup_server *s)
{
    int rc = 0;

    /* warning: state INIT might not have run! */
    if (s->socket == -1) {
        /* not connected */
        s->state = SIMET_INETUP_P_C_SHUTDOWN;
        s->disconnect_clock = 0;
        return 0;
    }

    if (!s->disconnect_clock) {
        s->disconnect_clock = reltime();
        protocol_trace(s, "attempting clean disconnection for up to %d seconds", SIMET_DISCONNECT_WAIT_TIMEOUT);
    }

    /* FIXME: this needs to track event recording lifetime when we implement it,
     * so we should not do ma_clientstop on non-shutdown */
    if (!simet_uptime2_msg_clientlifetime(s, 0)) {
        /* queued sucessfully */
        s->state = SIMET_INETUP_P_C_DISCONNECT_WAIT;
        return 0;
    }

    /* will have to retry queueing again, check timeout */
    rc = timer_check(s->disconnect_clock, SIMET_DISCONNECT_WAIT_TIMEOUT);
    if (!rc)
        s->state = SIMET_INETUP_P_C_DISCONNECT_WAIT; /* timed out, kick to next stage */

    return rc;
}

static int uptimeserver_disconnectwait(struct simet_inetup_server *s)
{
    if (s->socket == -1) {
        /* not connected */
        s->state = SIMET_INETUP_P_C_SHUTDOWN;
        s->disconnect_clock = 0;
        return 0;
    }

    if (!s->disconnect_clock)
        s->disconnect_clock = reltime(); /* should not happen */

    int rc = timer_check(s->disconnect_clock, SIMET_DISCONNECT_WAIT_TIMEOUT);
    if (!rc || tcpaq_is_out_queue_empty(s)) {
        /* tcpaq queue is empty, or we are out of time */
        tcpaq_close(s);
        s->socket = -1;
        s->disconnect_clock = 0;

        protocol_info(s, "client disconnected");

        s->state = SIMET_INETUP_P_C_SHUTDOWN;
        return 0;
    }

    return rc;
}

static int uptimeserver_create(struct simet_inetup_server **sp, int ai_family)
{
    static unsigned int next_connection_id = 1;

    struct simet_inetup_server *s;

    assert(sp);
    assert(ai_family == AF_INET || ai_family == AF_INET6);

    /* this zero-fills the allocated data area */
    s = calloc(1, sizeof(struct simet_inetup_server));
    if (!s)
        return -ENOMEM;

    s->socket = -1;
    s->state = SIMET_INETUP_P_C_INIT;
    s->ai_family = ai_family;
    s->connection_id = next_connection_id;
    s->out_queue.buffer = calloc(1, SIMET_INETUP_QUEUESIZE);
    s->in_queue.buffer = calloc(1, SIMET_INETUP_QUEUESIZE);
    if (!s->out_queue.buffer || !s->in_queue.buffer) {
        free(s->out_queue.buffer);
        free(s->in_queue.buffer);
        free(s);
        return -ENOMEM;
    }
    s->out_queue.buffer_size = SIMET_INETUP_QUEUESIZE;
    s->in_queue.buffer_size = SIMET_INETUP_QUEUESIZE;

    next_connection_id++;

    *sp = s;

    return 0;
}

/*
 * Configuration
 */

/* returns 0 ok, (-1, errno set) on error. *p unchanged on error */
static int fread_agent_str(const char *path, const char ** const p)
{
    FILE *fp;
    char *b;
    int n, e;

    assert(path && p);

    fp = fopen(path, "r");
    if (!fp)
        return -1;

    do {
        n = fscanf(fp, " %256000ms ", &b);
    } while (n == EOF && errno == EINTR);

    e = (errno)? errno : EINVAL;
    fclose(fp);

    if (n == 1) {
        *p = b;
        return 0;
    } else {
        errno = e;
        return -1;
    }
}

static int validate_nonempty(const char * const vname, const char * const v)
{
    if (!v || !v[0]) {
        print_err("invalid %s: \"%s\"", vname, (v)? v : "");
        return -1;
    }
    return 0;
}

static int load_agent_data(const char * const aid_path, const char * const atoken_path)
{
    const char *new_aid = agent_id;
    const char *new_atok = agent_token;

    if (aid_path) {
        if (fread_agent_str(aid_path, &new_aid)) {
            print_err("failed to read agent-id from %s: %s", aid_path, strerror(errno));
            return -1;
        } else if (validate_nonempty("agent-id", new_aid)) {
            return -1;
        }
    }
    if (atoken_path) {
        if (fread_agent_str(atoken_path, &new_atok)) {
            print_err("failed to read agent token from %s: %s", atoken_path, strerror(errno));
            return -1;
        } else if (validate_nonempty("agent token", new_atok)) {
            return -1;
        }
    }

    /* We only change agent-id,token as a set */
    if (agent_id != new_aid) {
        free_constchar(agent_id);
        agent_id = new_aid;
    }
    if (agent_token != new_atok) {
        free_constchar(agent_token);
        agent_token = new_atok;
    }

    if (agent_id)
        print_msg(MSG_NORMAL, "agent-id: %s", agent_id);

    return 0;
}

static int load_netdev_file(const char * const netdev_name_path)
{
    const char * netdev_name = monitor_netdev;

    if (netdev_name_path) {
        if (fread_agent_str(netdev_name_path, &netdev_name)) {
            print_err("failed to read network device name from %s: %s", netdev_name_path, strerror(errno));
            return -1;
        } else if (validate_nonempty("network device to monitor", netdev_name)) {
            return -1;
        }
    }

    if (monitor_netdev != netdev_name) {
        free_constchar(monitor_netdev);
        monitor_netdev = netdev_name;
    }
    return 0;
}

/*
 * Command line and main executable
 */

static const char program_copyright[]=
    "Copyright (c) 2018,2019 NIC.br\n\n"
    "This is free software; see the source for copying conditions.\n"
    "There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR\n"
    "A PARTICULAR PURPOSE.\n";

static void print_version(void)
{
    fprintf(stdout, "%s %s\n%s\n", PACKAGE_NAME, PACKAGE_VERSION, program_copyright);
    exit(SEXIT_SUCCESS);
}

/* FIXME:
 * implement both "standalone daemon" modes and foreground modes?
 *
 * daemon:     -p <pidfile>, and does setsid() and fork().
 * foreground: [-f], works better for systemd and procd
 *
 * currently, implements only foreground mode.
 */

static void print_usage(const char * const p, int mode)
{
    fprintf(stderr, "Usage: %s [-q] [-v] [-h] [-V] [-t <timeout>] "
        "[-d <agent-id>] [-m <string>] [-b <boot id>] [-j <token> ] [-M <string>] "
        "<server name> [<server port>]\n", p);

    if (mode) {
        fprintf(stderr, "\n"
            "\t-h\tprint usage help and exit\n"
            "\t-V\tprint program version and copyright, and exit\n"
            "\t-v\tverbose mode (repeat for increased verbosity)\n"
            "\t-q\tquiet mode (repeat for errors-only)\n"
            "\t-t\tinitial tcp protocol timeout in seconds\n"
            "\t-d\tpath to a file with the measurement agent id\n"
            "\t-m\tmeasurement agent hardcoded id\n"
            "\t-M\tmeasurement task name\n"
            "\t-b\tboot id (e.g. from /proc/sys/kernel/random/boot_id)\n"
            "\t-j\tpath to a file with the access credentials\n"
            "\n"
            "server name: DNS name of server\n"
            "server port: TCP port on server\n"
            "\nNote: client will attempt to open one IPv4 and one IPv6 connection to the server");
    }

    exit((mode)? SEXIT_SUCCESS : SEXIT_BADCMDLINE);
}

static int is_valid_fd(const int fd)
{
    return fcntl(fd, F_GETFD) != -1 || errno != EBADF;
}

static void fix_fds(const int fd, const int fl)
{
    int nfd;

    if (is_valid_fd(fd))
            return;

    nfd = open("/dev/null", fl);
    if (nfd == -1 || dup2(nfd, fd) == -1) {
            print_err("could not attach /dev/null to file descriptor %d: %s",
                      fd, strerror(errno));
            /* if (nfd != -1) close(nfd); - disabled as we're going to exit() now */
            exit(SEXIT_FAILURE);
    }
    if (nfd != fd)
            close(nfd);
}

/*
 * glibc does not ensure sanity of the standard streams at program start
 * for non suid/sgid applications.  The streams are initialized as open
 * and not in an error state even when their underlying FDs are invalid
 * (closed).  These FDs will later become valid due to an unrelated
 * open(), which will cause undesired behavior (such as data corruption)
 * should the stream be used.
 *
 * freopen() cannot be used to fix this directly, due to a glibc 2.14+ bug
 * when freopen() is called on an open stream that has an invalid FD which
 * also happens to be the first available FD.
 */
static void sanitize_std_fds(void)
{
   /* do it in file descriptor numerical order! */
   fix_fds(STDIN_FILENO,  O_RDONLY);
   fix_fds(STDOUT_FILENO, O_WRONLY);
   fix_fds(STDERR_FILENO, O_RDWR);
}

static void ml_update_wait(int * const pwait, const int nwait)
{
    if (nwait >= 0 && nwait < *pwait)
        *pwait = nwait;
}

int main(int argc, char **argv) {
    const char *server_name = NULL;
    const char *server_port = "22000";
    int intarg;

    progname = argv[0];
    sanitize_std_fds();

    client_start_timestamp = reltime();
    client_eventrec_start_timestamp = 0;

    int option;
    /* FIXME: parameter range checking, proper error messages, strtoul instead of atoi */
    while ((option = getopt (argc, argv, "vq46hVc:l:t:d:m:M:b:j:i:")) != -1) {
        switch (option) {
        case 'v':
            if (log_level < 1)
                log_level = 2;
            else if (log_level < MSG_TRACE)
                log_level++;
            break;
        case 'q':
            if (log_level <= 0)
                log_level = -1;
            else
                log_level = 0;
            break;
        case 't':
            intarg = atoi(optarg);
            if (intarg >= SIMET_UPTIME2_SHORTEST_TIMEOUT &&
                    intarg <= SIMET_UPTIME2_LONGEST_TIMEOUT) {
                simet_uptime2_tcp_timeout = (unsigned int)intarg;
            } else {
                print_usage(progname, 1);
            }
            break;
        case 'd':
            agent_id_file = optarg;
            break;
        case 'm':
            agent_mac = optarg;
            break;
        case 'M':
            task_name = optarg;
            break;
        case 'b':
            boot_id = optarg;
            break;
        case 'j':
            agent_token_file = optarg;
            break;
        case 'i':
            monitor_netdev_file = optarg;
            break;
        case 'h':
            print_usage(progname, 1);
            /* fall-through */
        case 'V':
            print_version();
            /* fall-through */
        default:
            print_usage(progname, 0);
        }
    };

    if (optind >= argc || argc - optind > 2)
        print_usage(progname, 0);

    server_name = argv[optind++];
    if (optind < argc)
        server_port = argv[optind];

    init_signals();

    print_msg(MSG_ALWAYS, PACKAGE_NAME " " PACKAGE_VERSION " starting...");
    print_msg(MSG_DEBUG, "initial timeout=%us, server=\"%s\", port=%s",
              simet_uptime2_tcp_timeout, server_name, server_port);

    /* init */
    /* this can be easily converted to use up-to-# servers per ai_family, etc */
    const unsigned int servers_count = 2;
    struct pollfd *servers_pollfds = calloc(servers_count, sizeof(struct pollfd));
    servers = calloc(servers_count, sizeof(struct simet_inetup_server *));
    if (!servers_pollfds || !servers ||
            uptimeserver_create(&servers[0], AF_INET) || uptimeserver_create(&servers[1], AF_INET6)) {
        print_err("out of memory");
        return SEXIT_OUTOFRESOURCE;
    }

    if (load_agent_data(agent_id_file, agent_token_file)) {
        print_err("failed to read agent identification credentials");
        return SEXIT_FAILURE;
    }
    if (load_netdev_file(monitor_netdev_file)) {
        print_err("failed to read network device name to monitor, disabling functionality");
    }

    simet_uptime2_measurements_global_init();

    /* state machine loop */
    do {
        time_t minwait = 300;
        unsigned int j, num_shutdown;
        int queued_msg_disconnect;

        num_shutdown = 0;

        /* safe semanthics if it is ever made volatile/MT */
        queued_msg_disconnect = 0;
        if (got_disconnect_msg) {
            queued_msg_disconnect = 1;
            got_disconnect_msg = 0;
        }

        for (j = 0; j < servers_count; j++) {
            struct simet_inetup_server *s = servers[j];
            int wait = 0;

            if (got_exit_signal)
                simet_uptime2_disconnect(s);

#if 0
            print_msg(MSG_DEBUG, "%s(%u): main loop, currently at state %u",
                    str_ipv46(s->ai_family), s->connection_id, s->state);
#endif

            switch (s->state) {
            case SIMET_INETUP_P_C_INIT:
                assert(s->socket == -1 && s->out_queue.buffer && s->in_queue.buffer);
                servers_pollfds[j].fd = -1;
                servers_pollfds[j].events = POLLRDHUP | POLLIN;
                /* fall-through */
            case SIMET_INETUP_P_C_RECONNECT:
                if (queued_msg_disconnect) {
                    s->backoff_level = BACKOFF_LEVEL_MAX-1;
                    s->backoff_clock = reltime();
                    protocol_trace(s, "global disconnect: will attempt to reconnect in %u seconds",
                            backoff_times[s->backoff_level]);
                }
                wait = uptimeserver_connect(s, server_name, server_port);
                servers_pollfds[j].fd = s->socket;
                break;
            case SIMET_INETUP_P_C_REFRESH:
                s->remote_keepalive_clock = 0;
                s->backoff_reset_clock = reltime();
                wait = uptimeserver_refresh(s);
                break;
            case SIMET_INETUP_P_C_MAINLOOP:
                if (queued_msg_disconnect) {
                    /* FIXME: queue a server-told-us-to-disconnect event to report later */
                    s->backoff_level = BACKOFF_LEVEL_MAX-1;
                    simet_uptime2_reconnect(s);
                    wait = 0;
                    break;
                }

                if (s->backoff_reset_clock &&
                        !timer_check_full(s->backoff_reset_clock, s->server_timeout * 2)) {
                    protocol_trace(s, "assuming measurement peer is willing to provide service, backoff timer reset");
                    simet_uptime2_backoff_reset(s);
                }

                if (need_telemetry_server())
                    propose_as_telemetry_server(s);

                /* process return channel messages */
                while (simet_uptime2_recvmsg(s, simet_uptime2_messages_mainloop) > 0);

                if (got_disconnect_msg)
                    break;

                if (!uptimeserver_remotetimeout(s)) {
                    /* remote keepalive timed out */
                    protocol_trace(s, "remote keepalive timed out");
                    simet_uptime2_reconnect(s);
                    wait = 0;
                    break;
                }

                /* measurement and event messages go here */
                wait = run_measurement_wantxrx(s);
                /* ml_update_wait(&wait, ...); */

                ml_update_wait(&wait, uptimeserver_keepalive(s));
                break;

            case SIMET_INETUP_P_C_DISCONNECT:
                wait = uptimeserver_disconnect(s);
                uptimeserver_drain(s);
                break;
            case SIMET_INETUP_P_C_DISCONNECT_WAIT:
                wait = uptimeserver_disconnectwait(s);
                uptimeserver_drain(s);
                break;

            case SIMET_INETUP_P_C_SHUTDOWN:
                /* warning: state INIT might not have run! */
                num_shutdown++;
                servers_pollfds[j].fd = -1;
                wait = INT_MAX;
                break;

            default:
                print_err("internal error or memory corruption");
                return SEXIT_INTERNALERR;
            }

            if (wait >= 0 && wait < minwait)
                minwait = wait;

            if (uptimeserver_flush(s)) {
                simet_uptime2_reconnect(s);
                minwait = 0;
            }
        }

#if 0
        print_msg(MSG_DEBUG, "main loop: stream loop end, minwait=%ld", minwait);
#endif

        if (num_shutdown >= servers_count && got_exit_signal)
            break;

        if (got_disconnect_msg)
            minwait = 0;

        if (minwait > 0) {
            /* optimized for a small number of servers */
            int poll_res = poll(servers_pollfds, servers_count, minwait * 1000U);
            if (poll_res > 0) {
                for (j = 0; j < servers_count; j++) {
                    if (servers_pollfds[j].revents & (POLLRDHUP | POLLHUP | POLLERR)) {
                        if (servers[j]->state != SIMET_INETUP_P_C_RECONNECT) {
                            /* ugly, but less ugly than having reconnect close the socket immediately */
                            protocol_info(servers[j], "connection to measurement peer lost");
                            simet_uptime2_reconnect(servers[j]); /* fast close/shutdown detection */
                        }
                        servers_pollfds[j].fd = -1;
                    } else if (servers_pollfds[j].revents & ~POLLIN) {
                        protocol_trace(servers[j],
                            "unhandled: pollfd[%u].fd = %d, pollfd[%u].events = 0x%04x, pollfd[%u].revents = 0x%04x",
                            j, servers_pollfds[j].fd,
                            j, (unsigned int)servers_pollfds[j].events,
                            j, (unsigned int)servers_pollfds[j].revents);
                    }
                }
            } else if (poll_res == -1 && (errno != EINTR && errno != EAGAIN)) {
                print_err("internal error, memory corruption or out of memory");
                return SEXIT_INTERNALERR;
            }
        }

        if (got_reload_signal && !got_exit_signal) {
            got_reload_signal = 0;
            if (load_agent_data(agent_id_file, agent_token_file)) {
                print_err("failed to reload agent identification credentials, using old");
            }
            if (load_netdev_file(monitor_netdev_file)) {
                simet_uptime2_measurements_disable_netdev();
            }
            simet_uptime2_measurements_reconfig();
            for (j = 0; j < servers_count; j++)
                simet_uptime2_reconnect(servers[j]);
            /* FIXME: queue a "we forced a disconnect-reconnect event" event for next connection ? */
        }
    } while (1);

    simet_uptime2_measurements_global_done();

    if (got_exit_signal)
        print_msg(MSG_NORMAL, "received exit signal %d, exiting...", got_exit_signal);
    else
        print_msg(MSG_NORMAL, "all servers connections have been shutdown, exiting...");

    return SEXIT_SUCCESS;
}

/* vim: set et ts=4 sw=4 : */
