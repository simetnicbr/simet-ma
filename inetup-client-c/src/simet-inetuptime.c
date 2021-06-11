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
#include <inttypes.h>

#include <limits.h>
#include <string.h>
#include <ctype.h>
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

static struct simet_inetup_server_cluster *server_clusters = NULL;
static struct simet_inetup_server **servers = NULL;
static unsigned int servers_count = 0;
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

static clockid_t clockid = CLOCK_MONOTONIC;
static time_t client_start_timestamp;
static time_t client_eventrec_start_timestamp;
static time_t client_boot_offset = 0;
static int    client_boot_sync   = 0;

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

/* strcmp with proper semanthics for NULL */
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

/* trim spaces, note we return NULL if the result is empty or ENOMEM */
static char *strndup_trim(const char *s, size_t l)
{
    if (!s)
        return NULL;

    while (isspace(*s) && l > 0) {
        s++;
        l--;
    };

    if (!*s || l <= 0)
        return NULL;

    while (l > 0 && isspace(s[l-1]))
        l--;

    return (l > 0) ? strndup(s, l) : NULL;
}

/* trim spaces, note we return NULL if the result is empty or ENOMEM */
static char *strdup_trim(const char *s)
{
    if (!s)
        return NULL;
    return strndup_trim(s, strlen(s));
}

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

    if (!clock_gettime(clockid, &now)) {
        now.tv_sec += client_boot_offset;
        return (now.tv_sec > 0)? now.tv_sec : 0;  /* this helps the optimizer and squashes several warnings */
    } else {
        print_err("clock_gettime(%d) failed!", clockid);
        /* FIXME: consider abort(EXIT_FAILURE) */
        return 0; /* kaboom! most likely :-( */
    }
}

static void init_timekeeping(void)
{
    struct timespec ts;
    int64_t now_boot;

#ifdef CLOCK_BOOTTIME
    /* First option: CLOCK_BOOTTIME */
    if (!clock_gettime(CLOCK_BOOTTIME, &ts)) {
        clockid = CLOCK_BOOTTIME;
        client_boot_offset = 0;
        client_boot_sync = 1;
    } else
#endif
    /* Second option: CLOCK_MONOTONIC + sys/sysinfo::sysinfo() */
    if (!os_seconds_since_boot(&now_boot)) {
        time_t now_rel;
        int64_t old_offset = client_boot_offset;

        client_boot_offset = 0; /* reset in case this is a resync */
        now_rel = reltime(); /* must call with offset set to zero */

        /* Don't bother correcting offset errors smaller than 3s, as 1s
         * (and maybe 2s?) requires a back-to-back retry if it fails due to
         * landing at the wrong side of a second bondary in either clock
         * (or worse, both clocks), and doing it for errors smaller than 1s
         * requires either something else than os_seconds_since_boot() or a
         * phase-lock loop that takes several *seconds* to run */

        /* Keep in sync with timekeeping_needs_resync() or it will break
         * hideously!  Time won't go backwards in a resync because we never
         * trigger the resync in that case. */
        client_boot_offset = (abs(now_boot - now_rel) > 2)? now_boot - now_rel : 0;

        clockid = CLOCK_MONOTONIC;
        client_boot_sync = 1;

        if (client_boot_offset < old_offset) {
            /* Should never happen: it went backwards! */

            print_msg(MSG_IMPORTANT, "irrecoverable clock sync loss: (old offset %lld) > (new offset %lld)",
                    (long long) old_offset, (long long) client_boot_offset);
            print_msg(MSG_IMPORTANT, "switching to unsync mode, and keeping old offset");
            client_boot_sync = 0;
            client_boot_offset = old_offset;
        }
    } else {
        /* last option: defaults */
        clockid = CLOCK_MONOTONIC;
        client_boot_sync = 0;
        client_boot_offset = 0;
    }
}

/* Returns non-zero if there is a need to resync.
 * To resync: call init_timekeeping(), but do it with all connections
 * down and all threads quiesced!
 */
static int timekeeping_needs_resync(void)
{
#ifdef CLOCK_BOOTTIME
    if (clockid == CLOCK_BOOTTIME)
        return 0;
#endif

    if (clockid == CLOCK_MONOTONIC && client_boot_sync) {
        time_t  reltime_now = reltime();
        int64_t boottime_now;

        if (os_seconds_since_boot(&boottime_now)) {
            /* it broke?! resync to fix */
            return 1;
        }

        /* ignore differences of up to three seconds.  Do *not* even
         * consider a resync if it would cause the offset to go backwards.
         *
         * if reltime() breaks and returns 0, it is also going to force a
         * resync.  triggering resync at smaller differences is non-trivial
         * as we don't sync *here* and it could happen very often due to
         * bounded phase error at the second boundary of either (or both!)
         * clocks.
         *
         * Keep the threshold in sync with init_timekeeping(), or
         * it could break hideously.
         * */
        return !!(boottime_now - reltime_now > 2);
    }

    return 0;
}

static void log_timekeeping_state()
{
    if (client_boot_sync) {
        print_msg(MSG_DEBUG, "timestamps are seconds since system boot");

#ifdef CLOCK_BOOTTIME
        if (clockid == CLOCK_BOOTTIME) {
           print_msg(MSG_DEBUG, "timestamps will use CLOCK_BOOTTIME");
        }
#endif
        if (client_boot_offset)  {
           print_msg(MSG_DEBUG, "timestamps using a monotonic clock offset: %llds",
                (long long) client_boot_offset);
        }
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

#define protocol_msg(aloglevel, protocol_stream, format, arg...) \
    do { \
        if (log_level >= aloglevel) { \
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

#define protocol_trace(protocol_stream, format, arg...) \
    protocol_msg(MSG_TRACE, protocol_stream, format, ## arg)

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
        if (is_EAGAIN_WOULDBLOCK(err) || err == EINTR)
            return 0;
        protocol_trace(s, "send() error: %s", strerror(err));
        return -err;
    }
    s->out_queue.rd_pos += sent; /* sent verified to be >= 0 */

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
    ssize_t res = 0;

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
            if (is_EAGAIN_WOULDBLOCK(err))
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
        ssize_t res;

        do {
            res = recv(s->socket, NULL, s->in_queue.wr_pos_reserved,
                       MSG_DONTWAIT | MSG_TRUNC);
        } while (res == -1 && errno == EINTR);
        if (res == -1) {
            int err = errno;
            if (is_EAGAIN_WOULDBLOCK(err))
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
    ssize_t rcvres;

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
        rcvres = recv(s->socket, s->in_queue.buffer + s->in_queue.wr_pos, object_size, MSG_DONTWAIT);
    } while (rcvres == -1 && errno == EINTR);
    if (rcvres == -1) {
        int err = errno;
        if (is_EAGAIN_WOULDBLOCK(err))
            return 0;
        protocol_trace(s, "tcpaq_request: recv() error: %s", strerror(err));
        return -err;
    }
    s->in_queue.wr_pos += rcvres; /* recv() ensures 0 <= rcvres <= wr_pos */
    object_size -= rcvres;  /* recv() ensures 0 <= rcvres <= wr_pos */

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

/*
 * First value returned on program start must be 1, not zero.
 * Must wrap around UINT32_MAX+1 to zero.
 *
 * note: C11 atomics are probably not available in openwrt 15.05;
 * FIXME: if we ever go multithreaded, deal with this! */
static uint32_t get_uptime2_seqnumber(void)
{
    static uint32_t uptime2_seqnumber = 0;

    uptime2_seqnumber++;

    return uptime2_seqnumber;
}
static void xx_json_object_seqnum_add(struct json_object * const j)
{
    json_object_object_add(j, "seqnum",
                    json_object_new_int64(get_uptime2_seqnumber()));
}

static void xx_set_tcp_timeouts(struct simet_inetup_server * const s)
{
    /* The use of SO_SNDTIMEO for blocking connect() timeout is not
     * mandated by POSIX and it is implemented only in [non-ancient]
     * Linux
     *
     * FIXME: now that we're doing non-blocking connect(), we could
     * implement it explicitly ourselves, perhaps in addition to using
     * this.
     */
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
        protocol_msg(MSG_IMPORTANT, s, "internal error: tried to send too large a message, discarded it instead");
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
        protocol_msg(MSG_IMPORTANT, s, "recvmsg: message too large (%u bytes), sync might have been lost",
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

    if (s->client_seqnum_enabled)
        xx_json_object_seqnum_add(jroot);

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
                    protocol_msg(MSG_DEBUG, s, "ma_config: set %s to %u", param_name, *param);
                }
                return 1;
            }
        }
        protocol_msg(MSG_NORMAL, s, "ma_config: invalid %s: %s",
                      param_name, json_object_to_json_string(jo));
        return -EINVAL;
    }

    return 0;
}

static int xx_maconfig_getstr(struct simet_inetup_server * const s,
                        struct json_object * const jconf,
                        const char * const param_name,
                        const char * * const param)
{
    struct json_object *jo;

    if (json_object_object_get_ex(jconf, param_name, &jo)) {
        if (json_object_is_type(jo, json_type_string)) {
            errno = 0;
            const char *val = json_object_get_string(jo);
            if (errno == 0) {
                if (!xstrcmp(val, *param)) {
                    return 1;
                }
                if (val) {
                    val = strdup(val);
                    if (!val)
                        return -ENOMEM;
                }
                free_constchar(*param);
                *param = val;
                return 2;
            }
        }
        protocol_msg(MSG_NORMAL, s, "ma_config: invalid %s: %s",
                      param_name, json_object_to_json_string(jo));
        return -EINVAL;
    }

    return 0;
}

/*
 * MA_CONFIG message:
 *
 * { "config": {
 *   "capabilities-enabled": [ "..." ],
 *   "client-timeout-seconds": 60,
 *   "server-timeout-seconds": 60,
 *   "measurement-period-seconds": 300,
 *   "uptime-group": "<uptime availability group>",
 *   "server-hostname": "<hostname>",
 *   "server-description": "<description for this server>"
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
        s->client_seqnum_enabled = 0;

        /* set any capabilities we know about, warn of others */
        al = json_object_array_length(jo);
        while (--al >= 0) {
            const char *cap = json_object_get_string(json_object_array_get_idx(jo, al));
            if (!strcasecmp("server-keepalive", cap)) {
                /* this one we should enable even if we did not request it */
                s->remote_keepalives_enabled = 1;
            } else if (!strcasecmp("client-seqnum-v1", cap)) {
                s->client_seqnum_enabled = 1;
            /* else if (!strcasecmp("other key", cap)) ... */
            } else {
                protocol_trace(s, "ma_config: ignoring capability %s", cap ? cap : "(empty)");
            }
        }
    }

    if (xx_maconfig_getuint(s, jconf, "client-timeout-seconds", &s->client_timeout, 0, 86400) > 0)
        xx_set_tcp_timeouts(s);
    xx_maconfig_getuint(s, jconf, "server-timeout-seconds", &s->server_timeout, 0, 86400);
    xx_maconfig_getuint(s, jconf, "measurement-period-seconds", &s->measurement_period, 0, 86400);

    if (xx_maconfig_getstr(s, jconf, "server-hostname", &s->server_hostname) > 0
            && s->server_hostname) {
        protocol_msg(MSG_DEBUG, s, "ma_config: measurement peer hostname is \"%s\"", s->server_hostname);
    }
    if (xx_maconfig_getstr(s, jconf, "server-description", &s->server_description) > 0
            && s->server_description) {
        protocol_msg(MSG_DEBUG, s, "ma_config: measurement peer description is \"%s\"", s->server_description);
    }
    if (xx_maconfig_getstr(s, jconf, "cluster-hostname", &s->s_cluster_hostname) > 0
            && s->s_cluster_hostname) {
        protocol_msg(MSG_DEBUG, s, "ma_config: measurement peer cluster is \"%s\"", s->s_cluster_hostname);
    }

    /* FIXME: it would be nice to actually cause a connection drop if uptime-group
     * can't be correctly processed, but returning an error here isn't enough */
    const char *new_sg = NULL;
    if (xx_maconfig_getstr(s, jconf, "uptime-group", &new_sg) > 1) {
        if (!s->uptime_group) {
            s->uptime_group = new_sg;
        } else {
            protocol_msg(MSG_IMPORTANT, s, "measurement peer tried to change availability group from \"%s\" to \"%s\", ignoring",
                    s->uptime_group, new_sg ? new_sg : "(none)");
            free_constchar(new_sg);
        }
    }
    if (s->uptime_group) {
        protocol_msg(MSG_DEBUG, s, "ma_config: availability group set to \"%s\"", s->uptime_group);
    }

    if (s->ma_config_count < 2)
        s->ma_config_count++;
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
 * { "events": [ { "name": "<event>", "timestamp-seconds": <event timestamp> }, ... ],
 *   "seqnum": <seqnum> (optional) }
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
        protocol_trace(s, "events: received measurement peer event \"%s\"", event_name);

        /* handle events */
        if (!strcmp(event_name, "mp_disconnect")) {
            /* server told us to disconnect, and not reconnect back for a while */
            protocol_msg(MSG_NORMAL, s, "measurement peer closing connection... trying to change to another peer");
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
        protocol_trace(s, "events: ignoring invalid message: %s",
                      json_tokener_error_desc(json_tokener_get_error(jtok)));
    } else if (res > 1) {
        protocol_trace(s, "events: received malformed message");
    }
    json_tokener_free(jtok);
    if (jroot)
        json_object_put(jroot);
    return res;
}

static int simet_uptime2_msghdl_serverdisconnect(struct simet_inetup_server * const s,
                    const struct simet_inetup_msghdr * const hdr __attribute__((__unused__)),
                    const void * const data __attribute__((__unused__)) )
{
    protocol_msg(MSG_IMPORTANT, s, "received global disconnection message from measurement peer");
    got_disconnect_msg = 1;
    return 1;
}

/* State: WAITCONFIG, MAINLOOP */
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
     *
     * Protocol v2: msg-measurement capability
     *    - client will send MEASUREMENT messages when needed
     *    - client processes optional measurement-period-seconds
     *      parameter in MA_CONFIG
     *
     * Protocol v2: timestamp-zero-at-boot
     *    - client timestamp has its zero at device boot
     *
     * Protocol v2: client-seqnum-v1 capability
     *    - client will add client-sequence-number fields to:
     *      CONNECT, MEASUREMENT, EVENTS
     *      the sequence number is global to the client, and strictly
     *      monotonic [until wraparound / client restart].
     *      It wraps at UINT32_MAX to 0.
     *    - client will stop tracking/sending sequence numbers to
     *      an connection after it receives a ma_config message
     *      removing the client-seqnum-v1 capability.  Note that this
     *      could come later after a few messages have already been sent.
     */
    if (simet_uptime2_request_remotekeepalive) {
        json_object_array_add(jcap, json_object_new_string("server-keepalive"));
    }
    json_object_array_add(jcap, json_object_new_string("msg-disconnect"));
    json_object_array_add(jcap, json_object_new_string("msg-measurement"));
    if (client_boot_sync) {
        json_object_array_add(jcap, json_object_new_string("timestamp-zero-at-boot"));
    }
    if (s->client_seqnum_enabled) {
        json_object_array_add(jcap, json_object_new_string("client-seqnum-v1"));
    }
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

    /* always add a sequence number to the CONNECT message */
    xx_json_object_seqnum_add(jo);

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
    if (s && s->state == SIMET_INETUP_P_C_MAINLOOP && s->measurement_period) {
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
 * ], "seqnum": <seqnum> (optional) }
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
    json_object_object_add(jo, "timestamp-seconds", json_object_new_int64(t2_s + client_boot_offset));
    json_object_object_add(jo, "timestamp-microseconds-since-second", json_object_new_int64(t2_us));
    json_object_object_add(jo, "since-timestamp-seconds", json_object_new_int64(t1_s + client_boot_offset));
    json_object_object_add(jo, "since-timestamp-microseconds-since-second", json_object_new_int64(t1_us));
    json_object_object_add(jo, "tx_delta_bytes", json_object_new_int64(idtx));
    json_object_object_add(jo, "rx_delta_bytes", json_object_new_int64(idrx));

    if (json_object_array_add(jarray, jo))
        goto err_exit;
    jo = NULL;

    json_object_object_add(jroot, "measurements", jarray);
    jarray = NULL;

    if (s->client_seqnum_enabled)
        xx_json_object_seqnum_add(jroot);

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

    if (clock_gettime(clockid, &m_wantxrx_data.last_t) ||
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

    if (os_get_netdev_counters(&tx, &rx, m_wantxrx_data.sys_context) || clock_gettime(clockid, &now))
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
        if (s->backoff_level) {
            protocol_msg(MSG_NORMAL, s, "will attempt to reconnect after %u seconds", backoff_times[s->backoff_level]);
        } else {
            protocol_msg(MSG_NORMAL, s, "attempting to reconnect...");
        }
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

        protocol_msg(MSG_NORMAL, s, "client disconnecting...");
    }
}

/* call this after we are sure the server likes us */
static void simet_uptime2_backoff_reset(struct simet_inetup_server * const s)
{
    s->backoff_level = 0;
    s->backoff_reset_clock = 0;
}

/* send keepalive message to remote */
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

static int xx_nameinfo(struct sockaddr_storage *sa, socklen_t sl,
                        sa_family_t *family, const char **hostname, const char **hostport)
{
    char namebuf[256] = "unknown";
    char portbuf[32]  = "unknown";
    sa_family_t af = AF_UNSPEC;

    if (sa->ss_family != AF_UNSPEC && !getnameinfo((struct sockaddr *)sa, sl,
                                                   namebuf, sizeof(namebuf), portbuf, sizeof(portbuf),
                                                   NI_NUMERICHOST | NI_NUMERICSERV)) {
        af = sa->ss_family;
    }

    if (!(*hostname) || strncmp(namebuf, *hostname, sizeof(namebuf))) {
        free_constchar(*hostname);
        *hostname = strdup(namebuf);
    }
    if (!(*hostport) || strncmp(portbuf, *hostport, sizeof(portbuf))) {
        free_constchar(*hostport);
        *hostport = strdup(portbuf);
    }
    *family = af;

    return (af != AF_UNSPEC)? 0 : 1;
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

static int uptimeserver_connect_init(struct simet_inetup_server * const s,
                       const char * const server_name, const char * const server_port)
{
    struct addrinfo ai;
    int backoff;
    int r;

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

    protocol_trace(s, "attempting connection to cluster %s, port %s", server_name, server_port);

    s->connect_timestamp = 0;

    /* per-server configuration data defaults */
    s->server_timeout = SIMET_UPTIME2_DEFAULT_TIMEOUT;
    s->client_timeout = simet_uptime2_tcp_timeout;
    s->measurement_period = SIMET_UPTIME2_DFL_MSR_PERIOD;
    s->remote_keepalives_enabled = 0;
    s->client_seqnum_enabled = 1;
    free_constchar(s->uptime_group);
    s->uptime_group = NULL;
    free_constchar(s->server_description);
    s->server_description = NULL;

    /* cleanup any leftover data from previous attempts */
    if (s->peer_gai) {
        freeaddrinfo(s->peer_gai);
        s->peer_gai = NULL;
        s->peer_ai = NULL;
    }

    memset(&ai, 0, sizeof(ai));
    ai.ai_flags = AI_ADDRCONFIG;
    ai.ai_socktype = SOCK_STREAM;
    ai.ai_family = s->ai_family;
    ai.ai_protocol = IPPROTO_TCP;

    r = getaddrinfo(server_name, server_port, &ai, &s->peer_gai);
    if (r != 0) {
        protocol_trace(s, "getaddrinfo() returned %s", gai_strerror(r));
        return backoff;
    }

    s->peer_ai = s->peer_gai;

    if (!s->peer_gai) {
        protocol_trace(s, "successfull getaddrinfo() with an empty result set!");
        return backoff;
    }

    s->state = SIMET_INETUP_P_C_CONNECT;
    return 0;
}

static int uptimeserver_connect(struct simet_inetup_server * const s)
{
    int connected = 0;
    int r;

    const int int_one = 1;

    assert(s && s->state == SIMET_INETUP_P_C_CONNECT);

    while (s->socket == -1 && s->peer_ai != NULL) {
        struct addrinfo * const airp = s->peer_ai;

        /* avoid fast reconnect to same peer */
        if (s->peer_noconnect_ttl && xx_cmpnameinfo(airp, s->ai_family, s->peer_name)) {
            protocol_trace(s, "skipping peer %s on this attempt", s->peer_name);

            s->peer_ai = s->peer_ai->ai_next;
            continue;
        }

        s->socket = socket(airp->ai_family,
                           airp->ai_socktype | SOCK_CLOEXEC | SOCK_NONBLOCK,
                           airp->ai_protocol);
        if (s->socket == -1) {
            s->peer_ai = s->peer_ai->ai_next;
            continue;
        }

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

        /*
         * connect() can be hard outside of Linux, basically, we cannot
         * portably deal with EINTR.  The only sane path needs a close(),
         * and this is the only reason this whole loop had to be complex
         *
         * http://cr.yp.to/docs/connect.html
         * http://www.madore.org/~david/computers/connect-intr.html
         */
        r = connect(s->socket, airp->ai_addr, airp->ai_addrlen);
        if (!r) {
            connected = 1;
            break; /* connected immediately */
        }
        if (errno == EINPROGRESS) {
            if (log_level >= MSG_TRACE) {
                char namebuf[256], portbuf[32];
                if (!getnameinfo(airp->ai_addr, airp->ai_addrlen,
                               namebuf, sizeof(namebuf), portbuf, sizeof(portbuf),
                               NI_NUMERICHOST | NI_NUMERICSERV)) {
                    protocol_trace(s, "attempting connection to measurement peer %s port %s", namebuf, portbuf);
                }
            }
            break; /* trying to connect */
        }

        if (errno == EINTR) {
            /* redo loop without advancing */
            close(s->socket);
            s->socket = -1;
            continue;
        }

        close(s->socket);
        s->socket = -1;
        s->peer_ai = s->peer_ai->ai_next;
    }

    if (s->socket == -1) {
        if (s->peer_noconnect_ttl)
            s->peer_noconnect_ttl--;

        const int waittime_left = timer_check(s->backoff_clock, backoff_times[s->backoff_level]);
        if (waittime_left > 0)
            protocol_trace(s, "could not connect, will retry in %d seconds", waittime_left);

        /* go back to the previous state, so that we getaddrinfo() again */
        s->state = SIMET_INETUP_P_C_RECONNECT;
        return (waittime_left > 0)? waittime_left : 0;
    }

    if (connected) {
        s->state = SIMET_INETUP_P_C_CONNECTED;
        return 0;
    }

    s->state = SIMET_INETUP_P_C_CONNECTWAIT;
    return (int) simet_uptime2_tcp_timeout;
}

static int uptimeserver_connectwait(struct simet_inetup_server * const s)
{
    int socket_err;
    socklen_t socket_err_sz = sizeof(socket_err);
    int r;

    assert(s && s->state == SIMET_INETUP_P_C_CONNECTWAIT);

    if (s->socket == -1 || !s->peer_ai) {
        /* should never happen, recover */
        s->state = SIMET_INETUP_P_C_RECONNECT;
        return 0;
    }

    /* We could hit this codepath before poll() returned ready for writing or an error */
    struct pollfd pfd = {
        .fd     = s->socket,
        .events = POLLOUT | POLLERR | POLLRDHUP | POLLHUP,
    };
    do {
        r = poll(&pfd, 1, 0);
    } while (r == -1 && errno == EINTR);
#if 0
    protocol_trace(s, "connectwait: pollfd.fd = %d, pollfd.events = 0x%04x, pollfd.revents = 0x%04x",
                   pfd.fd, (unsigned int)pfd.events, (unsigned int)pfd.revents);
#endif
    if (pfd.revents == 0)
        return (int) simet_uptime2_tcp_timeout; /* FIXME: timeout accounting? */

    /* Detect if a pending connect() failed, modern version.
     *
     * Portability hazard:
     * http://cr.yp.to/docs/connect.html
     * http://www.madore.org/~david/computers/connect-intr.html
     */
    if (getsockopt(s->socket, SOL_SOCKET, SO_ERROR, &socket_err, &socket_err_sz))
        socket_err = errno;
    switch (socket_err) {
    case 0:
    case EISCONN:
        /* socket connected */
        s->state = SIMET_INETUP_P_C_CONNECTED;
        break;
    case EALREADY:
    case EINPROGRESS:
        /* Unusual, poll().revents == 0 above is the normal path for this */
        protocol_trace(s, "connectwait: still waiting for connection to complete");
        /* FIXME: timeout accounting explicitly ? */
        return (int) simet_uptime2_tcp_timeout;
    default:
        protocol_trace(s, "connection attempt failed: %s", strerror(socket_err));

        /* connection attempt failed */
        s->peer_ai = s->peer_ai->ai_next;
        close(s->socket);
        s->socket = -1;

        /* go back to the previous state, to loop */
        s->state = SIMET_INETUP_P_C_CONNECT;
    }

    return 0;
}

static int uptimeserver_connected(struct simet_inetup_server * const s)
{
    const int int_one = 1;
    struct sockaddr_storage sa;
    socklen_t sa_len;

    /* Get metadata of the connected socket */
    sa_len = sizeof(struct sockaddr_storage);
    sa.ss_family = AF_UNSPEC;
    if (getpeername(s->socket, (struct sockaddr *)&sa, &sa_len)) {
        /* Resilience: ENOTCON here is sometimes the only thing that works */
        if (errno == ENOTCONN) {
            protocol_trace(s, "connect: late detection of connection failure");
            /* connection attempt failed */
            s->peer_ai = s->peer_ai->ai_next;
            close(s->socket);
            s->socket = -1;

            /* go back to the previous state, to loop */
            s->state = SIMET_INETUP_P_C_CONNECT;
            return 0;
        }
        protocol_trace(s, "connect: getpeername failed: %s", strerror(errno));
    }
    if (xx_nameinfo(&sa, sa_len, &s->peer_family, &s->peer_name, &s->peer_port))
        print_warn("failed to get peer metadata, coping with it");
    s->peer_noconnect_ttl = 0;

    sa_len = sizeof(struct sockaddr_storage);
    sa.ss_family = AF_UNSPEC;
    if (getsockname(s->socket, (struct sockaddr *)&sa, &sa_len) ||
        xx_nameinfo(&sa, sa_len, &s->local_family, &s->local_name, &s->local_port))
        print_warn("failed to get local metadata, coping with it");

    /* Disable Naggle, we don't need it (but we can tolerate it) */
    setsockopt(s->socket, IPPROTO_TCP, TCP_NODELAY, &int_one, sizeof(int_one));

    /* done... */
    s->connect_timestamp = reltime();
    if (s->cluster) {
        protocol_msg(MSG_NORMAL, s, "connect: connected over %s to measurement peer cluster %s, port %s",
               str_ipv46(s->local_family), s->cluster->cluster_name, s->cluster->cluster_port);
    }
    protocol_msg(MSG_NORMAL, s, "connect: local %s address [%s]:%s, remote %s address [%s]:%s",
                  str_ipv46(s->local_family), s->local_name, s->local_port,
                  str_ipv46(s->peer_family), s->peer_name, s->peer_port);

    if (s->peer_gai)
        freeaddrinfo(s->peer_gai);
    s->peer_gai = NULL;
    s->peer_ai = NULL;

    /* try to send first message to server */
    if (simet_uptime2_msg_maconnect(s)) {
        simet_uptime2_reconnect(s);
        return 0;
    }

    /* start tracking server keepalives for timeout */
    simet_uptime2_keepalive_update(s);
    s->backoff_reset_clock = reltime();

    s->state = SIMET_INETUP_P_C_WAITCONFIG;
    return 0;
}

static int uptimeserver_waitconfig(struct simet_inetup_server * const s)
{
    assert(s);
    assert(s->state == SIMET_INETUP_P_C_WAITCONFIG);

    if (s->ma_config_count < 1)
        return INT_MAX;

    s->state = SIMET_INETUP_P_C_MAINLOOP;
    /* do this only after s->state is set to MAINLOOP */
    propose_as_telemetry_server(s);

    /* FIXME: this is correct, but not being done the right way */
    if (simet_uptime2_msg_clientlifetime(s, 1))
        simet_uptime2_reconnect(s);
    else if (simet_uptime2_msg_link(s, 1))
        simet_uptime2_reconnect(s);

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

        protocol_msg(MSG_IMPORTANT, s, "client disconnected");

        s->state = SIMET_INETUP_P_C_SHUTDOWN;
        return 0;
    }

    return rc;
}

static void uptimeserver_destroy(struct simet_inetup_server *s)
{
    if (s) {
        if (s->socket != -1) {
            tcpaq_close(s);
            s->socket = -1;
            protocol_msg(MSG_IMPORTANT, s, "client forcefully disconnected");
        }

        free(s->out_queue.buffer);
        free(s->in_queue.buffer);

        if (s->peer_gai)
            freeaddrinfo(s->peer_gai);

        free_constchar(s->peer_name);
        free_constchar(s->peer_port);
        free_constchar(s->local_name);
        free_constchar(s->local_port);

        free_constchar(s->uptime_group);
        free_constchar(s->server_hostname);
        free_constchar(s->server_description);
        free_constchar(s->s_cluster_hostname);

        free(s);
    }
}

static int uptimeserver_create(struct simet_inetup_server ** const sp,
                               const sa_family_t ai_family,
                               const struct simet_inetup_server_cluster * const sc)
{
    static unsigned int next_connection_id = 1;

    struct simet_inetup_server *s;

    if (!sp || !sc || (ai_family != AF_INET && ai_family != AF_INET6))
        return -EINVAL;

    /* this zero-fills the allocated data area */
    s = calloc(1, sizeof(struct simet_inetup_server));
    if (!s)
        return -ENOMEM;

    s->socket = -1;
    s->state = SIMET_INETUP_P_C_INIT;
    s->ai_family = ai_family;
    s->connection_id = next_connection_id;
    s->cluster = sc;
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
 * server clusters
 */

static struct simet_inetup_server_cluster * server_cluster_create(const char * const hostname, const char * const port)
{
    struct simet_inetup_server_cluster *sc;

    if (!hostname)
        return NULL;

    /* malloc and zero-fill */
    sc = calloc(1, sizeof(struct simet_inetup_server_cluster));
    if (!sc)
        return NULL;

    sc->cluster_name = hostname;
    sc->cluster_port = port;
    return sc;
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

static void print_usage(const char * const p, int mode) __attribute__((__noreturn__));
static void print_usage(const char * const p, int mode)
{
    fprintf(stderr, "Usage: %s [-q] [-v] [-h] [-V] [-t <timeout>] [-i <netdev> ] "
        "[-d <agent-id-path> ] [-m <string>] [-b <boot id>] [-j <token-path> ] [-M <string>] "
        "<server name>[:<server port>] ...\n", p);

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
            "\t-i\tpath to a file with network devices to monitor for amount of traffic\n"
            "\n"
            "server name: DNS name of server(s)\n"
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

static int cmdln_parse_server(char *name, struct simet_inetup_server_cluster ***ps)
{
    struct simet_inetup_server_cluster *ne = NULL;
    char *hostname = NULL;
    char *port = NULL;
    char *r;

    assert(ps && *ps);

    while (*name && isspace(*name))
        name++;

    if (!*name)
        return 1;

    r = name;

    /* handle IPv6 [<ip address>]:<port> */
    /* FIXME: this is lax, accepts [<dns hostname>] as well, and [<ipv4>], etc */
    if (*name == '[') {
        name++;
        r = strchr(name, ']');
        if (!r)
            goto err_exit;

        hostname = strndup_trim(name, r - name);
        r++;

        if (*r && *r != ':') {
            while (*r && isspace(*r))
                r++;
            if (*r)
                goto err_exit;
            r = NULL;
        }
    } else {
        r = strrchr(r, ':');
        if (r) {
            hostname = strndup_trim(name, r - name);
        } else {
            hostname = strdup_trim(name);
        }
    }

    if (r) {
        /* parse optional :<port> */
        r++;
        if (!*r)
            goto err_exit;
        port = strdup_trim(r);
    }

    if (!hostname)
        goto err_exit;

    if (!port) {
        port = strdup(SIMET_UPTIME2_DEFAULT_PORT);
        if (!port)
            goto err_exit;
    }

    ne = server_cluster_create(hostname, port);
    if (!ne)
        goto err_exit;

    **ps = ne;
    *ps = &(ne->next);

    return 0;

err_exit:
    free(ne);
    free(hostname);
    free(port);
    return 1;
}

static void free_server_structures(struct simet_inetup_server ***as, unsigned int *as_len)
{
    assert(as && as_len);
    if (*as) {
        for (unsigned int i = 0; i < *as_len; i++) {
            uptimeserver_destroy((*as)[i]);
        }
        free(*as);
        *as = NULL;
    }
    *as_len = 0;
}

static int init_server_structures(struct simet_inetup_server_cluster * const asc,
                       struct simet_inetup_server ***pservers,
                       unsigned int *pservers_count)
{
    struct simet_inetup_server_cluster *sc;
    struct simet_inetup_server **asrv = NULL;
    unsigned int nservers = 0;
    unsigned int i;

    assert(pservers && pservers_count);

    for (sc = asc; sc != NULL; sc = sc->next)
        nservers += 2; /* one IPv4 and one IPv6 server per cluster */
    if (nservers <= 0) {
        free_server_structures(pservers, pservers_count);
        return 0;
    }

    asrv = calloc(nservers, sizeof(struct simet_inetup_server *));
    if (!asrv)
        return -ENOMEM;

    for (sc = asc, i = 0; sc != NULL && i < nservers; sc = sc->next) {
        print_msg(MSG_NORMAL, "measurement cluster: %s port %s", sc->cluster_name, sc->cluster_port);
        if (uptimeserver_create(&(asrv[i++]), AF_INET, sc) ||
            uptimeserver_create(&(asrv[i++]), AF_INET6, sc))
            goto err_nomemexit; /* -EINVAL should be impossible: as long as we exit, it is fine */
    }

    free_server_structures(pservers, pservers_count);
    *pservers = asrv;
    *pservers_count = nservers;
    return 0;

err_nomemexit:
    free_server_structures(&asrv, &nservers);

    return -ENOMEM;
}

static void ml_update_wait(int * const pwait, const int nwait)
{
    if (nwait >= 0 && nwait < *pwait)
        *pwait = nwait;
}

int main(int argc, char **argv) {
    int intarg;

    progname = argv[0];
    sanitize_std_fds();

    init_timekeeping();
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

    if (optind >= argc)
        print_usage(progname, 0);

    struct simet_inetup_server_cluster **ps = &server_clusters;
    while (optind < argc) {
        if (cmdln_parse_server(argv[optind], &ps)) {
            print_err("incorrect server name or port: %s", argv[optind] ? argv[optind] : "(NULL)");
            print_usage(progname, 0);
        }
        optind++;
    }

    if (!server_clusters) {
        print_err("at least one server is required");
        print_usage(progname, 0);
    }

    init_signals();

    print_msg(MSG_ALWAYS, PACKAGE_NAME " " PACKAGE_VERSION " starting...");

    /* init */

    log_timekeeping_state();

    if (init_server_structures(server_clusters, &servers, &servers_count) < 0)
        goto err_enomem;

    struct pollfd *servers_pollfds = calloc(servers_count, sizeof(struct pollfd));

    if (load_agent_data(agent_id_file, agent_token_file)) {
        print_err("failed to read agent identification credentials");
        return SEXIT_FAILURE;
    }
    if (load_netdev_file(monitor_netdev_file)) {
        print_err("failed to read network device name to monitor, disabling functionality");
    }

    simet_uptime2_measurements_global_init();

    print_msg(MSG_ALWAYS, "connecting to measurement peers...");

    /* state machine loop */
    do {
        time_t minwait = 300;
        unsigned int j, num_shutdown;
        int queued_msg_disconnect;
        int queued_full_resync;

        num_shutdown = 0;

        queued_full_resync = !!(timekeeping_needs_resync());
        if (queued_full_resync) {
            /* we will *have* to force-disconnect everything in the next pass */
            print_msg(MSG_IMPORTANT, "resync due to system sleep required, forcing global disconnection");
            init_timekeeping();
            log_timekeeping_state();
        }

        /* safe semanthics if it is ever made volatile/MT
         * if a resync is pending, resync first */
        queued_msg_disconnect = 0;
        if (!queued_full_resync && got_disconnect_msg) {
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
                assert(s->socket == -1 && s->out_queue.buffer && s->in_queue.buffer && s->cluster);
                servers_pollfds[j].fd = -1;
                /* fall-through */
            case SIMET_INETUP_P_C_RECONNECT:
                if (queued_full_resync) {
                    /* resync before reconnecting */
                    wait = 0;
                    break;
                }
                if (queued_msg_disconnect) {
                    s->backoff_level = BACKOFF_LEVEL_MAX-1;
                    s->backoff_clock = reltime();
                    protocol_trace(s, "global disconnect: will attempt to reconnect in %u seconds",
                            backoff_times[s->backoff_level]);
                }
                wait = uptimeserver_connect_init(s, s->cluster->cluster_name, s->cluster->cluster_port);
                servers_pollfds[j].fd = -1;
                break;
            case SIMET_INETUP_P_C_CONNECT:
                wait = uptimeserver_connect(s);
                servers_pollfds[j].fd = s->socket;
                servers_pollfds[j].events = POLLRDHUP | POLLIN | POLLOUT | POLLERR;
                break;
            case SIMET_INETUP_P_C_CONNECTWAIT:
                wait = uptimeserver_connectwait(s);
                break;
            case SIMET_INETUP_P_C_CONNECTED:
                wait = uptimeserver_connected(s);
                servers_pollfds[j].events = POLLRDHUP | POLLIN;
                break;
            case SIMET_INETUP_P_C_WAITCONFIG:
                if (queued_full_resync) {
                    simet_uptime2_reconnect(s);
                    wait = 0;
                    break;
                }
                if (queued_msg_disconnect) {
                    /* FIXME: queue a server-told-us-to-disconnect event to report later */
                    s->backoff_level = BACKOFF_LEVEL_MAX-1;
                    simet_uptime2_reconnect(s);
                    wait = 0;
                    break;
                }

                /* process return channel messages, we want MA_CONFIG */
                while (simet_uptime2_recvmsg(s, simet_uptime2_messages_mainloop) > 0);

                if (got_disconnect_msg)
                    break;

                if (!uptimeserver_remotetimeout(s)) {
                    /* remote keepalive timed out */
                    protocol_msg(MSG_NORMAL, s, "measurement peer connection lost: ma_config not received");
                    simet_uptime2_reconnect(s);
                    wait = 0;
                    break;
                }

                wait = uptimeserver_waitconfig(s);
                break;
            case SIMET_INETUP_P_C_MAINLOOP:
                if (queued_full_resync) {
                    simet_uptime2_reconnect(s);
                    wait = 0;
                    break;
                }
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
                    protocol_msg(MSG_NORMAL, s, "measurement peer connection lost: silent for too long");
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
                        if (servers[j]->state >= SIMET_INETUP_P_C_CONNECTED
                            && servers[j]->state < SIMET_INETUP_P_C_SHUTDOWN)
                        {
                            /* ugly, but less ugly than having reconnect close the socket immediately */
                            protocol_msg(MSG_NORMAL, servers[j], "connection to measurement peer lost");
                            simet_uptime2_reconnect(servers[j]); /* fast close/shutdown detection */
                        }
                        servers_pollfds[j].fd = -1;
                    } else if (servers_pollfds[j].revents & POLLNVAL) {
                        /* We screwed up and left an outdated socket in pollfds */
                        protocol_trace(servers[j], "internal error: POLLNVAL: state[%u]=%u, fd=%d, events=0x%04x, revents=0x%04x",
                            j, servers[j]->state, servers_pollfds[j].fd,
                            (unsigned int)servers_pollfds[j].events,
                            (unsigned int)servers_pollfds[j].revents);
                        /* Work around the bug */
                        servers_pollfds[j].fd = -1;
                    } else if (servers_pollfds[j].revents & ~(POLLIN|POLLOUT)) {
                        protocol_trace(servers[j],
                            "unhandled: state=%u, pollfd[%u].fd=%d, .events=0x%04x, .revents=0x%04x",
                            servers[j]->state, j, servers_pollfds[j].fd,
                            (unsigned int)servers_pollfds[j].events,
                            (unsigned int)servers_pollfds[j].revents);
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

err_enomem:
    print_err("out of memory");
    return SEXIT_OUTOFRESOURCE;
}

/* vim: set et ts=4 sw=4 : */
