/*
 * SIMET2 MA Internet Availability Measurement (inetup) client
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

#include "simet-inetuptime_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <limits.h>
#include <string.h>
#include <getopt.h>
#include <assert.h>

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
#include "logger.h"

#ifdef HAVE_JSON_JSON_H
#include <json/json.h>
#elif HAVE_JSON_C_JSON_H
#include <json-c/json.h>
#else
#include <json.h>
#endif

static struct simet_inetup_server **servers = NULL;
static const char *agent_id = NULL;
static const char *agent_token = NULL;
static const char *boot_id = NULL;
static const char *agent_mac = NULL;
static const char *task_name = NULL;

static int simet_uptime2_keepalive_interval = 30; /* seconds */
static int simet_uptime2_tcp_timeout = 60; /* seconds, for data to be ACKed as well as connect() */

static time_t client_start_timestamp;

static volatile int got_exit_signal = 0;    /* SIGTERM, SIGQUIT */
static volatile int got_reload_signal = 0;  /* SIGHUP */

#define BACKOFF_LEVEL_MAX 8
static const unsigned int backoff_times[BACKOFF_LEVEL_MAX] =
    { 1, 10, 10, 30, 30, 60, 60, 300 };

/* events that can tolerate it, will oportunistically fire if called within
 * TIMERFUZZ seconds interval before they are scheduled to fire */
#define SIMET_INETUP_TIMERFUZZ 5

/* time we wait to flush queue to kernel before we drop it during disconnect */
#define SIMET_DISCONNECT_WAIT_TIMEOUT 5

/*
 * helpers
 */

static time_t reltime(void)
{
    struct timespec now;

    if (!clock_gettime(CLOCK_MONOTONIC, &now)) {
        return (now.tv_sec > 0)? now.tv_sec : 0;  /* this helps the optimizer and squashes several warnings */
    } else {
        ERROR_LOG("clock_gettime(CLOCK_MONOTONIC) returned an error!");
        /* FIXME: consider abort(EXIT_FAILURE) */
        return 0; /* kaboom! most likely :-( */
    }
}

/* returns: 0 = expired, otherwise seconds left to time out
 * written for clarity, and no integer overflows */
static time_t timer_check(const time_t timestamp, const time_t rel_timeout)
{
    if (timestamp <= 0 || rel_timeout <= 0)
        return 0; /* timer expired as fail-safe */
    const time_t now = reltime();
    if (now < timestamp)
        return 0; /* timer expired due to wrap or timestamp in the future */
    const time_t now_rel = now - timestamp;
    return (rel_timeout > now_rel)? rel_timeout - now_rel : 0;
}

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

#define TRACE_LOG(s, ...) \
    do { LOG_MESSAGE(stderr, "TRACE"); \
         fprintf(stderr, "%s(%u)@%lds: ", str_ip46(s->ai_family), s->connection_id, (long int)reltime() - client_start_timestamp); \
         fprintf(stderr, __VA_ARGS__); \
         fprintf(stderr, "\n"); \
    } while(0)

#if 0
static struct json_object * xx_json_object_new_in64_as_str(const int64_t v)
{
    char buf[32];
    snprintf(buf, sizeof(buf), "%" PRIi64, v);
    return json_object_new_string(buf);
}
#endif


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
        WARNING_LOG("failed to set signal handlers, precision during restarts will suffer");

    sa.sa_handler = &handle_reloadsig;
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGHUP, &sa, NULL))
        WARNING_LOG("failed to set SIGHUP handler");
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
 */

static void tcpaq_close(struct simet_inetup_server * const s)
{
    assert(s);
    if (s->socket != -1) {
        shutdown(s->socket, SHUT_RDWR);
        close(s->socket);
        s->socket = -1;
    }
    s->queue.rd_pos = 0;
    s->queue.wr_pos = 0;
    s->queue.wr_pos_reserved = 0;
}

static int tcpaq_reserve(struct simet_inetup_server * const s, size_t size)
{
    assert(s);

    /* paranoia */
    if (s->queue.wr_pos >= s->queue.wr_pos_reserved)
        s->queue.wr_pos_reserved = s->queue.wr_pos;

    if (s->queue.wr_pos_reserved + size >= s->queue.buffer_size)
        return -ENOSPC;

    s->queue.wr_pos_reserved += size;
    return 0;
}

static void tcpaq_unreserve(struct simet_inetup_server * const s, size_t size)
{
    assert(s);
    if (s->queue.wr_pos_reserved > s->queue.wr_pos + size)
        s->queue.wr_pos_reserved -= size;
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
    assert(s && s->queue.buffer);

    if (!size)
        return 0;
    if (!reserved && tcpaq_reserve(s, size))
        return -ENOSPC;
    if (s->queue.wr_pos + size >= s->queue.buffer_size)
        return -ENOSPC; /* defang the bug */

    memcpy(&s->queue.buffer[s->queue.wr_pos], data, size);
    s->queue.wr_pos += size;

    if (s->queue.wr_pos > s->queue.wr_pos_reserved) {
        WARNING_LOG("internal error: stream %u went past reservation, coping with it", s->connection_id);
        s->queue.wr_pos_reserved = s->queue.wr_pos;
    }

    return 0;
}

static int tcpaq_is_queue_empty(struct simet_inetup_server * const s)
{
    /* do it in a fail-save manner against queue accounting bugs */
    return (s->queue.rd_pos >= s->queue.wr_pos || s->queue.rd_pos >= s->queue.buffer_size);
}

static void xx_tcpaq_compact(struct simet_inetup_server * const s)
{
    /* FIXME: also compact partially transmitted using a watermark */
    if (s->queue.rd_pos >= s->queue.wr_pos) {
        if (s->queue.wr_pos_reserved > s->queue.rd_pos) {
            s->queue.wr_pos_reserved -= s->queue.rd_pos;
        } else {
            s->queue.wr_pos_reserved = 0;
        }
        s->queue.wr_pos = 0;
        s->queue.rd_pos = 0;
    }
}

static int tcpaq_send_nowait(struct simet_inetup_server * const s)
{
    size_t  send_sz;
    ssize_t sent;

    assert(s && s->queue.buffer);

    if (s->socket == -1)
        return -ENOTCONN;
    if (s->queue.wr_pos == 0)
        return 0;
    if (tcpaq_is_queue_empty(s)) {
        xx_tcpaq_compact(s);
        return 0;
    }

    send_sz = s->queue.wr_pos - s->queue.rd_pos;
    sent = send(s->socket, &s->queue.buffer[s->queue.rd_pos], send_sz, MSG_DONTWAIT | MSG_NOSIGNAL);
    if (sent < 0) {
        int err = errno;
        if (err == EAGAIN || err == EWOULDBLOCK || err == EINTR)
            return 0;
        TRACE_LOG(s, "send() error: %s", strerror(err));
        return -err;
    }
    s->queue.rd_pos += sent;

#if 0
    /* commented out - we can tolerate 200ms extra delay from Naggle just fine,
     * and we already asked for TCP_NODELAY after connect() */

    const int zero = 0;
    const int one = 1;
    /* Ask kernel to flush buffer every time our local queue is empty */
    if (s->queue.wr_pos <= s->queue.rd_pos) {
        setsockopt(s->socket, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        setsockopt(s->socket, IPPROTO_TCP, TCP_NODELAY, &zero, sizeof(zero));
    }
#endif
    /* TRACE_LOG(s, "send() %zd out of %zu bytes", sent, send_sz); */

    xx_tcpaq_compact(s);
    return 0;
}

#if 0
/* Tries hard to flush queue, but only up to timeout seconds */
static int tcpaq_send_timeout(struct simet_inetup_server * const s, time_t timeout)
{
    const time_t tstart = reltime();
    int rc = -EAGAIN;

    while (rc && !tcpaq_is_queue_empty(s) && timer_check(tstart, timeout)) {
        rc = tcpaq_send_nowait(s);
    }

    return rc;
}
#endif

/*
 * SIMET2 Uptime2 protocol helpers
 */
static int xx_simet_uptime2_sndmsg(struct simet_inetup_server * const s,
                               const uint16_t msgtype, const uint32_t msgsize,
                               const char * const msgdata)
{
    struct simet_inetup_msghdr hdr;
    size_t reserve_sz = msgsize + sizeof(hdr);

    if (tcpaq_reserve(s, reserve_sz))
        return -EAGAIN; /* can't send right now */

    hdr.message_type = htons(msgtype);
    hdr.message_size = htonl(msgsize);

    if (tcpaq_queue(s, &hdr, sizeof(hdr), 1) || tcpaq_queue(s, (void *)msgdata, msgsize, 1)) {
        tcpaq_unreserve(s, reserve_sz);
        return -EAGAIN;
    }

    return tcpaq_send_nowait(s);
}

static int uptimeserver_flush(struct simet_inetup_server * const s)
{
    if (s && s->queue.buffer && s->socket != -1 && s->state != SIMET_INETUP_P_C_SHUTDOWN)
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

    TRACE_LOG(s, "sending %s event", name);

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
        TRACE_LOG(s, "ma_event message: %s", jsonstr);
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
 * SIMET2 Uptime2 general messages
 *
 * Returns: 0 or -errno
 */

static int simet_uptime2_msg_clientlifetime(struct simet_inetup_server * const s, int is_start)
{
    return xx_simet_uptime2_sndevent(s, (is_start)? client_start_timestamp : reltime(),
                                        (is_start)? "ma_clientstart" : "ma_clientstop");
}

static int simet_uptime2_msg_link(struct simet_inetup_server * const s, int link_is_up)
{
    return xx_simet_uptime2_sndevent(s, reltime(), (link_is_up)? "ma_link" : "ma_nolink");
}

static int simet_uptime2_msg_keepalive(struct simet_inetup_server * const s)
{
    TRACE_LOG(s, "sending ma_keepalive event");
    return xx_simet_uptime2_sndmsg(s, SIMET_INETUP_P_MSGTYPE_KEEPALIVE, 0, NULL);
}

static int simet_uptime2_msg_maconnect(struct simet_inetup_server * const s)
{
    json_object *jo;
    int rc = -ENOMEM;

    assert(s);

    TRACE_LOG(s, "sending ma_connect event");

    jo = json_object_new_object();
    if (!jo)
        return -ENOMEM;

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
    if (task_name)
        json_object_object_add(jo, "task-name", json_object_new_string(task_name));
    json_object_object_add(jo, "task-version", json_object_new_string(PACKAGE_VERSION));
    json_object_object_add(jo, "timestamp-seconds", json_object_new_int64(reltime()));

    const char *jsonstr = json_object_to_json_string(jo);
    if (jsonstr) {
        TRACE_LOG(s, "ma_connect message: %s", jsonstr);
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
        TRACE_LOG(s, "will attempt to reconnect in %u seconds", backoff_times[s->backoff_level]);
        s->state = SIMET_INETUP_P_C_RECONNECT;
        s->backoff_clock = reltime();
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

        TRACE_LOG(s, "client disconnecting...");
    }
}

/* call this after we are sure the server likes us */
static void simet_uptime2_backoff_reset(struct simet_inetup_server * const s)
{
    s->backoff_level = 0;
}

/*
 * protocol state machine: state workers
 *
 * returns: N < 0 : errors (-errno)
 *          N = 0 : OK, run next state ASAP
 *          N > 0 : OK, no need to run again for N seconds
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

    time_t waittime_left = timer_check(s->keepalive_clock, simet_uptime2_keepalive_interval);
    if (waittime_left > SIMET_INETUP_TIMERFUZZ)
        return waittime_left;

    if (simet_uptime2_msg_keepalive(s)) {
        simet_uptime2_reconnect(s);
        return 0;
    }

    simet_uptime2_keepalive_update(s);
    return simet_uptime2_keepalive_interval;
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

static int uptimeserver_connect(struct simet_inetup_server * const s,
                       const char * const server_name, const char * const server_port)
{
    struct addrinfo *air, *airp;
    struct addrinfo ai;
    int backoff;
    int r;

    const int int_one = 1;

    assert(s && server_name && server_port);
    assert(s->state == SIMET_INETUP_P_C_INIT || s->state == SIMET_INETUP_P_C_RECONNECT);

    if (s->state == SIMET_INETUP_P_C_RECONNECT && s->socket != -1)
        tcpaq_close(s);

    /* Backoff timer */
    time_t waittime_left = timer_check(s->backoff_clock, backoff_times[s->backoff_level]);
    if (waittime_left > 0)
        return waittime_left;
    s->backoff_clock = reltime();
    if (s->backoff_level < BACKOFF_LEVEL_MAX-1)
        s->backoff_level++;
    backoff = (int) backoff_times[s->backoff_level];

    TRACE_LOG(s, "attempting connection to %s, port %s", server_name, server_port);

    memset(&ai, 0, sizeof(ai));
    ai.ai_flags = AI_ADDRCONFIG;
    ai.ai_socktype = SOCK_STREAM;
    ai.ai_family = s->ai_family;
    ai.ai_protocol = IPPROTO_TCP;

    r = getaddrinfo(server_name, server_port, &ai, &air);
    if (r != 0) {
        TRACE_LOG(s, "getaddrinfo returned %s", gai_strerror(r));
        return backoff;
    }
    for (airp = air; airp != NULL; airp = airp->ai_next) {
        s->socket = socket(airp->ai_family, airp->ai_socktype | SOCK_CLOEXEC, airp->ai_protocol);
        if (s->socket == -1)
            continue;

        /* FIXME: do this using select()/poll(), but we have to make it
         * indepondent and async so that we can return to caller to process
         * other concurrent connect()s to other server streams in the
         * meantime.  And that must happen in the middle of the
         * getaddrinfo() loop */

        /* The use of SO_SNDTIMEO for blocking connect() timeout is not
         * mandated by POSIX and it is implemented only in [non-ancient]
         * Linux */
        const struct timeval so_timeout = {
            .tv_sec = simet_uptime2_tcp_timeout,
            .tv_usec = 0,
        };
        if (setsockopt(s->socket, SOL_SOCKET, SO_SNDTIMEO, &so_timeout, sizeof(so_timeout)) ||
            setsockopt(s->socket, SOL_SOCKET, SO_RCVTIMEO, &so_timeout, sizeof(so_timeout))) {
            TRACE_LOG(s, "failed to set socket timeouts using SO_*TIMEO");
        }

        /* RFC-0793/RFC-5482 user timeout.
         *
         * WARNING: Linux seems to be using twice the value set, but trying to
         * compensate for this (by giving it half the value we want) is dangerous
         * unless we do track it down to be sure it has been enshrined as ABI
         */
        const unsigned int ui = (unsigned int)simet_uptime2_tcp_timeout * 1000U;
        if (setsockopt(s->socket, IPPROTO_TCP, TCP_USER_TIMEOUT, &ui, sizeof(unsigned int))) {
            WARNING_LOG("failed to enable TCP timeouts, measurement error will increase");
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
            WARNING_LOG("failed to enable TCP Keep-Alives, measurement error might increase");
        } else {
            DEBUG_LOG("RFC-1122 TCP Keep-Alives enabled, idle=%ds, intvl=%ds, count=%d", tcp_keepidle, tcp_keepintvl, tcp_keepcnt);
        }
#endif

        if (connect(s->socket, airp->ai_addr, airp->ai_addrlen) != -1)
            break;
        close(s->socket);
        s->socket = -1;
    }

    /* FIXME: backoff_clock update required because we are doing blocking connects(),
     * so several seconds will have elapsed already */
    s->backoff_clock = reltime();

    if (!airp) {
        TRACE_LOG(s, "could not connect, will retry in %d seconds", backoff);
        return backoff;
    }

    freeaddrinfo(air);

    s->state = SIMET_INETUP_P_C_RECONNECT; /* if we abort, ensure we will cleanup */

    /* Disable Naggle, we don't need it (but we can tolerate it) */
    setsockopt(s->socket, IPPROTO_TCP, TCP_NODELAY, &int_one, sizeof(int_one));

    /* Get metadata of the connected socket */
    struct sockaddr_storage sa;
    socklen_t sa_len;

    sa_len = sizeof(struct sockaddr_storage);
    sa.ss_family = AF_UNSPEC;
    if (getpeername(s->socket, (struct sockaddr *)&sa, &sa_len) || 
        xx_nameinfo(&sa, sa_len, &s->peer_family, &s->peer_name, &s->peer_port))
        WARNING_LOG("failed to get peer metadata, coping with it");

    sa_len = sizeof(struct sockaddr_storage);
    sa.ss_family = AF_UNSPEC;
    if (getsockname(s->socket, (struct sockaddr *)&sa, &sa_len) ||
        xx_nameinfo(&sa, sa_len, &s->local_family, &s->local_name, &s->local_port))
        WARNING_LOG("failed to get local metadata, coping with it");

    /* done... */
    TRACE_LOG(s, "connected: local %s:[%s]:%s, remote %s:[%s]:%s",
            str_ip46(s->local_family), s->local_name, s->local_port,
            str_ip46(s->peer_family), s->peer_name, s->peer_port);

    s->state = SIMET_INETUP_P_C_REFRESH;
    return 0;
}

static int uptimeserver_disconnect(struct simet_inetup_server *s)
{
    int rc = 0;

    if (s->socket == -1) {
        /* not connected */
        s->state = SIMET_INETUP_P_C_SHUTDOWN;
        s->disconnect_clock = 0;
        return 0;
    }

    if (!s->disconnect_clock) {
        s->disconnect_clock = reltime();
        TRACE_LOG(s, "attempting clean disconnection for up to %d seconds", SIMET_DISCONNECT_WAIT_TIMEOUT);
    }

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
    if (!rc || tcpaq_is_queue_empty(s)) {
        /* tcpaq queue is empty, or we are out of time */
        tcpaq_close(s);
        s->socket = -1;
        s->disconnect_clock = 0;

        TRACE_LOG(s, "client disconnected");

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

    s = calloc(1, sizeof(struct simet_inetup_server));
    if (!s)
        return -ENOMEM;

    s->socket = -1;
    s->state = SIMET_INETUP_P_C_INIT;
    s->ai_family = ai_family;
    s->connection_id = next_connection_id;
    s->queue.buffer = calloc(1, SIMET_INETUP_QUEUESIZE);
    if (!s->queue.buffer) {
        free(s);
        return -ENOMEM;
    }
    s->queue.buffer_size = SIMET_INETUP_QUEUESIZE;

    next_connection_id++;

    *sp = s;

    return 0;
}

/*
 * Command line and main executable
 */

static const char program_copyright[]=
    "Copyright (c) 2018 NIC.br\n\n"
    "This is free software; see the source for copying conditions.\n"
    "There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR\n"
    "A PARTICULAR PURPOSE.\n";

static void print_version(void)
{
    fprintf(stdout, "%s %s\n%s\n", PACKAGE_NAME, PACKAGE_VERSION, program_copyright);
    exit(EXIT_SUCCESS);
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
    fprintf(stderr, "Usage: %s [-h] [-V] [-t <timeout>] "
        "[-d <agent-id>] [-m <string>] [-b <boot id>] [-j <token> ] [-M <string>] "
        "<server name> [<server port>]\n", p);
    if (mode) {
    fprintf(stderr, "\n"
        "\t-h\tprint usage help and exit\n"
        "\t-V\tprint program version and copyright, and exit\n"
        "\t-t\tprotocol timeout in seconds\n"
        "\t-d\tmeasurement agent id\n"
        "\t-m\tmeasurement agent hardcoded id\n"
        "\t-M\tmeasurement task name\n"
        "\t-b\tboot id (e.g. from /proc/sys/kernel/random/boot_id)\n"
        "\t-j\taccess credentials\n"
        "\n"
        "server name: DNS name of server\n"
        "server port: TCP port on server\n"
        "\nNote: client will attempt to open one IPv4 and one IPv6 connection to the server");
    }
    exit((mode)? EXIT_SUCCESS : EXIT_FAILURE);
}

int main(int argc, char **argv) {
    const char *server_name = NULL;
    const char *server_port = "22000";
    int intarg;

    client_start_timestamp = reltime();

    int option;
    /* FIXME: parameter range checking, proper error messages, strtoul instead of atoi */
    while ((option = getopt (argc, argv, "46hVc:l:t:d:m:M:b:j:")) != -1) {
        switch (option) {
        case 't':
            intarg = atoi(optarg);
            if (intarg >= 15)
                simet_uptime2_tcp_timeout = intarg;

            if (simet_uptime2_keepalive_interval >= simet_uptime2_tcp_timeout)
                simet_uptime2_keepalive_interval = simet_uptime2_tcp_timeout / 2;
            if (simet_uptime2_keepalive_interval > 30)
                simet_uptime2_keepalive_interval = 30;
            break;
        case 'd':
            agent_id = optarg;
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
            agent_token = optarg;
            break;
        case 'h':
            print_usage(argv[0], 1);
            /* fall-through */
        case 'V':
            print_version();
            /* fall-through */
        default:
            print_usage(argv[0], 0);
        }
    };

    if (optind >= argc || argc - optind > 2)
        print_usage(argv[0], 0);

    server_name = argv[optind++];
    if (optind < argc)
        server_port = argv[optind];

    init_signals();

    DEBUG_LOG("timeout=%ds, keepalive=%ds, server=\"%s\", port=%s",
              simet_uptime2_tcp_timeout, simet_uptime2_keepalive_interval,
              server_name, server_port);

    /* init */
    /* this can be easily converted to use up-to-# servers per ai_family, etc */
    const unsigned int servers_count = 2;
    struct pollfd *servers_pollfds = calloc(servers_count, sizeof(struct pollfd));
    servers = calloc(servers_count, sizeof(struct simet_inetup_server *));
    if (!servers_pollfds || !servers ||
            uptimeserver_create(&servers[0], AF_INET) || uptimeserver_create(&servers[1], AF_INET6)) {
        ERROR_LOG("out of memory");
        return EXIT_FAILURE;
    }

    /* state machine loop */
    do {
        time_t minwait = 300;
        unsigned int j, num_shutdown;

        num_shutdown = 0;
        for (j = 0; j < servers_count; j++) {
            struct simet_inetup_server *s = servers[j];
            int wait = 0;

            if (got_exit_signal)
                simet_uptime2_disconnect(s);

            /* DEBUG_LOG("%s(%u): main loop, currently at state %u", str_ip46(s->ai_family), s->connection_id, s->state); */

            switch (s->state) {
            case SIMET_INETUP_P_C_INIT:
                /* FIXME: add POLLIN if a backchannel is added, etc */
                servers_pollfds[j].fd = -1;
                servers_pollfds[j].events = POLLRDHUP;
                /* fall-through */
            case SIMET_INETUP_P_C_RECONNECT:
                wait = uptimeserver_connect(s, server_name, server_port);
                servers_pollfds[j].fd = s->socket;
                break;
            case SIMET_INETUP_P_C_REFRESH:
                wait = uptimeserver_refresh(s);
                if (!s->backoff_reset_clock)
                    s->backoff_reset_clock = reltime();
                break;
            case SIMET_INETUP_P_C_MAINLOOP:
                if (s->backoff_reset_clock &&
                        timer_check(s->backoff_reset_clock, simet_uptime2_tcp_timeout * 2) == 0) {
                    TRACE_LOG(s, "assuming server is willing to provide service, backoff timer reset");
                    simet_uptime2_backoff_reset(s);
                    s->backoff_reset_clock = 0;
                }
                wait = uptimeserver_keepalive(s);
                /* state change messages go here */
                break;

            case SIMET_INETUP_P_C_DISCONNECT:
                wait = uptimeserver_disconnect(s);
                break;
            case SIMET_INETUP_P_C_DISCONNECT_WAIT:
                wait = uptimeserver_disconnectwait(s);
                break;

            case SIMET_INETUP_P_C_SHUTDOWN:
                num_shutdown++;
                servers_pollfds[j].fd = -1;
                wait = INT_MAX;
                break;

            default:
                ERROR_LOG("internal error or memory corruption");
                return EXIT_FAILURE;
            }

            if (wait >= 0 && wait < minwait)
                minwait = wait;

            if (uptimeserver_flush(s)) {
                simet_uptime2_reconnect(s);
                minwait = 0;
            }
        }
        /* DEBUG_LOG("------ (minwait: %ld) ------", minwait); */

        if (num_shutdown >= servers_count && got_exit_signal)
            break;

        if (minwait > 0) {
            /* optimized for a small number of servers */
            int poll_res = poll(servers_pollfds, servers_count, minwait * 1000U);
            if (poll_res > 0) {
                for (j = 0; j < servers_count; j++) {
                    if (servers_pollfds[j].revents & (POLLRDHUP | POLLHUP | POLLERR)) {
                        TRACE_LOG(servers[j], "connection to server lost");
                        simet_uptime2_reconnect(servers[j]); /* fast close/shutdown detection */
                    } else if (servers_pollfds[j].revents) {
                        TRACE_LOG(servers[j], "unhandled: pollfd[%u].fd = %d, pollfd[%u].events = 0x%04x, pollfd[%u].revents = 0x%04x",
                            j, servers_pollfds[j].fd,
                            j, (unsigned int)servers_pollfds[j].events,
                            j, (unsigned int)servers_pollfds[j].revents);
                    }
                }
            } else if (poll_res == -1 && (errno != EINTR && errno != EAGAIN)) {
                ERROR_LOG("internal error, memory corruption or out of memory");
                return EXIT_FAILURE;
            }
        }

        if (got_reload_signal && !got_exit_signal) {
            got_reload_signal = 0;
            for (j = 0; j < servers_count; j++)
                simet_uptime2_reconnect(servers[j]);
        }
    } while (1);

    if (got_exit_signal)
        DEBUG_LOG("received exit signal %d, exiting...", got_exit_signal);
    else
        DEBUG_LOG("all servers connections have been shutdown, exiting...");

    return EXIT_SUCCESS;
}

/* vim: set et ts=4 sw=4 : */