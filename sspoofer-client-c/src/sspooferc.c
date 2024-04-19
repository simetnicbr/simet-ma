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

#include "sspooferc_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include <stdbool.h>

#include <limits.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>

#include <assert.h>
#if !defined(static_assert) && defined(__STDC_VERSION__) && (__STDC_VERSION__ < 202301L)
#  define static_assert _Static_assert
#endif

#include <sys/stat.h>
#include <fcntl.h>
#include <sys/poll.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include "netinet-tcp-compat.h"
#include <netdb.h>
#include <arpa/inet.h>

#include <time.h>
#include <signal.h>

#include "sspooferc.h"
#include "simet_err.h"
#include "logger.h"
#include "tcpaq.h"
#include "base64.h"
#include "timespec.h"
#include "report.h"

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

static struct sspoof_server_cluster *server_clusters = NULL;
static struct sspoof_server **servers = NULL;
static unsigned int servers_count = 0;
static const char *agent_id_file = NULL;
static const char *agent_id = NULL;
static const char *agent_token_file = NULL;
static const char *agent_token = NULL;

static unsigned int sspoofer_tcp_timeout = SSPOOFER_DEFAULT_CTRL_TIMEOUT;

static clockid_t clockid = CLOCK_MONOTONIC;
static time_t client_start_timestamp;
static time_t client_boot_offset = 0;
static int    client_boot_sync   = 0;

static volatile int got_exit_signal = 0;    /* SIGTERM, SIGQUIT, SIGINT... */
static int got_disconnect_msg = 0;          /* MSG_DISCONNECT */

/* UI purposes */
static int connected_once;
static int successful_measurement_once;

#define BACKOFF_LEVEL_MAX 5
static const unsigned int backoff_times[BACKOFF_LEVEL_MAX] =
    { 1, 1, 5, 5, 10 }; /* first and last levels are not used */

/* time we wait to flush queue to kernel before we drop it during disconnect */
#define SIMET_DISCONNECT_WAIT_TIMEOUT 5

/* maximum payload size of a sspoofer control protocol message */
#define SSPOOFER_MAXDATASIZE (SIMET_TCPAQ_QUEUESIZE - sizeof(struct sspoof_ctrl_msghdr))

/* sanity for agent-ids, currently they are UUIDs */
#define SIMET_AGENTID_MAX_LEN 40

/*
 * helpers
 */

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

/* closes socket requesting TCP RST */
static void tcp_abort(int socket)
{
    struct linger l = {
        .l_onoff = 1,
        .l_linger = 0,
    };
    if (socket >= 0) {
        setsockopt(socket, SOL_SOCKET, SO_LINGER, &l, sizeof(l));
        close(socket); /* TCP RST, signal error condition */
    }
}

/*
 *
 * TIMEKEEPING
 *
 */

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
        client_boot_offset = (llabs(now_boot - now_rel) > 2)? now_boot - now_rel : 0;

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

static void log_timekeeping_state(void)
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


/*
 *
 * Control protocol and reporting helpers
 *
 */

/* FIXME: likely we want the server, ai_family... */
#define protocol_msg(aloglevel, sctx, format, arg...) \
    do { \
       print_msg(aloglevel, "ctrl conn %u (%s): " format, sctx->connection_id, str_ipv46(sctx->conn.ai_family), ## arg); \
    } while (0)

#define protocol_trace(sctx, format, arg...) \
    protocol_msg(MSG_TRACE, sctx, format, ## arg)

static int fits_u64_i64(const uint64_t v64u, int64_t * const p64d)
{
    *p64d = v64u & INT64_MAX;
    return !!(v64u <= INT64_MAX);
}

/* msmt context helpers */

static void sspoof_msmtreq_freecontents(struct sspoof_msmt_req *mreq)
{
/*
    if (mreq) {
       ...
    }
*/
    (void) mreq;
}

static struct sspoof_msmt_ctx *sspoof_msmtctx_new(void)
{
    struct sspoof_msmt_ctx *mctx = calloc(1, sizeof(struct sspoof_msmt_ctx));
    if (mctx) {
        mctx->udpsocket = -1;
    }
    return mctx;
}

static void sspoof_msmtctx_destroy(struct sspoof_msmt_ctx * mctx)
{
    while (mctx != NULL) {
        for (int i = 0; i < mctx->msmt_req_count; i++) {
            sspoof_msmtreq_freecontents(&mctx->msmt_reqs[i]);
        }
        mctx->msmt_req_count = 0;

        if (mctx->udpsocket >= 0)
            close(mctx->udpsocket);
        mctx->udpsocket = -1;

        free_const(mctx->measurement_id);
        mctx->measurement_id = NULL;

        struct sspoof_msmt_ctx * m = mctx;
        mctx = mctx->next;
        free(m);
    }
}

/* append to end of queue */
static void sspoof_msmtctx_enqueue(struct sspoof_msmt_ctx *mctx,
                                   struct sspoof_msmt_ctx **queue)
{
    while (queue && *queue) {
        queue = &((*queue)->next);
    }
    if (queue) {
        *queue = mctx;
    }
}

/* split a network prefix into network address and prefix length */
/* for IPv6, we truncate the network address at /64 */
/* for IPv4, the 32-bit address is in the low 32 bits */
/* modifies astr */
static int xx_split_prefix(const char * const astr,
        const sa_family_t family,
        uint64_t * prefix, uint8_t * const plen)
{
    if (!astr || !plen || !prefix)
        return -EINVAL;

    char ip_str[INET6_ADDRSTRLEN + 4];
    if (strlen(astr) >= sizeof(ip_str))
        return -EBADMSG;
    strncpy(ip_str, astr, sizeof(ip_str)-1);

    char *r = strchr(ip_str, '/');
    long pl = 128;
    if (r) {
        *r = '\0'; /* split */
        r++;

        errno = 0;
        char *rerr = NULL;
        pl = strtol(r, &rerr, 10);
        if (errno != 0 || r == rerr)
            return -EBADMSG;
    }
    if (pl < 0 || pl > 128)
        return -EBADMSG;

    union {
        struct in_addr  ip4;
        struct in6_addr ip6;
        uint64_t in_addr64[2];
    } ip;
    if (inet_pton(family, ip_str, &ip) <= 0)
        return -EBADMSG;
    switch (family) {
    case AF_INET:
        *prefix = ip.ip4.s_addr; /* align ip4 to lowest bits */
        *plen = (pl < 32) ? (uint8_t)pl : 32;
        break;
    case AF_INET6:
        *prefix = ip.in_addr64[0]; /* keep just the network /64 */
        *plen = (pl < 64) ? (uint8_t)pl : 64;
        break;
    default:
        return -EBADMSG;
    }

    return 0;
}

/* json helpers */

/*
 * First value returned on program start must be 1, not zero.
 * Must wrap around UINT32_MAX+1 to zero.
 *
 * note: C11 atomics are probably not available in openwrt 15.05;
 * FIXME: if we ever go multithreaded, deal with this! */
static uint32_t get_seqnumber(void)
{
    static uint32_t aseqnumber = 0;

    aseqnumber++;

    return aseqnumber;
}
static void xx_json_object_seqnum_add(struct json_object * const j)
{
    json_object_object_add(j, "seqnum",
                    json_object_new_int64(get_seqnumber()));
}

static void xx_set_tcp_timeouts(struct sspoof_server * const s)
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
        .tv_sec = s->control_timeout,
        .tv_usec = 0,
    };
    if (setsockopt(s->conn.socket, SOL_SOCKET, SO_SNDTIMEO, &so_timeout, sizeof(so_timeout)) ||
        setsockopt(s->conn.socket, SOL_SOCKET, SO_RCVTIMEO, &so_timeout, sizeof(so_timeout))) {
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
    const unsigned int ui = (unsigned int)s->control_timeout * 1000U;
    if (setsockopt(s->conn.socket, IPPROTO_TCP, TCP_USER_TIMEOUT, &ui, sizeof(unsigned int))) {
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
    int tcp_keepintvl = sspoofer_tcp_timeout / tcp_keepcnt;
    if (tcp_keepintvl < 5)
        tcp_keepintvl = 5;
    int tcp_keepidle = sspoofer_tcp_timeout / tcp_keepcnt;
    if (tcp_keepidle < 5)
        tcp_keepidle = 5;
    if (setsockopt(s->conn.socket, IPPROTO_TCP, TCP_KEEPCNT, &tcp_keepcnt, sizeof(int)) ||
        setsockopt(s->conn.socket, IPPROTO_TCP, TCP_KEEPIDLE, &tcp_keepidle, sizeof(int)) ||
        setsockopt(s->conn.socket, IPPROTO_TCP, TCP_KEEPINTVL, &tcp_keepintvl, sizeof(int)) ||
        setsockopt(s->conn.socket, SOL_SOCKET, SO_KEEPALIVE, &int_one, sizeof(int_one))) {
        print_warn("failed to enable TCP Keep-Alives, measurement error might increase");
    } else {
        protocol_trace(s, "RFC-1122 TCP Keep-Alives enabled, idle=%ds, intvl=%ds, count=%d", tcp_keepidle, tcp_keepintvl, tcp_keepcnt);
    }
#endif
}

static int xx_sspoofer_sndmsg(struct sspoof_server * const s,
                               const uint16_t msgtype, const size_t msgsize,
                               const char * const msgdata)
{
    struct sspoof_ctrl_msghdr hdr;

    static_assert(SSPOOFER_MAXDATASIZE < UINT32_MAX, "SSPOOFER_MAXDATASIZE cannot be larger than UINT32_MAX");

    if (msgsize > SSPOOFER_MAXDATASIZE) {
        protocol_msg(MSG_IMPORTANT, s, "internal error: tried to send too large a message, discarded it instead");
        return 0; /* or abort the program, which would be worse */
    }

    size_t reserve_sz = msgsize + sizeof(hdr);
    if (tcpaq_reserve(&s->conn, reserve_sz))
        return -EAGAIN; /* can't send right now */

    memset(&hdr, 0, sizeof(hdr));
    hdr.message_type = htons(msgtype);
    hdr.message_size = htonl((uint32_t)msgsize); /* safe, < SSPOOFER_MAXDATASIZE */

    if (tcpaq_queue(&s->conn, &hdr, sizeof(hdr), 1) || tcpaq_queue(&s->conn, (void *)msgdata, msgsize, 1)) {
        /* should not happen, but if it does, try to recover */
        if (tcpaq_unreserve(&s->conn, reserve_sz))
            return -EINVAL; /* internal error?! */
        return -EAGAIN;
    }

    return tcpaq_send_nowait(&s->conn);
}

/* update remote keepalive timer, we can do that every time we hear from remote */
static void sspoofer_remotekeepalive_update(struct sspoof_server * const s)
{
    s->remote_keepalive_clock = reltime();
}

static int sspoofserver_drain(struct sspoof_server * const s)
{
    int res = tcpaq_drain(&s->conn);
    if (res > 0) {
            /* we did discard something, so remote is alive */
            protocol_trace(s, "drain: remote watchdog updated");
            sspoofer_remotekeepalive_update(s);
            return 0;
    }
    return res;
}

/* Message receve handling */

typedef int (* sspoof_ctrl_msghandler)(struct sspoof_server * const s,
                                       const struct sspoof_ctrl_msghdr * const hdr,
                                       const void * const data);

#define SSPOOF_MSGHANDLER_EOL 0xffffffff
struct sspoof_ctrl_msghandlers {
    uint32_t type;                      /* > 0xffff means EOL */
    sspoof_ctrl_msghandler handler;     /* NULL to handle by discarding */
};

/* 0: did nothing; < 0 : error; -ENOENT msg not in table, discarded */
static int sspoofer_recvmsg(struct sspoof_server * const s,
                const struct sspoof_ctrl_msghandlers *handlers)
{
    struct sspoof_ctrl_msghdr hdr;
    const char *data = NULL;
    int res;

    /* we do some dances to reduce buffer copying, and to avoid give backs */
    res = tcpaq_peek_nowait(&s->conn, sizeof(hdr), &data);
    if (res <= 0 || !data)
        return res;
    hdr.message_type = ntohs(((struct sspoof_ctrl_msghdr *)data)->message_type);
    hdr.message_size = ntohl(((struct sspoof_ctrl_msghdr *)data)->message_size);

    /* messages larger than 64KiB are illegal and must cause a connection drop */
    if (hdr.message_size > 65535) {
        protocol_msg(MSG_IMPORTANT, s, "recvmsg: message too large (%u bytes), sync might have been lost",
                (unsigned int) hdr.message_size);
        return -EFAULT;
    }

    protocol_trace(s, "recvmsg: remote watchdog updated");
    sspoofer_remotekeepalive_update(s);

    /* either tcpaq_discard the whole thing, or tcpaq_peek hdr and data */
    int handler_found = 0;
    if (handlers && hdr.message_size <= SSPOOFER_MAXDATASIZE) {
        while (handlers->type != hdr.message_type && !(handlers->type & 0xffff0000U))
            handlers++;
        if (handlers->type == hdr.message_type) {
            if (handlers->handler) {
                /* single-threaded, so we can peek to avoid an extra copy... */
                res = tcpaq_peek_nowait(&s->conn, hdr.message_size + sizeof(hdr), &data);
                if (res > 0 && data) { /* data is NULL only for res <= 0, this is just safety */
                    res = (* handlers->handler)(s, &hdr, data + sizeof(hdr));
                    if (tcpaq_discard(&s->conn, hdr.message_size + sizeof(hdr)) <= 0) {
                        /* entire message was peeked at, since peek_nowait did not return zero */
                        protocol_trace(s, "recvmsg: unexpected result for discard-after-peek");
                    }
                }
            } else {
                /* try to silent discard the whole thing */
                res = tcpaq_discard(&s->conn, hdr.message_size + sizeof(hdr));
            }
            if (res < 0) {
                protocol_trace(s, "error processing message type 0x%04x, size %" PRIu32 ": %s",
                        (unsigned int) hdr.message_type, hdr.message_size,
                        strerror(-res));
                return res;
            }
            handler_found = 1;
        }
    }
    if (!handler_found) {
        /* unexpected discard */
        res = tcpaq_discard(&s->conn, hdr.message_size + sizeof(hdr));
        if (res < 0)
            return res;
        protocol_trace(s, "%s message with type 0x%04x and size %" PRIu32,
                       (res) ? "discarded" : "will discard",
                       (unsigned int) hdr.message_type, hdr.message_size);
        res = -ENOENT;
    }
    return res;
}

static int sspoofserver_flush(struct sspoof_server * const s)
{
    if (s && s->conn.out_queue.buffer && s->conn.socket != -1 && s->state != SSPOOF_P_C_SHUTDOWN)
        return tcpaq_send_nowait(&s->conn);

    return 0;
}

/* update keepalive timer every time we send a message of any time */
static void sspoofer_keepalive_update(struct sspoof_server * const s)
{
   s->keepalive_clock = reltime();
}


/*
 * SIMET spoofer client message processing
 */

/* returns -errno (error), >= 0 (valid) */
static int parse_sid(struct sspoof_sid *sid)
{
    if (!sid || !sid->str)
        return -EINVAL;

    ssize_t rc = base64_decode(sid->str, strlen(sid->str), sid->sid, sizeof(sid->sid));
    if (rc <= 0)
        return -EINVAL;

    /* paranoia, really */
    if (rc > (ssize_t)sizeof(sid->sid))
        return -E2BIG;

    static_assert(sizeof(sid->sid) < UINT8_MAX, "size of struct sppoof_sid::sid too large");

    sid->len = (uint8_t)rc;

    /* print_msg(MSG_DEBUG, "sid: base64 \"%s\" decoded into %u bytes", sid->str, sid->len); */

    return 0;
}

/* <0 -errno, 0 not found, 1 found, no change, 2 found, updated */
static int xx_json_getbool(struct sspoof_server * const s, const char * const what,
                        struct json_object * const jconf,
                        const char * const param_name,
                        bool * const param)
{
    struct json_object *jo;

    if (json_object_object_get_ex(jconf, param_name, &jo)) {
        if (json_object_is_type(jo, json_type_boolean)) {
            errno = 0;
            json_bool val = json_object_get_boolean(jo);
            if (errno == 0) {
                const bool ubval = !!(val);
                if ((!!*param) != !!(ubval)) {
                    *param = ubval;
                    protocol_msg(MSG_DEBUG, s, "%s: set %s to %s", what, param_name, (*param)? "true" : "false");
                    return 2;
                }
                return 1;
            }
        }
        protocol_msg(MSG_NORMAL, s, "%s: invalid %s: %s", what,
                      param_name, json_object_to_json_string(jo));
        return -EINVAL;
    }

    return 0;
}

/* <0 -errno, 0 not found, 1 found, no change, 2 found, updated */
static int xx_json_getuint(struct sspoof_server * const s, const char * const what,
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
                    protocol_msg(MSG_DEBUG, s, "%s: set %s to %u", what, param_name, *param);
                    return 2;
                }
                return 1;
            }
        }
        protocol_msg(MSG_NORMAL, s, "%s: invalid %s: %s", what,
                      param_name, json_object_to_json_string(jo));
        return -EINVAL;
    }

    return 0;
}

/* <0 -errno, 0 not found, 1 found, no change, 2 found, updated */
static int xx_json_getstr(struct sspoof_server * const s,
                        const char * const what,
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
                free_const(*param);
                *param = val;
                return 2;
            }
        }
        protocol_msg(MSG_NORMAL, s, "%s: invalid %s: %s", what,
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
 *   "control-timeout-seconds": 60,
 *   "measurement-timeout-seconds": 60,
 *   "cluster-hostname": "<hostname>",
 *   "server-hostname": "<hostname>",
 *   "server-description": "<description for this server>"
 *    } }
 *
 * all fields optional.  fields completely override previous settings.
 * implementation detail: we ignore trailing crap to avoid json-c internals
 *
 * protocol v1:
 * * Capability "simet-spoofer-v1" is mandatory.
 */
static int sspoofer_msghdl_maconfig(struct sspoof_server * const s,
                    const struct sspoof_ctrl_msghdr * const hdr,
                    const void * const data)
{
    struct json_tokener *jtok;
    struct json_object *jroot = NULL;
    struct json_object *jconf, *jo;
    int res = 2;
    int seen_sspoofer_cap = 0;

    const char * const w = "ma_config";

    if (hdr->message_size < 2 || hdr->message_size > INT_MAX) {
        protocol_trace(s, "ma_config: malformed message, invalid size");
        return -EBADMSG;
    }

    protocol_trace(s, "ma_config: processing message: %.*s",
            (int) hdr->message_size, (const char *)data);

    jtok = json_tokener_new();
    if (!jtok)
        return -ENOMEM;

    jroot = json_tokener_parse_ex(jtok, data, (int) hdr->message_size);
    if (!json_object_object_get_ex(jroot, "config", &jconf))
        goto err_exit;
    if (!json_object_is_type(jconf, json_type_object))
        goto err_exit;

    if (json_object_object_get_ex(jconf, "capabilities-enabled", &jo)) {
        size_t al;

        /* check syntax before we reset any capabilities */
        if (!json_object_is_type(jo, json_type_array))
            goto err_exit;
        al = json_object_array_length(jo);
        while (al > 0) {
            --al;
            if (!json_object_is_type(json_object_array_get_idx(jo, al), json_type_string))
                goto err_exit;
        }

        /* set any capabilities we know about, warn of others */
        al = json_object_array_length(jo);
        while (al > 0) {
            --al;
            const char *cap = json_object_get_string(json_object_array_get_idx(jo, al));
            if (!strcasecmp("simet-spoofer-v1", cap)) {
                seen_sspoofer_cap = 1;
            /* } else if (!strcasecmp("other key", cap)) ... { */
            } else {
                protocol_trace(s, "ma_config: ignoring capability %s", cap ? cap : "(empty)");
            }
        }
    }

    /* terminate connection on missing/invalid capabilties */
    if (!seen_sspoofer_cap) {
        protocol_msg(MSG_IMPORTANT, s, "measurement peer responded in an unsupported protocol");
        res = -EBADMSG;
        goto err_exit_free;
    }

    if (xx_json_getstr(s, w, jconf, "session-id", &s->sid.str) <= 0 || parse_sid(&s->sid) < 0) {
        protocol_msg(MSG_IMPORTANT, s, "measurement peer did not send a valid v1 session-id");
        res = -EBADMSG;
        goto err_exit_free;
    }

    if (xx_json_getuint(s, w, jconf, "control-timeout-seconds", &s->control_timeout, 0, 86400) > 0)
        xx_set_tcp_timeouts(s);
    xx_json_getuint(s, w, jconf, "measurement-timeout-seconds", &s->measurement_timeout, 0, 86400);

    if (xx_json_getstr(s, w, jconf, "server-hostname", &s->server_hostname) > 0
            && s->server_hostname) {
        protocol_msg(MSG_DEBUG, s, "ma_config: measurement peer hostname is \"%s\"", s->server_hostname);
    }
    if (xx_json_getstr(s, w, jconf, "server-description", &s->server_description) > 0
            && s->server_description) {
        protocol_msg(MSG_DEBUG, s, "ma_config: measurement peer description is \"%s\"", s->server_description);
    }

    if (xx_json_getstr(s, w, jconf, "cluster-hostname", &s->s_cluster_hostname) > 0
           && s->s_cluster_hostname) {
        protocol_msg(MSG_DEBUG, s, "ma_config: measurement peer cluster is \"%s\"", s->s_cluster_hostname);
    }

    if (s->ma_config_count < 2)
        s->ma_config_count++;
    res = 1;

err_exit:
    if (json_tokener_get_error(jtok) != json_tokener_success) {
        protocol_trace(s, "ma_config: received invalid message: %s",
                      json_tokener_error_desc(json_tokener_get_error(jtok)));
        res = -EBADMSG;
    } else if (res > 1) {
        protocol_trace(s, "ma_config: received malformed message");
        res = -EBADMSG;
    }

err_exit_free:
    json_tokener_free(jtok);
    if (jroot)
        json_object_put(jroot);
    return res;
}

/*
 * MSMTREQ message:
 *
 * { "measurement_id": "<id string>",
 *   "measurement_request" : [
 *   {
 *      "type": "spoof-v1"|"probe",
 *      "packet_group_count": <number of packet groups>, MANDATORY
 *      "dst_port": <udp destination port>,              default: same as TCP control connection
 *      "payload_size": <payload size>,                  default SSPOOF_MSMT_DFL_PAYLOADSZ
 *      "ip_traffic_class": <ip4 tos/ip6 tc field>,      default 0
 *      "ip_ttl": <time to live>,                        default: SSPOOF_MSMT_DFL_TTL
 *      "interpacket_interval_ms": <time in ms>,         default: 50ms
 *      "intergroup_interval_ms": <time in ms>,          default: 500ms
 *      "spoofed_src": "<prefix>",  (spoof-v1 only)
 *      "spoofed_src_type": "<tag>", (sspoof-v1 only)    max len: SSPOOF_MSMT_SPOOFV1_TAGLEN-1
 *   }, ...
 * ] }
 *
 * Note: measurements in the same MSMTREQ message run in parallel
 *
 * implementation detail: we ignore trailing crap to avoid json-c internals
 */
static int sspoofer_msghdl_msmtreq(struct sspoof_server * const s,
                    const struct sspoof_ctrl_msghdr * const hdr,
                    const void * const data)
{
    struct json_tokener *jtok;
    struct json_object *jroot = NULL;
    struct json_object *jmsmt_a, *jmsmt, *jo;
    const char *param_str = NULL;

    struct sspoof_msmt_ctx * mctx = NULL;

    int res = 2;

    const char * const w = "msmtreq";

    if (hdr->message_size < 2 || hdr->message_size > INT_MAX) {
        protocol_trace(s, "msmtreq: malformed message, invalid size");
        return -EBADMSG;
    }

    protocol_trace(s, "msmtreq: processing message: %.*s",
            (int) hdr->message_size, (const char *)data);

    jtok = json_tokener_new();
    if (!jtok)
        return -ENOMEM;

    jroot = json_tokener_parse_ex(jtok, data, (int) hdr->message_size);
    if (!json_object_object_get_ex(jroot, "measurement_request", &jmsmt_a))
        goto err_exit;
    if (!json_object_is_type(jmsmt_a, json_type_array))
        goto err_exit;

    /* allocate a new msmt context to hold the measurements */
    mctx = sspoof_msmtctx_new();
    if (!mctx)
        goto err_exit;

    size_t msmt_alen = json_object_array_length(jmsmt_a);
    while (msmt_alen > 0) {
        struct sspoof_msmt_req *msmtreq = &mctx->msmt_reqs[mctx->msmt_req_count];

        --msmt_alen;

        memset(msmtreq, 0, sizeof(*msmtreq));
        msmtreq->payload_size = SSPOOF_MSMT_DFL_PAYLOADSZ;
        msmtreq->ip_ttl = SSPOOF_MSMT_DFL_TTL;
        msmtreq->pkt_interval_us = 50000;
        msmtreq->grp_interval_us = 500000;

        jmsmt = json_object_array_get_idx(jmsmt_a, msmt_alen);
        if (!json_object_is_type(jmsmt, json_type_object))
            goto err_exit;

        /* parse a msmt in jmsmt */
        if (!json_object_object_get_ex(jmsmt, "type", &jo))
            goto err_exit;
        const char * const msmt_type_str = json_object_get_string(jo);
        if (!msmt_type_str)
            goto err_exit;
        if (!strcasecmp("probe", msmt_type_str)) {
            msmtreq->type = SSPOOF_MSMT_T_PROBE;
        } else if (!strcasecmp("spoof-v1", msmt_type_str)) {
            msmtreq->type = SSPOOF_MSMT_T_SPOOFV1;
        } else {
            protocol_trace(s, "unknown measurement type: %s", msmt_type_str);
            goto err_exit;
        }

        /* common fields */
        int rc;
        unsigned int value = 0;
        if (xx_json_getuint(s, w, jmsmt, "packet_group_count", &value, 1, 500) <= 0) /* mandatory */
            goto err_exit;
        msmtreq->pkt_group_count = (int)value; /* verified 1..500 */
        value = msmtreq->dst_port;
        if ((rc = xx_json_getuint(s, w, jmsmt, "dst_port", &value, 1024, 65530)) < 0) {
            goto err_exit;
        } else if (rc > 1) {
             msmtreq->dst_port = (uint16_t)value; /* verified 1024..65530 */
        }
        value = msmtreq->payload_size;
        if ((rc = xx_json_getuint(s, w, jmsmt, "payload_size", &value, 64, 4000)) < 0) {
            goto err_exit;
        } else if (rc > 1) {
             msmtreq->payload_size = (uint16_t)value; /* verified 64..4000 */
        }

        if (xx_json_getuint(s, w, jmsmt, "interpacket_interval_us", &msmtreq->pkt_interval_us, 10, 2000000) < 0) {
            goto err_exit;
        }
        if (xx_json_getuint(s, w, jmsmt, "intergroup_interval_us", &msmtreq->grp_interval_us, 10, 2000000) < 0) {
            goto err_exit;
        }

        /* duh... */
        if (msmtreq->grp_interval_us < msmtreq->pkt_interval_us)
            msmtreq->grp_interval_us = msmtreq->pkt_interval_us;

        value = msmtreq->ip_ttl;
        if ((rc = xx_json_getuint(s, w, jmsmt, "ip_ttl", &value, 1, 255)) < 0) {
            goto err_exit;
        } else if (rc > 1) {
            msmtreq->ip_ttl = (uint8_t)value; /* verified 1..255 */
        }
        value = msmtreq->ip_traffic_class;
        if ((rc = xx_json_getuint(s, w, jmsmt, "ip_traffic_class", &value, 0, 255)) < 0) {
            goto err_exit;
        } else if (rc > 1) {
            msmtreq->ip_traffic_class = (uint8_t)value;
        }

        if (msmtreq->type == SSPOOF_MSMT_T_SPOOFV1) {
            /* only for type spoof-v1 */
            if (xx_json_getstr(s, w, jmsmt, "spoofed_src", &param_str) <= 1)
                goto err_exit;
            if (xx_split_prefix(param_str, s->conn.ai_family, &msmtreq->prefix, &msmtreq->prefix_length) < 0) {
                protocol_msg(MSG_DEBUG, s, "invalid prefix: %s", (param_str && *param_str)? param_str : "(none)");
                goto err_exit;
            }
            /* protocol_msg(MSG_DEBUG, s, "prefix: %s = %16lx / %02u", param_str, msmtreq->prefix, msmtreq->prefix_length); */
            free_const(param_str);
            param_str = NULL;

            rc = xx_json_getstr(s, w, jmsmt, "spoofed_src_type", &param_str);
            if (rc < 0) {
                goto err_exit;
            } else if (rc > 0) {
                if (!param_str || !(*param_str) || strlen(param_str) >= sizeof(msmtreq->prefixtag)) {
                    protocol_msg(MSG_DEBUG, s, "invalid spoof src type: %s", (param_str && *param_str)? param_str: "(none)");
                    goto err_exit;
                }
                strncpy(msmtreq->prefixtag, param_str, sizeof(msmtreq->prefixtag)); /* strlen(param_str) < sizeof(msmtreq->prefixtag) */
                /* protocol_msg(MSG_DEBUG, s, "spoofed src address type: %s", param_str); */
            }
            free_const(param_str);
            param_str = NULL;
        }
        mctx->msmt_req_count++;
    }

    if (!json_object_object_get_ex(jroot, "measurement_id", &jo))
        goto err_exit;
    if (!json_object_is_type(jo, json_type_string))
        goto err_exit;
    const char * m_id = json_object_get_string(jo);
    if (!m_id || strlen(m_id) < 4)
        goto err_exit;
    mctx->measurement_id = strdup(m_id);

    protocol_trace(s, "msmtreq: will queue %d measurement requests", mctx->msmt_req_count);
    sspoof_msmtctx_enqueue(mctx, &s->msmt_queue);
    mctx = NULL;
    res = 1;

err_exit:
    free_const(param_str);
    param_str = NULL;

    if (json_tokener_get_error(jtok) != json_tokener_success) {
        protocol_trace(s, "msmtreq: received invalid message: %s",
                      json_tokener_error_desc(json_tokener_get_error(jtok)));
        res = -EBADMSG;
    } else if (res > 1) {
        protocol_trace(s, "msmtreq: received malformed message");
        res = -EBADMSG;
    }

    json_tokener_free(jtok);
    if (jroot)
        json_object_put(jroot);

    if (mctx) {
        sspoof_msmtctx_destroy(mctx);
    }
    return res;
}

/*
 * MSMTDATA message:
 *
 * { "measurement_id": "<id string>",
 *   "measurement_summary": {
 *   "sentinel_packets_received": <int>,
 *   "spoof_packets_received": <int>,
 *   "probe_packets_received": <int>,
 *   "sentinel_snat": <bool>,
 *   "spoof_snat": <bool>,
 *   "probe_snat": <bool>,
 *   "sentinel_intact": <bool>,
 *   "spoof_intact": <bool>,
 *   "probe_intact": <bool>,
 *   "sentinel_snat_addr": "<ip address>",
 *   "spoof_snat_addr": "<ip address>",
 *   "probe_snat_addr": "<ip address>"
 * }
 *
 * implementation detail: we ignore trailing crap to avoid json-c internals
 */
static int sspoofer_msghdl_msmtdata(struct sspoof_server * const s,
                    const struct sspoof_ctrl_msghdr * const hdr,
                    const void * const data)
{
    struct json_tokener *jtok;
    struct json_object *jroot = NULL;
    struct json_object *jmsmt, *jo;

    int res = 2;

    const char * const w = "msmtdata";

    if (hdr->message_size < 2 || hdr->message_size > INT_MAX) {
        protocol_trace(s, "msmtdata: malformed message, invalid size");
        return -EBADMSG;
    }

    protocol_trace(s, "msmtdata: processing message: %.*s",
            (int) hdr->message_size, (const char *)data);

    jtok = json_tokener_new();
    if (!jtok)
        return -ENOMEM;

    jroot = json_tokener_parse_ex(jtok, data, (int) hdr->message_size);
    if (!json_object_object_get_ex(jroot, "measurement_summary", &jmsmt))
        goto err_exit;
    if (!json_object_is_type(jmsmt, json_type_object))
        goto err_exit;

    /* parse results in message */
    struct sspoof_msmt_results ndata = { };
    int rc;

    /* sentinel packets sent over the raw socket (part of spoof-v1) */
    if ((rc = xx_json_getuint(s, w, jmsmt, "sentinel_packets_received", &ndata.sentinel_rcvd_count, 0, 65535)) < 0) {
        goto err_exit;
    }
    if (rc > 0) {
        if (xx_json_getbool(s, w, jmsmt, "sentinel_snat", &ndata.sentinel_snat_seen) < 0
                || xx_json_getbool(s, w, jmsmt, "sentinel_intact", &ndata.sentinel_intact_seen) < 0) {
            goto err_exit;
        }
        if (ndata.sentinel_snat_seen && xx_json_getstr(s, w, jmsmt, "sentinel_snat_addr", &ndata.last_sentinel_snat_saddr) < 0) {
            goto err_exit;
        }
    }

    /* spoofed packets sent over the raw socket (part of spoof-v1) */
    if ((rc = xx_json_getuint(s, w, jmsmt, "spoof_packets_received", &ndata.spoof_rcvd_count, 0, 65535)) < 0) {
        goto err_exit;
    }
    if (rc > 0) {
        if (xx_json_getbool(s, w, jmsmt, "spoof_snat", &ndata.spoof_snat_seen) < 0
                || xx_json_getbool(s, w, jmsmt, "spoof_intact", &ndata.spoof_intact_seen) < 0) {
            goto err_exit;
        }
        if (ndata.spoof_snat_seen && xx_json_getstr(s, w, jmsmt, "spoof_snat_addr", &ndata.last_spoof_snat_saddr) < 0) {
            goto err_exit;
        }
    }

    /* probe packets sent over a normal UDP socket (probe) */
    if ((rc = xx_json_getuint(s, w, jmsmt, "probe_packets_received", &ndata.probe_rcvd_count, 0, 65535)) < 0) {
        goto err_exit;
    }
    if (rc > 0) {
        if (xx_json_getbool(s, w, jmsmt, "probe_snat", &ndata.probe_snat_seen) < 0
                || xx_json_getbool(s, w, jmsmt, "probe_intact", &ndata.probe_intact_seen) < 0) {
            goto err_exit;
        }
        if (ndata.probe_snat_seen && xx_json_getstr(s, w, jmsmt, "probe_snat_addr", &ndata.last_probe_snat_saddr) < 0) {
            goto err_exit;
        }
    }

    if (!json_object_object_get_ex(jroot, "measurement_id", &jo))
        goto err_exit;
    if (!json_object_is_type(jo, json_type_string))
        goto err_exit;
    const char * const m_id = json_object_get_string(jo); /* owned by jo */
    if (!m_id || strlen(m_id) < 4)
        goto err_exit;

    /* find the correct context */
    struct sspoof_msmt_ctx *mctx = s->msmt_done;
    while (mctx && xstrcmp(m_id, mctx->measurement_id)) {
        mctx = mctx->next;
    }
    if (!mctx) {
        mctx = s->msmt_queue;
        while (mctx && xstrcmp(m_id, mctx->measurement_id)) {
            mctx = mctx->next;
        }
    }
    if (!mctx) {
        print_err("server sent data about a measurement unknown to us, ingoring it");
        res = 0;
        goto err_exit;
    }

    /* merge results with those already in the context, if any */
    mctx->data.sentinel_rcvd_count  += ndata.sentinel_rcvd_count;
    mctx->data.probe_rcvd_count     += ndata.probe_rcvd_count;
    mctx->data.spoof_rcvd_count     += ndata.spoof_rcvd_count;
    mctx->data.sentinel_snat_seen   |= ndata.sentinel_snat_seen;
    mctx->data.probe_snat_seen      |= ndata.probe_snat_seen;
    mctx->data.spoof_snat_seen      |= ndata.spoof_snat_seen;
    mctx->data.sentinel_intact_seen |= ndata.sentinel_intact_seen;
    mctx->data.probe_intact_seen    |= ndata.probe_intact_seen;
    mctx->data.spoof_intact_seen    |= ndata.spoof_intact_seen;
    if (ndata.last_sentinel_snat_saddr) {
        free_const(mctx->data.last_sentinel_snat_saddr);
        mctx->data.last_sentinel_snat_saddr = strdup(ndata.last_sentinel_snat_saddr);
    }
    if (ndata.last_spoof_snat_saddr) {
        free_const(mctx->data.last_spoof_snat_saddr);
        mctx->data.last_spoof_snat_saddr = strdup(ndata.last_spoof_snat_saddr);
    }
    if (ndata.last_probe_snat_saddr) {
        free_const(mctx->data.last_probe_snat_saddr);
        mctx->data.last_probe_snat_saddr = strdup(ndata.last_probe_snat_saddr);
    }

    /* if that measurement is done, it was completed sucessfully */
    if (mctx->done)
        successful_measurement_once = 1;

    res = 1;

err_exit:
    if (json_tokener_get_error(jtok) != json_tokener_success) {
        protocol_trace(s, "msmtreq: received invalid message: %s",
                      json_tokener_error_desc(json_tokener_get_error(jtok)));
        res = -EBADMSG;
    } else if (res > 1) {
        protocol_trace(s, "msmtreq: received malformed message");
        res = -EBADMSG;
    }

    json_tokener_free(jtok);
    if (jroot)
        json_object_put(jroot);

    return res;
}

static int sspoofer_msghdl_serverdisconnect(struct sspoof_server * const s,
                    const struct sspoof_ctrl_msghdr * const hdr __attribute__((__unused__)),
                    const void * const data __attribute__((__unused__)) )
{
    protocol_msg(MSG_IMPORTANT, s, "received global disconnection message from measurement peer");
    got_disconnect_msg = 1;
    return 1;
}

static int sspoofer_msghdl_serverclose(struct sspoof_server * const s,
                    const struct sspoof_ctrl_msghdr * const hdr __attribute__((__unused__)),
                    const void * const data __attribute__((__unused__)) )
{
    /* FIXME: drop just this connection */
    return sspoofer_msghdl_serverdisconnect(s, hdr, data);
}


/* State: WAITCONFIG */
const struct sspoof_ctrl_msghandlers sspoofer_messages_waitconfig[] = {
    { .type = SSPOOF_P_MSGTYPE_MACONFIG,    .handler = &sspoofer_msghdl_maconfig },
    { .type = SSPOOF_P_MSGTYPE_CLOSE,       .handler = &sspoofer_msghdl_serverclose },
    { .type = SSPOOF_P_MSGTYPE_DISCONNECT,  .handler = &sspoofer_msghdl_serverdisconnect },
    { .type = SSPOOF_MSGHANDLER_EOL }
};

/* State: MAINLOOP */
const struct sspoof_ctrl_msghandlers sspoofer_messages_mainloop[] = {
    { .type = SSPOOF_P_MSGTYPE_CLOSE,       .handler = &sspoofer_msghdl_serverclose },
    { .type = SSPOOF_P_MSGTYPE_DISCONNECT,  .handler = &sspoofer_msghdl_serverdisconnect },
    { .type = SSPOOF_P_MSGTYPE_MSMTREQ,     .handler = &sspoofer_msghdl_msmtreq },
    { .type = SSPOOF_P_MSGTYPE_MSMTDATA,    .handler = &sspoofer_msghdl_msmtdata },
    { .type = SSPOOF_MSGHANDLER_EOL }
};

/*
 * SIMET2 sspoofer general messages
 *
 * Returns: 0 or -errno
 */

static int sspoofer_msg_maconnect(struct sspoof_server * const s)
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
     * Protocol v1: bidirectional channel
     *    - capabilities support on CONNECT message
     *    - client drains return channel (server->client)
     *    - client ignores unknown messages
     *    - client accepts MA_CONFIG message from server
     *    - capability "simet-spoofer-v1" is required
     */

    json_object_array_add(jcap, json_object_new_string("simet-spoofer-v1"));
    if (client_boot_sync) {
        json_object_array_add(jcap, json_object_new_string("timestamp-zero-at-boot"));
    }
    json_object_object_add(jo, "capabilities", jcap);
    jcap = NULL;

    if (agent_id)
        json_object_object_add(jo, "agent-id", json_object_new_string(agent_id));
    if (agent_token)
        json_object_object_add(jo, "agent-token", json_object_new_string(agent_token)); /* FIXME: not a good idea */

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
    json_object_object_add(jo, "engine-name", json_object_new_string(SIMET_ENGINE_NAME));
    json_object_object_add(jo, "engine-version", json_object_new_string(PACKAGE_VERSION));
#if 0
#ifdef IS_SIMETBOX_BUILD
    json_object_object_add(jo, "agent-family", json_object_new_string("embedded"));
#else
    json_object_object_add(jo, "agent-family", json_object_new_string("system_service"));
#endif
#endif
    if (s->connect_timestamp)
        json_object_object_add(jo, "timestamp-seconds", json_object_new_int64(s->connect_timestamp));

    /* always add a sequence number to the CONNECT message */
    xx_json_object_seqnum_add(jo);

    const char *jsonstr = json_object_to_json_string(jo);
    if (jsonstr) {
        protocol_trace(s, "ma_connect message: %s", jsonstr);
        rc = xx_sspoofer_sndmsg(s, SSPOOF_P_MSGTYPE_CONNECT, strlen(jsonstr), jsonstr);
    } else {
        rc = -EFAULT;
    }

err_exit:
    /* free(jsonstr); -- not! it is managed by json-c */
    json_object_put(jo);

    return rc;
}

/*
 * MSMTSTART message:
 *
 * { "measurement_id": "<measurement_id_string>" }
 */
static int sspoofer_msg_msmtstart(struct sspoof_server * const s,
        struct sspoof_msmt_ctx * const mctx)
{
    if (!mctx || !mctx->measurement_id)
        return -EINVAL;

    json_object *jo = json_object_new_object();
    if (!jo)
        return -ENOMEM;
    json_object_object_add(jo, "measurement_id", json_object_new_string(mctx->measurement_id));

    const char *jsonstr = json_object_to_json_string(jo);
    int rc = xx_sspoofer_sndmsg(s, SSPOOF_P_MSGTYPE_MSMTSTART, strlen(jsonstr), jsonstr);

    json_object_put(jo);
    return rc;
}

/*
 * MSMTFINISH message:
 *
 * { "measurement_id": "<measurement_id_string>" }
 */
static int sspoofer_msg_msmtfinish(struct sspoof_server * const s,
        struct sspoof_msmt_ctx * const mctx)
{
    if (!mctx || !mctx->measurement_id)
        return -EINVAL;

    json_object *jo = json_object_new_object();
    if (!jo)
        return -ENOMEM;
    json_object_object_add(jo, "measurement_id", json_object_new_string(mctx->measurement_id));

    const char *jsonstr = json_object_to_json_string(jo);
    int rc = xx_sspoofer_sndmsg(s, SSPOOF_P_MSGTYPE_MSMTFINISH, strlen(jsonstr), jsonstr);

    json_object_put(jo);
    return rc;
}

/*
 * SIMET2 spoofer connection lifetime messages and handling
 */

/* jump to the disconnect state, unless it is already disconnecting */
static void sspoofer_disconnect(struct sspoof_server * const s)
{
    if (s->state != SSPOOF_P_C_DISCONNECT &&
            s->state != SSPOOF_P_C_DISCONNECT_WAIT &&
            s->state != SSPOOF_P_C_SHUTDOWN) {
        s->state = SSPOOF_P_C_DISCONNECT;
        s->disconnect_clock = 0;

        protocol_msg(MSG_NORMAL, s, "client disconnecting...");
    }
}

/* jump to the reconnect state, used by state machine workers
 *
 * note that we might decide to disconnect instead, if the time budget is over
 * (i.e. we're at the end of the backoff list)
 */
static void sspoofer_reconnect(struct sspoof_server * const s)
{
    if (s->backoff_level >= BACKOFF_LEVEL_MAX-1) {
        sspoofer_disconnect(s);
    } else if (s->state != SSPOOF_P_C_RECONNECT && !got_exit_signal) {
        if (s->backoff_level) {
            protocol_msg(MSG_NORMAL, s, "will attempt to reconnect after %u seconds", backoff_times[s->backoff_level]);
        } else {
            protocol_msg(MSG_NORMAL, s, "attempting to reconnect...");
        }
        s->state = SSPOOF_P_C_RECONNECT;
        s->backoff_clock = reltime();
    }
}

/* returns 0 if we should timeout the remote */
static int sspoofserver_remotetimeout(struct sspoof_server * const s)
{
    assert(s);

    if (!s->remote_keepalive_clock)
        return 1; /* we are not depending on remote keepalives */

    return (timer_check_full(s->remote_keepalive_clock, s->control_timeout) > 0);
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
 *
 * Returning an error will kick the state machine to the
 * shutdown state through the _shutdown() method.
 */

/* usually called when we find out the connection dropped */
static int sspoofserver_shutdown(struct sspoof_server *s)
{
    /* warning: state INIT might not have run! */
    if (s->state != SSPOOF_P_C_INIT && s->conn.socket >= 0) {
        tcp_abort(s->conn.socket);
        s->conn.socket = -1;
        tcpaq_close(&s->conn);
    }

    /* set to -1 when the struct is created, safe before INIT */
    if (s->rawsock >= 0) {
        close(s->rawsock);
        s->rawsock = -1;
    }

    s->state = SSPOOF_P_C_SHUTDOWN;
    s->disconnect_clock = 0;
    return 0;
}

static int sspoofserver_connect_init(struct sspoof_server * const s,
                       const char * const server_name, const char * const server_port)
{
    struct addrinfo ai;
    int backoff;
    int r;

    assert(s && server_name && server_port);
    assert(s->state == SSPOOF_P_C_INIT || s->state == SSPOOF_P_C_RECONNECT);

    if (s->state == SSPOOF_P_C_RECONNECT && s->conn.socket != -1)
        tcpaq_close(&s->conn);

    assert(s->conn.socket == -1);

    /* Backoff timer */
    int waittime_left = timer_check(s->backoff_clock, backoff_times[s->backoff_level]);
    if (waittime_left > 0)
        return waittime_left;
    s->backoff_clock = reltime();
    if (s->backoff_level < BACKOFF_LEVEL_MAX-1)
        s->backoff_level++;
    backoff = (int) backoff_times[s->backoff_level];

    protocol_trace(s, "attempting connection to measurement peer %s, port %s", server_name, server_port);

    s->connect_timestamp = 0;

    /* per-server configuration data defaults */
    s->measurement_timeout = SSPOOFER_DEFAULT_MSMT_TIMEOUT;
    s->control_timeout = sspoofer_tcp_timeout;
    free_const(s->server_description);
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
    ai.ai_family = s->conn.ai_family;
    ai.ai_protocol = IPPROTO_TCP;

    r = getaddrinfo(server_name, server_port, &ai, &s->peer_gai);
    if (r != 0) {
        protocol_trace(s, "getaddrinfo() returned %s", gai_strerror(r));
        goto exit_backoff;
    }

    s->peer_ai = s->peer_gai;

    if (!s->peer_gai) {
        protocol_trace(s, "successfull getaddrinfo() with an empty result set!");
        goto exit_backoff;
    }

    s->state = SSPOOF_P_C_CONNECT;
    return 0;

exit_backoff:
    /* did we exceed the number of retries ? */
    if (s->backoff_level >= BACKOFF_LEVEL_MAX-1) {
        protocol_trace(s, "maximum number of connection retries reached, giving up on peer %s, port %s", server_name, server_port);
        /* we are not connected, no need to go through the disconnect state, fast track to shutdown */
        return sspoofserver_shutdown(s);
    }

    return backoff;
}

static int sspoofserver_connect(struct sspoof_server * const s)
{
    int connected = 0;
    int r;

    assert(s && s->state == SSPOOF_P_C_CONNECT);

    /* create the raw socket to send packets */
    if (s->rawsock >= 0)
        close(s->rawsock);
    s->rawsock = socket(s->conn.ai_family, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, IPPROTO_RAW); /* NEEDS CAP_NET_RAW on Linux */
    if (s->rawsock < 0) {
        protocol_msg(MSG_IMPORTANT, s, "error: could not create RAW socket: %s", strerror(errno));
        return -errno;
    }

    while (s->conn.socket == -1 && s->peer_ai != NULL) {
        struct addrinfo * const airp = s->peer_ai;

        /* avoid fast reconnect to same peer */
        if (s->peer_noconnect_ttl && sspoof_cmpnameinfo(airp, s->conn.ai_family, s->peer_name)) {
            protocol_trace(s, "skipping peer %s on this attempt", s->peer_name);

            s->peer_ai = s->peer_ai->ai_next;
            continue;
        }

        s->conn.socket = socket(airp->ai_family,
                           airp->ai_socktype | SOCK_CLOEXEC | SOCK_NONBLOCK,
                           airp->ai_protocol);
        if (s->conn.socket == -1) {
            s->peer_ai = s->peer_ai->ai_next;
            continue;
        }

        xx_set_tcp_timeouts(s);

        /*
         * connect() can be hard outside of Linux, basically, we cannot
         * portably deal with EINTR.  The only sane path needs a close(),
         * and this is the only reason this whole loop had to be complex
         *
         * http://cr.yp.to/docs/connect.html
         * http://www.madore.org/~david/computers/connect-intr.html
         */
        r = connect(s->conn.socket, airp->ai_addr, airp->ai_addrlen);
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
            close(s->conn.socket);
            s->conn.socket = -1;
            continue;
        }

        close(s->conn.socket);
        s->conn.socket = -1;
        s->peer_ai = s->peer_ai->ai_next;
    }

    if (s->conn.socket == -1) {
        if (s->peer_noconnect_ttl)
            s->peer_noconnect_ttl--;

        /* did we exceed the number of retries ? */
        if (s->backoff_level >= BACKOFF_LEVEL_MAX-1) {
            protocol_trace(s, "maximum number of connection attempts reached");
            /* we are not connected, no need to go through the disconnect state, fast track to shutdown */
            return sspoofserver_shutdown(s);
        }

        const int waittime_left = timer_check(s->backoff_clock, backoff_times[s->backoff_level]);
        if (waittime_left > 0)
            protocol_trace(s, "could not connect, will retry in %d seconds", waittime_left);

        /* go back to the previous state, so that we getaddrinfo() again */
        s->state = SSPOOF_P_C_RECONNECT;
        return (waittime_left > 0)? waittime_left : 0;
    }

    if (connected) {
        s->state = SSPOOF_P_C_CONNECTED;
        return 0;
    }

    s->state = SSPOOF_P_C_CONNECTWAIT;
    return (int) sspoofer_tcp_timeout;
}

static int sspoofserver_connectwait(struct sspoof_server * const s)
{
    int socket_err;
    socklen_t socket_err_sz = sizeof(socket_err);
    int r;

    assert(s && s->state == SSPOOF_P_C_CONNECTWAIT);

    if (s->conn.socket == -1 || !s->peer_ai) {
        /* should never happen, recover */
        s->state = SSPOOF_P_C_RECONNECT;
        return 0;
    }

    /* We could hit this codepath before poll() returned ready for writing or an error */
    struct pollfd pfd = {
        .fd     = s->conn.socket,
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
        return (int) sspoofer_tcp_timeout; /* FIXME: timeout accounting? */

    /* Detect if a pending connect() failed, modern version.
     *
     * Portability hazard:
     * http://cr.yp.to/docs/connect.html
     * http://www.madore.org/~david/computers/connect-intr.html
     */
    if (getsockopt(s->conn.socket, SOL_SOCKET, SO_ERROR, &socket_err, &socket_err_sz))
        socket_err = errno;
    switch (socket_err) {
    case 0:
    case EISCONN:
        /* socket connected */
        s->state = SSPOOF_P_C_CONNECTED;
        break;
    case EALREADY:
    case EINPROGRESS:
        /* Unusual, poll().revents == 0 above is the normal path for this */
        protocol_trace(s, "connectwait: still waiting for connection to complete");
        /* FIXME: timeout accounting explicitly ? */
        return (int) sspoofer_tcp_timeout;
    default:
        protocol_trace(s, "connection attempt failed: %s", strerror(socket_err));

        /* connection attempt failed */
        s->peer_ai = s->peer_ai->ai_next;
        close(s->conn.socket);
        s->conn.socket = -1;

        /* go back to the previous state, to loop */
        s->state = SSPOOF_P_C_CONNECT;
    }

    return 0;
}

static int sspoofserver_connected(struct sspoof_server * const s)
{
    const int int_one = 1;

    /* Get metadata of the connected socket */
    s->sa_peer_len = sizeof(s->sa_peer);
    s->sa_peer.ss.ss_family = AF_UNSPEC;
    if (getpeername(s->conn.socket, (struct sockaddr *)&s->sa_peer, &s->sa_peer_len)) {
        /* Resilience: ENOTCON here is sometimes the only thing that works */
        if (errno == ENOTCONN) {
            protocol_trace(s, "connect: late detection of connection failure");
            goto conn_attempt_failed;
        }
        protocol_trace(s, "connect: getpeername failed: %s", strerror(errno));
    } else if (s->sa_peer_len > sizeof(s->sa_peer)) {
        print_err("connect: internal error: insufficient space for getpeername()");
        exit(SEXIT_INTERNALERR);
    }
    if (sspoof_nameinfo(&s->sa_peer, &s->peer_family, &s->peer_name, &s->peer_port)) {
        print_warn("failed to get peer metadata, coping with it");
    }
    s->peer_noconnect_ttl = 0;

    /* raw socket connection (which is instantaneous) */
    int res;
    do {
        res = connect(s->rawsock, &s->sa_peer.sa, s->sa_peer_len);
    } while (res < 0 && errno == EINTR);
    if (res < 0) {
        print_err("failed to connect RAW socket to peer: %s", strerror(errno));
        goto conn_attempt_failed;
    }

    s->sa_local_len = sizeof(s->sa_local);
    s->sa_local.sa.sa_family = AF_UNSPEC;
    if (getsockname(s->conn.socket, (struct sockaddr *)&s->sa_local, &s->sa_local_len)) {
        protocol_trace(s, "connect: getsockname failed: %s", strerror(errno));
    } else if (s->sa_local_len > sizeof(s->sa_local)) {
        print_err("connect: internal error: insufficient space for getsockame()");
        exit(SEXIT_INTERNALERR);
    }
    if (sspoof_nameinfo(&s->sa_local, &s->local_family, &s->local_name, &s->local_port)) {
        print_warn("failed to get local metadata, coping with it");
    }

    /* Disable Naggle, we don't need it (but we can tolerate it) */
    setsockopt(s->conn.socket, IPPROTO_TCP, TCP_NODELAY, &int_one, sizeof(int_one));

    /* done... */
    s->connect_timestamp = reltime();
    protocol_msg(MSG_NORMAL, s, "connect: local %s address [%s]:%s, remote %s address [%s]:%s",
                  str_ipv46(s->local_family), s->local_name, s->local_port,
                  str_ipv46(s->peer_family), s->peer_name, s->peer_port);

    if (s->peer_gai)
        freeaddrinfo(s->peer_gai);
    s->peer_gai = NULL;
    s->peer_ai = NULL;

    /* try to send first message to server */
    if (sspoofer_msg_maconnect(s)) {
        sspoofer_reconnect(s); /* try next on error */
        return 0;
    }

    /* start tracking server keepalives for timeout */
    sspoofer_keepalive_update(s);
    s->backoff_reset_clock = reltime();

    /* record for UI that we did connect */
    connected_once = 1;

    s->state = SSPOOF_P_C_WAITCONFIG;
    return 0;

conn_attempt_failed:
    /* connection attempt failed */
    s->peer_ai = s->peer_ai->ai_next;
    close(s->conn.socket);
    s->conn.socket = -1;

    /* go back to the previous state, to loop */
    s->state = SSPOOF_P_C_CONNECT;
    return 0;
}

static int sspoofserver_waitconfig(struct sspoof_server * const s)
{
    assert(s);
    assert(s->state == SSPOOF_P_C_WAITCONFIG);

    if (s->ma_config_count < 1)
        return INT_MAX;

    s->state = SSPOOF_P_C_MAINLOOP;

    return 0;
}

/* returns wait time in usec, not sec */
static long sspoofserver_msmtrun(struct sspoof_server * const s)
{
    assert(s);
    assert(s->state == SSPOOF_P_C_MAINLOOP);

    struct sspoof_msmt_ctx *mctx = s->msmt_queue;
    struct timespec ts_next = { .tv_sec = -1 };
    long wait_us = INT_MAX;
    int has_active_mreq = 0;
    int rc;

    /* no measurements? wait for one... */
    if (!mctx)
        return INT_MAX;

    /* empty measurement ? mark it done... */
    if (mctx->msmt_req_count <= 0) {
        protocol_trace(s, "marking empty measurement as done");
        mctx->done = 1;
    }

    /* current active msmt context processing */

    if (!mctx->done && mctx->msmt_req_count > 0) {
        if (!mctx->active) {
            /* Prepare the msmtreqs for the first packet */

            /* create the udp socket to send normal packets and have a source port */
            if (mctx->udpsocket >= 0)
                close(mctx->udpsocket);
            mctx->udpsocket = socket(s->conn.ai_family, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, IPPROTO_UDP);
            if (mctx->udpsocket < 0) {
                protocol_msg(MSG_IMPORTANT, s, "error: could not create UDP socket: %s", strerror(errno));
                return -errno;
            }
            mctx->udp_sa_local_len = sizeof(mctx->udp_sa_local);
            mctx->udp_sa_local.sa.sa_family = AF_UNSPEC;
            if (getsockname(s->conn.socket, &mctx->udp_sa_local.sa, &mctx->udp_sa_local_len)
                    || s->sa_local_len > sizeof(s->sa_local)) {
                if (!errno)
                    errno = ENOBUFS; /* sa_local_len too large */
                protocol_msg(MSG_IMPORTANT, s, "error: getsockname() failed for UDP socket: %s", strerror(errno));
                return -errno;
            } else {
                protocol_msg(MSG_DEBUG, s, "UDP socket: source port %d",
                        ntohs(sockaddr_any_get_port_nbo(&mctx->udp_sa_local)));
            }

            /* send a MSMTSTART message once for the whole context */
            if ((rc = sspoofer_msg_msmtstart(s, mctx)) < 0)
                return rc;
            mctx->active = true;

            /* init fields */
            if (clock_gettime(CLOCK_MONOTONIC, &mctx->ts_start))
                return -errno;
            mctx->ts_next = mctx->ts_start;
            for (int i = 0; i < mctx->msmt_req_count; i++) {
                mctx->msmt_reqs[i].ts_next_pkt = mctx->ts_start;
            }

            /* note that we do not wait an reply from the server */
        }

        struct timespec ts_cur;
        if (clock_gettime(CLOCK_MONOTONIC, &ts_cur))
            return -errno;

        /* loop over the requests in this context */
        if (timespec_le(&mctx->ts_next, &ts_cur)) {
            for (int i = 0; i < mctx->msmt_req_count; i++) {
                struct sspoof_msmt_req * const mreq = &mctx->msmt_reqs[i];

                /* are we done with this one ? */
                if (mreq->grp_sent < mreq->pkt_group_count) {
                    has_active_mreq = 1;
                    if (timespec_le(&mreq->ts_next_pkt, &ts_cur)) {
                        /* send packet(s). <0 = error, >=0 us to next tx */
                        long us_next_pkt = sspoof_msmt_txpkt(s, mctx, mreq);
                        if (us_next_pkt < 0) {
                            return (int)us_next_pkt;
                        }
                        mreq->ts_next_pkt = timespec_add_microseconds(&mreq->ts_next_pkt, us_next_pkt);
                        if (us_next_pkt < wait_us && us_next_pkt >= 0) {
                            wait_us = us_next_pkt;
                        }
                    }
                    if (ts_next.tv_sec == -1 || timespec_lt(&mreq->ts_next_pkt, &ts_next)) {
                        ts_next = mreq->ts_next_pkt;
                    }
                }
            }
            if (!has_active_mreq) {
                /* nothing more to be done on this msmt context */
                mctx->done = 1;
            }
        } else {
            ts_next = mctx->ts_next;
            wait_us = timespec_sub_microseconds(&ts_next, &ts_cur); /* wakeup might overshoot a little, that's fine */
        }

        if (ts_next.tv_sec >= 0) {
            mctx->ts_next = ts_next;
            /* wait_us will have been updated along with ts_next */
        } else {
            mctx->ts_next.tv_sec = 0;
            mctx->ts_next.tv_nsec = 0;
        }
    }

    if (mctx->active && mctx->done) {
        /* pending sending MSMTFINISH to server, waiting last packet */
        rc = sspoofer_msg_msmtfinish(s, mctx);
        if (rc < 0)
            return rc;
        wait_us = 0;

        s->msmt_queue = mctx->next;

        sspoof_msmtctx_enqueue(mctx, &s->msmt_done);

        close(mctx->udpsocket);
        mctx->udpsocket = -1;
    }

    return wait_us;
}

static int sspoofserver_disconnect(struct sspoof_server *s)
{
    /* warning: state INIT might not have run! */
    if (s->conn.socket == -1) {
        /* not connected */
        s->state = SSPOOF_P_C_SHUTDOWN;
        s->disconnect_clock = 0;
        return 0;
    }

    if (!s->disconnect_clock) {
        s->disconnect_clock = reltime();
        protocol_trace(s, "attempting clean disconnection for up to %d seconds", SIMET_DISCONNECT_WAIT_TIMEOUT);
    }

    /* FIXME: send MSG_DISCONNECT/CLOSE to server */
#if 1
    s->state = SSPOOF_P_C_DISCONNECT_WAIT;
    return 0;
#else
    if (!sspoofer_msg_clientlifetime(s, 0)) {
        /* queued sucessfully */
        s->state = SSPOOF_P_C_DISCONNECT_WAIT;
        return 0;
    }

    /* will have to retry queueing again, check timeout */
    int rc = timer_check(s->disconnect_clock, SIMET_DISCONNECT_WAIT_TIMEOUT);
    if (!rc)
        s->state = SSPOOF_P_C_DISCONNECT_WAIT; /* timed out, kick to next stage */

    return rc;
#endif
}

static int sspoofserver_disconnectwait(struct sspoof_server *s)
{
    if (s->conn.socket == -1) {
        /* not connected */
        s->state = SSPOOF_P_C_SHUTDOWN;
        s->disconnect_clock = 0;
        return 0;
    }

    if (!s->disconnect_clock)
        s->disconnect_clock = reltime(); /* should not happen */

    int rc = timer_check(s->disconnect_clock, SIMET_DISCONNECT_WAIT_TIMEOUT);
    if (!rc || tcpaq_is_out_queue_empty(&s->conn)) {
        /* tcpaq queue is empty, or we are out of time */
        tcpaq_close(&s->conn);
        s->conn.socket = -1;
        s->disconnect_clock = 0;

        if (s->rawsock >= 0) {
            close(s->rawsock);
            s->rawsock = -1;
        }

        protocol_msg(MSG_IMPORTANT, s, "client disconnected");

        s->state = SSPOOF_P_C_SHUTDOWN;
        return 0;
    }

    return rc;
}

static void sspoofserver_destroy(struct sspoof_server *s)
{
    if (s) {
        sspoof_msmtctx_destroy(s->msmt_queue);
        sspoof_msmtctx_destroy(s->msmt_done);

        if (s->conn.socket != -1) {
            tcpaq_close(&s->conn);
            s->conn.socket = -1;
            protocol_msg(MSG_IMPORTANT, s, "client forcefully disconnected");
        }

        tcpaq_free_members(&s->conn);

        if (s->rawsock >= 0) {
            close(s->rawsock);
            s->rawsock = -1;
        }

        free_const(s->sid.str);

        if (s->peer_gai)
            freeaddrinfo(s->peer_gai);

        free_const(s->peer_name);
        free_const(s->peer_port);
        free_const(s->local_name);
        free_const(s->local_port);

        free_const(s->server_hostname);
        free_const(s->server_description);
        free_const(s->s_cluster_hostname);

        free(s);
    }
}

static int sspoofserver_create(struct sspoof_server ** const sp,
                               const sa_family_t ai_family,
                               const struct sspoof_server_cluster * const sc)
{
    static unsigned int next_connection_id = 1;

    struct sspoof_server *s;
    int rc;

    if (!sp || !sc || (ai_family != AF_INET && ai_family != AF_INET6))
        return -EINVAL;

    /* this zero-fills the allocated data area */
    s = calloc(1, sizeof(struct sspoof_server));
    if (!s)
        return -ENOMEM;

    s->rawsock = -1;

    if ((rc = tcpaq_init(&s->conn, SIMET_TCPAQ_QUEUESIZE)) != 0) {
        free(s);
        return rc;
    }
    s->conn.ai_family = ai_family;

    s->state = SSPOOF_P_C_INIT;
    s->connection_id = next_connection_id;
    s->cluster = sc;

    next_connection_id++;

    *sp = s;

    return 0;
}

/*
 * server clusters
 */

static struct sspoof_server_cluster * server_cluster_create(const char * const hostname, const char * const port)
{
    struct sspoof_server_cluster *sc;

    if (!hostname)
        return NULL;

    /* malloc and zero-fill */
    sc = calloc(1, sizeof(struct sspoof_server_cluster));
    if (!sc)
        return NULL;

    sc->cluster_name = hostname;
    sc->cluster_port = port;
    return sc;
}

static void free_server_clusters(struct sspoof_server_cluster ** psc)
{
    if (psc) {
        struct sspoof_server_cluster *sc = *psc;

        while (sc) {
            struct sspoof_server_cluster *asc = sc->next;

            free_const(sc->cluster_name); sc->cluster_name = NULL;
            free_const(sc->cluster_port); sc->cluster_port = NULL;
            sc->next = NULL;
            free(sc);

            sc = asc;
        }
        *psc = NULL;
    }
}

/*
 * Configuration
 */

/* returns 0 ok, (-1, errno set) on error. *p unchanged on error */
static int fread_agent_str(const char *path, const char ** const p)
{
    FILE *fp;
    struct stat st;
    char *b;
    int n, e;

    assert(path && p);
    static_assert(SIMET_AGENTID_MAX_LEN < 262144, "you must increase the file size allowed in fread_agent_str()");

    fp = fopen(path, "r");
    if (!fp)
        return -1;

    /* clamp maximum amount of RAM it could cost us to 256KiB */
    if (fstat(fileno(fp), &st)) {
        return -1;
    }
    if (st.st_size > 262144) {
        errno = EINVAL;
        return -1;
    }

    do {
        n = fscanf(fp, " %ms ", &b); /* ENOMEM is relevant */
    } while (n == EOF && errno == EINTR);

    e = (errno)? errno : EINVAL;
    fclose(fp);

    if (n == 1 && e != ENOMEM) {
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
        } else if (validate_nonempty("agent-id", new_aid) || strlen(new_aid) > SIMET_AGENTID_MAX_LEN) {
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
        free_const(agent_id);
        agent_id = new_aid;
    }
    if (agent_token != new_atok) {
        free_const(agent_token);
        agent_token = new_atok;
    }

    if (agent_id)
        print_msg(MSG_NORMAL, "agent-id: %s", agent_id);

    return 0;
}


/*
 * Signal handling
 */

static void handle_exitsig(const int sig)
{
    got_exit_signal = sig;
}

static void init_signals(void)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = &handle_exitsig;

    if (sigaction(SIGQUIT, &sa, NULL) || sigaction(SIGTERM, &sa, NULL))
        print_warn("failed to set signal handlers, clean exit unavailable");
}


/*
 * Command line and main executable
 */

static const char program_copyright[]=
    "Copyright (c) 2024 NIC.br\n\n"
    "This is free software; see the source for copying conditions.\n"
    "There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR\n"
    "A PARTICULAR PURPOSE.\n";

static void print_version(void)
{
    fprintf(stdout, "%s %s\n%s\n", PACKAGE_NAME, PACKAGE_VERSION, program_copyright);
    exit(SEXIT_SUCCESS);
}

static void print_usage(const char * const p, int mode) __attribute__((__noreturn__));
static void print_usage(const char * const p, int mode)
{
    fprintf(stderr, "Usage: %s [-q] [-v] [-h] [-V] [-4|-6] [-t <timeout>] [-i <netdev> ] "
        "[-d <agent-id-path> ] [-m <string>] [-b <boot id>] [-j <token-path> ] [-M <string>] "
        "[-o <path>] [-r <mode>] "
        "<server name>[:<server port>] ...\n", p);

    if (mode) {
        fprintf(stderr, "\n"
            "\t-h\tprint usage help and exit\n"
            "\t-V\tprint program version and copyright, and exit\n"
            "\t-v\tverbose mode (repeat for increased verbosity)\n"
            "\t-q\tquiet mode (repeat for errors-only)\n"
            "\t-4\trestrict to IPv4 (default: both IPv4 and IPv6)\n"
            "\t-6\trestrict to IPv6 (default: both IPv4 and IPv6)\n"
            "\t-t\tinitial tcp protocol timeout in seconds\n"
            "\t-d\tpath to a file with the measurement agent id\n"
            "\t-j\tpath to a file with the access credentials\n"
            "\t-o\tredirect report output to <path>\n"
            "\t-r\treport mode: 0 = comma-separated (default), 1 = json array\n"
            "\n"
            "server name: DNS name of the measurement peer(s)\n"
            "server port: TCP port on the measurement peer\n"
            "\nNote: client will attempt to open one IPv4 and one IPv6 connection to each measurement peer\n");
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
 */
static void sanitize_std_fds(void)
{
   /* do it in file descriptor numerical order! */
   fix_fds(STDIN_FILENO,  O_RDONLY);
   fix_fds(STDOUT_FILENO, O_WRONLY);
   fix_fds(STDERR_FILENO, O_RDWR);
}

static int cmdln_parse_server(char *name, struct sspoof_server_cluster ***ps)
{
    struct sspoof_server_cluster *ne = NULL;
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

    if (r && *r == ':') {
        /* parse optional :<port> */
        r++;
        if (!*r)
            goto err_exit;
        port = strdup_trim(r);
    }

    if (!hostname)
        goto err_exit;

    if (!port) {
        port = strdup(SSPOOFER_DEFAULT_PORT);
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

static void free_server_structures(struct sspoof_server ***as, unsigned int *as_len)
{
    assert(as && as_len);
    if (*as) {
        for (unsigned int i = 0; i < *as_len; i++) {
            sspoofserver_destroy((*as)[i]);
        }
        free(*as);
        *as = NULL;
    }
    *as_len = 0;
}

static int init_server_structures(struct sspoof_server_cluster * const asc,
                       struct sspoof_server ***pservers,
                       unsigned int *pservers_count,
                       sa_family_t family_select)
{
    struct sspoof_server_cluster *sc;
    struct sspoof_server **asrv = NULL;
    unsigned int nservers = 0;
    unsigned int i;
    bool do_ip4, do_ip6;

    assert(pservers && pservers_count);

    do_ip4 = do_ip6 = true;
    switch (family_select) {
    case AF_INET:
        do_ip6 = false;
        break;
    case AF_INET6:
        do_ip4 = false;
    }

    for (sc = asc; sc != NULL; sc = sc->next)
        nservers += do_ip4 + do_ip6; /* one IPv4 and one IPv6 server per cluster */
    if (nservers <= 0) {
        free_server_structures(pservers, pservers_count);
        return 0;
    }

    asrv = calloc(nservers, sizeof(struct sspoof_server *));
    if (!asrv)
        return -ENOMEM;

    for (sc = asc, i = 0; sc != NULL && i < nservers; sc = sc->next) {
        print_msg(MSG_NORMAL, "measurement cluster: %s port %s", sc->cluster_name, sc->cluster_port);
        if ((do_ip4 && sspoofserver_create(&(asrv[i++]), AF_INET, sc)) ||
            (do_ip6 && sspoofserver_create(&(asrv[i++]), AF_INET6, sc)) )
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

static int check_sock_raw(sa_family_t f)
{
    int s = socket(f, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, IPPROTO_RAW);
    int err = errno;
    if (s >= 0)
        close(s);
    return (s < 0)? err : 0;
}

#define ts_zero(x) \
    do { x.tv_sec = 0; x.tv_nsec = 0; } while (0)

int main(int argc, char **argv) {
    int intarg;
    sa_family_t family = AF_UNSPEC;
    int report_mode = SSPOOF_REPORT_MODE_FRAGMENT;

    progname = argv[0];
    sanitize_std_fds();

    init_timekeeping();
    client_start_timestamp = reltime();

    int option;
    /* FIXME: parameter range checking, proper error messages, strtoul instead of atoi */
    while ((option = getopt (argc, argv, "vq46hVr:o:t:d:j:")) != -1) {
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
            if (intarg >= SSPOOFER_SHORTEST_TIMEOUT &&
                    intarg <= SSPOOFER_LONGEST_TIMEOUT) {
                sspoofer_tcp_timeout = (unsigned int)intarg;
            } else {
                print_usage(progname, 1);
            }
            break;
        case 'd':
            agent_id_file = optarg;
            break;
        case 'j':
            agent_token_file = optarg;
            break;

	case '4':
	    family = AF_INET;
	    break;
	case '6':
	    family = AF_INET6;
	    break;

	case 'o':
	    if (freopen(optarg, "w", stdout) == NULL) {
	        print_err("could not redirect output to %s: %s", optarg, strerror(errno));
	        exit(SEXIT_FAILURE);
	    }
	    break;
	case 'r':
	    report_mode = atoi(optarg);
            if (report_mode < 0 || report_mode >= SSPOOF_REPORT_MODE_EOL) {
                print_err("unknown report mode: %s", optarg);
                exit(SEXIT_BADCMDLINE);
            }
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

    if (check_sock_raw(AF_INET) && check_sock_raw(AF_INET6)) {
        print_err("cannot create RAW IP sockets");
        print_err("this program requires either the CAP_NET_RAW capability, or to run as unrestricted root");
        exit(SEXIT_NOADDRFAMILY);
    }

    struct sspoof_server_cluster **ps = &server_clusters;
    while (optind < argc) {
        if (cmdln_parse_server(argv[optind], &ps)) {
            print_err("incorrect measurement peer name or port: %s", argv[optind] ? argv[optind] : "(NULL)");
            print_usage(progname, 0);
        }
        optind++;
    }

    if (!server_clusters) {
        print_err("at least one measurement peer is required");
        print_usage(progname, 0);
    }

    init_signals();

    print_msg(MSG_ALWAYS, PACKAGE_NAME " " PACKAGE_VERSION " starting...");

    /* init */

    log_timekeeping_state();

    if (init_server_structures(server_clusters, &servers, &servers_count, family) < 0)
        goto err_enomem;

    struct pollfd *servers_pollfds = calloc(servers_count, sizeof(struct pollfd));

    if (load_agent_data(agent_id_file, agent_token_file)) {
        print_err("failed to read agent identification credentials");
        return SEXIT_FAILURE;
    }

    print_msg(MSG_ALWAYS, "connecting to measurement peers...");
    connected_once = 0;
    successful_measurement_once = 0;

    /* state machine loop */
    do {
        struct timespec ts_ppoll = { .tv_sec = 300 };
        unsigned int j, num_shutdown;
        int queued_msg_disconnect;

        num_shutdown = 0;

        queued_msg_disconnect = 0;
        if (got_disconnect_msg) {
            queued_msg_disconnect = 1;
            got_disconnect_msg = 0;
        }

        for (j = 0; j < servers_count; j++) {
            struct sspoof_server *s = servers[j];
            long wait_us = 0; /* microseconds */
            int wait = 0; /* seconds */
            int rc;

            if (got_exit_signal)
                sspoofer_disconnect(s);

#if 0
            print_msg(MSG_TRACE, "%s(%u): main loop, currently at state %u, ts_ppoll=(%ld.%09ld)",
                    str_ipv46(s->local_family), s->connection_id, s->state, (long)ts_ppoll.tv_sec, (long)ts_ppoll.tv_nsec);
#endif

            switch (s->state) {
            case SSPOOF_P_C_INIT:
                assert(s->conn.socket == -1 && s->conn.out_queue.buffer && s->conn.in_queue.buffer && s->cluster);
                servers_pollfds[j].fd = -1;
                /* fall-through */
            case SSPOOF_P_C_RECONNECT:
                if (queued_msg_disconnect) {
                    sspoofserver_disconnect(s);
                    wait = 0;
                    break;
                }
                wait = sspoofserver_connect_init(s, s->cluster->cluster_name, s->cluster->cluster_port); /* returns >= 0 */
                servers_pollfds[j].fd = -1;
                break;
            case SSPOOF_P_C_CONNECT:
                wait = sspoofserver_connect(s);
                servers_pollfds[j].fd = s->conn.socket;
                servers_pollfds[j].events = POLLRDHUP | POLLIN | POLLOUT | POLLERR;
                break;
            case SSPOOF_P_C_CONNECTWAIT:
                wait = sspoofserver_connectwait(s);
                break;
            case SSPOOF_P_C_CONNECTED:
                wait = sspoofserver_connected(s);
                servers_pollfds[j].events = POLLRDHUP | POLLIN;
                break;

            case SSPOOF_P_C_WAITCONFIG:
                if (queued_msg_disconnect) {
                    sspoofer_disconnect(s);
                    wait = 0;
                    break;
                }

                /* process return channel messages, we want MA_CONFIG */
                /* we must process just one message at a time here. */
                if (sspoofer_recvmsg(s, sspoofer_messages_waitconfig) < 0) {
                    sspoofer_disconnect(s);
                    wait = 0;
                    break;
                }

                if (got_disconnect_msg)
                    break;

                if (!sspoofserver_remotetimeout(s)) {
                    /* remote keepalive timed out */
                    protocol_msg(MSG_NORMAL, s, "measurement peer connection lost: ma_config not received");
                    sspoofer_disconnect(s);
                    wait = 0;
                    break;
                }

                wait = sspoofserver_waitconfig(s);
                break;

            case SSPOOF_P_C_MAINLOOP:
                if (queued_msg_disconnect) {
                    sspoofer_disconnect(s);
                    wait = 0;
                    break;
                }

                /* process return channel messages */
                while ((rc = sspoofer_recvmsg(s, sspoofer_messages_mainloop)) > 0);
                if (rc < 0) {
                    sspoofer_disconnect(s);
                    wait = 0;
                    break;
                }

                if (got_disconnect_msg)
                    break;

                if (!sspoofserver_remotetimeout(s)) {
                    /* remote keepalive timed out */
                    protocol_msg(MSG_NORMAL, s, "measurement peer connection lost: silent for too long");
                    sspoofer_disconnect(s);
                    wait = 0;
                    break;
                }

                /* process measurements */
                wait = 0;
                wait_us = sspoofserver_msmtrun(s);
                if (wait_us < 0) {
                    sspoofer_disconnect(s);
                    break;
                }
                break;

            case SSPOOF_P_C_DISCONNECT:
                wait = sspoofserver_disconnect(s);
                if (sspoofserver_drain(s) < 0)
                    sspoofserver_shutdown(s); /* fast track */
                break;
            case SSPOOF_P_C_DISCONNECT_WAIT:
                wait = sspoofserver_disconnectwait(s);
                if (sspoofserver_drain(s) < 0)
                    sspoofserver_shutdown(s); /* fast track */
                break;

            case SSPOOF_P_C_SHUTDOWN:
                /* warning: state INIT might not have run! */
                num_shutdown++;
                servers_pollfds[j].fd = -1;
                wait = INT_MAX;
                break;

            default:
                print_err("internal error or memory corruption");
                return SEXIT_INTERNALERR;
            }

            /* wait == 0 means ts_ppoll should be zero unless wait_us > 0 */
            /* wait_us == 0 means we should ignore it, and look just at wait */
#if 0
            protocol_msg(MSG_TRACE, s, "before ppoll change: wait = %d, wait_us = %ld, pts_ppoll=(%ld.%09ld)", wait, wait_us, (long)ts_ppoll.tv_sec, ts_ppoll.tv_nsec);
#endif

            if (wait < 0 || wait_us < 0) {
                print_err("giving up on measurement peer and closing connection");
                sspoofserver_shutdown(s);
                ts_zero(ts_ppoll);
            } else if (wait >= 0 || wait_us > 0) {
                struct timespec ts_wait = microseconds_to_timespec(wait_us);
                ts_wait.tv_sec += wait;
                if (ts_wait.tv_sec > 7)
                    ts_wait.tv_sec = 7;
#if 0
                protocol_msg(MSG_TRACE, s, "will update ppoll: ts_wait=(%ld.%09ld), ts_ppoll=(%ld.%09ld)", (long)ts_wait.tv_sec, ts_wait.tv_nsec, (long)ts_ppoll.tv_sec, ts_ppoll.tv_nsec);
#endif
                if (timespec_lt(&ts_wait, &ts_ppoll)) {
                    ts_ppoll = ts_wait;
                }
            }
#if 0
            protocol_msg(MSG_TRACE, s, "after ppoll change: wait = %d, wait_us = %ld, pts_ppoll=(%ld.%09ld)", wait, wait_us, (long)ts_ppoll.tv_sec, ts_ppoll.tv_nsec);
#endif
            if (sspoofserver_flush(s)) {
                sspoofer_disconnect(s);
                ts_zero(ts_ppoll);
            }

#if 0
            print_msg(MSG_TRACE, "%s(%u): main loop: before next stream: currently at state %u, ts_ppoll=(%ld.%09ld)",
                    str_ipv46(s->local_family), s->connection_id, s->state, (long)ts_ppoll.tv_sec, (long)ts_ppoll.tv_nsec);
#endif
        }

#if 0
        print_msg(MSG_TRACE, "main loop: stream loop end, ts_ppoll=(%ld.%09ld), num_shut=%u, serv_count=%u", (long)ts_ppoll.tv_sec, (long)ts_ppoll.tv_nsec, num_shutdown, servers_count);
#endif

        if (num_shutdown >= servers_count)
            break;

        if (got_disconnect_msg)
            ts_zero(ts_ppoll);

        /* ts_ppoll assumed normalized, and tv_sec never negative */
        if (ts_ppoll.tv_sec > 0 || ts_ppoll.tv_nsec > 0) {
            /* optimized for a small number of servers */
            int poll_res = ppoll(servers_pollfds, servers_count, &ts_ppoll, NULL);
            if (poll_res > 0) {
                for (j = 0; j < servers_count; j++) {
                    if (servers_pollfds[j].revents & (POLLRDHUP | POLLHUP | POLLERR)) {
                        if (servers[j]->state >= SSPOOF_P_C_CONNECTED
                            && servers[j]->state < SSPOOF_P_C_SHUTDOWN)
                        {
                            protocol_msg(MSG_NORMAL, servers[j], "connection to measurement peer lost");
                            sspoofserver_shutdown(servers[j]); /* fast close/shutdown detection */
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
    } while (1); /* FIXME: got_exit_signal already set for some time, also */

    free(servers_pollfds);
    servers_pollfds = NULL;

    if (got_exit_signal) {
        print_msg(MSG_NORMAL, "received exit signal %d, exiting...", got_exit_signal);
        return 128 + got_exit_signal;
    }

    if (!connected_once) {
        print_msg(MSG_NORMAL, "could not connect to any measurement peers");
        return SEXIT_MP_REFUSED;
    } else {
        print_msg(MSG_NORMAL, "all measurement peer connections closed");
    }

    if (!successful_measurement_once) {
        print_msg(MSG_IMPORTANT, "measurement failed");
        return SEXIT_FAILURE;
    }

    int rc = sspoof_render_report(servers, servers_count, report_mode);

    free_server_structures(&servers, &servers_count);
    free_server_clusters(&server_clusters);

    if (rc == -ENOMEM) {
        goto err_enomem;
    }
    if (rc == -ENODATA) {
        print_msg(MSG_IMPORTANT, "no data to report...");
        return SEXIT_MP_REFUSED;
    }
    if (rc < 0) {
        print_err("failed to render report");
        rc = SEXIT_FAILURE;
    }
    return rc;

err_enomem:
    print_err("out of memory");
    return SEXIT_OUTOFRESOURCE;
}

/* vim: set et ts=8 sw=4 : */
