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

#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>

#include <limits.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <assert.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <time.h>

#include "simet-inetuptime.h"
#include "tcpaq.h"
#include "simet_err.h"
#include "logger.h"

#include "sys-linux.h"

/* FIXME:
 * logging callback?
 */

#define protocol_trace(protocol_stream, format, arg...) \
    print_msg(MSG_TRACE, format, ## arg);

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

/**
 * tcpaq_init: initalizes a tcpaq_conn struct for use
 *
 * @s:     pointer to struct tcpaq_conn to initialize (already allocated)
 * @qsize: size of the queue buffers (will be allocated and owned by the struct)
 *
 * Allocates and initalizes the queues, sets socket to -1, and ai_family to
 * AF_UNSPEC.
 *
 * returns: 0, -ENOMEM, -EINVAL
 */
int tcpaq_init(struct tcpaq_conn * const s, size_t qsize)
{
    if (!s)
        return -EINVAL;
    if (!qsize || qsize > SSIZE_MAX)
        return -EINVAL;

    memset(s, 0, sizeof(struct tcpaq_conn));
    s->socket = -1;
    s->ai_family = AF_UNSPEC;
    s->out_queue.buffer = calloc(1, qsize);
    s->in_queue.buffer = calloc(1, qsize);
    if (!s->out_queue.buffer || !s->in_queue.buffer) {
        free(s->out_queue.buffer);
        free(s->in_queue.buffer);
        return -ENOMEM;
    }
    s->out_queue.buffer_size = qsize;
    s->in_queue.buffer_size = qsize;

    return 0;
}

/**
 * tcpaq_free_members: free fields of a tcpaq_conn struct, but not the struct itself
 *
 * @s: pointer to struct tcpaq_conn, whose internal fields will be freed.
 *     can be NULL.
 */
void tcpaq_free_members(struct tcpaq_conn * const s)
{
    if (s) {
        free(s->out_queue.buffer);
        s->out_queue.buffer = NULL;
        free(s->in_queue.buffer);
        s->in_queue.buffer = NULL;
    }
}

void tcpaq_close(struct tcpaq_conn * const s)
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

int tcpaq_reserve(struct tcpaq_conn * const s, size_t size)
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
int tcpaq_unreserve(struct tcpaq_conn * const s, size_t size)
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
int tcpaq_queue(struct tcpaq_conn * const s, void *data, size_t size, int reserved)
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
        print_warn("internal error: fd %d: stream went past reservation, coping with it", s->socket);
        s->out_queue.wr_pos_reserved = s->out_queue.wr_pos;
    }

    return 0;
}

int tcpaq_is_out_queue_empty(struct tcpaq_conn * const s)
{
    /* do it in a fail-safe manner against queue accounting bugs */
    return (s->out_queue.rd_pos >= s->out_queue.wr_pos || s->out_queue.rd_pos >= s->out_queue.buffer_size);
}

static void xx_tcpaq_compact(struct tcpaq_conn * const s)
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

int tcpaq_send_nowait(struct tcpaq_conn * const s)
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

    /* FIXME: this would need to know whether we are already in NODELAY mode
     * or not, otherwise we'd always disable it */

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
static int tcpaq_send_timeout(struct tcpaq_conn * const s, time_t timeout)
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
static int xx_tcpaq_is_in_queue_empty(struct tcpaq_conn * const s)
{
    /* do it in a fail-safe manner against queue accounting bugs */
    return (s->in_queue.rd_pos >= s->in_queue.wr_pos || s->in_queue.rd_pos >= s->in_queue.buffer_size);
}

/* discards all pending receive data, returns 0 for nothing discarded, NZ for something, <0 error */
int tcpaq_drain(struct tcpaq_conn * const s)
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
int tcpaq_discard(struct tcpaq_conn * const s, size_t object_size)
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
static int tcpaq_request_receive_nowait(struct tcpaq_conn * const s, size_t object_size)
{
    int res;
    ssize_t rcvres;

    assert(s && s->in_queue.buffer);

    /* skip any cruft we are still discarding */
    res = tcpaq_discard(s, 0);
    if (res <= 0)
        return res;

    /* note: tcpaq_discard() > 0 ensures s->in_queue.wr_pos_reserved = 0 */

    if (object_size > SIMET_TCPAQ_QUEUESIZE)
        return -EFAULT; /* we can't do it */

    size_t unread_bufsz = 0;
    if (s->in_queue.wr_pos > s->in_queue.rd_pos)
        unread_bufsz = s->in_queue.wr_pos - s->in_queue.rd_pos;

    if (unread_bufsz >= object_size)
        return 1; /* we have enough buffered data */

    object_size -= unread_bufsz;
    if (s->in_queue.wr_pos + object_size > SIMET_TCPAQ_QUEUESIZE) {
        /* compress buffer */
        memmove(s->in_queue.buffer, s->in_queue.buffer + s->in_queue.rd_pos, unread_bufsz);
        s->in_queue.wr_pos = unread_bufsz;
        s->in_queue.rd_pos = 0;
    }

    /* paranoia, must not happen */
    if (s->in_queue.wr_pos + object_size > SIMET_TCPAQ_QUEUESIZE)
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
 * Size is limited to SIMET_TCPAQ_QUEUESIZE.  Does not wait,
 * returns 0 if there is not enough received buffer yet.  If
 * buf is NULL, discards the data.
 *
 * Returns:
 *   < 0: -errno
 *   0  : not enough data buffered
 *   NZ : requested object is in *buf
 */
int tcpaq_receive_nowait(struct tcpaq_conn * const s, size_t object_size, void *buf)
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
 * Size is limited to SIMET_TCPAQ_QUEUESIZE.  Does not wait,
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
int tcpaq_peek_nowait(struct tcpaq_conn * const s, size_t object_size, const char **pbuf)
{
    int res = tcpaq_request_receive_nowait(s, object_size);
    if (pbuf)
        *pbuf = (res > 0) ? s->in_queue.buffer + s->in_queue.rd_pos : NULL;
    return res;
}

/* vim: set et ts=4 sw=4 : */
