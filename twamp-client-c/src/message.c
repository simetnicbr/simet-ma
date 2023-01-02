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

#include "message.h"

#include "logger.h"

#include <stdint.h>
#include <limits.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>

#include <arpa/inet.h>

/********************/
/* MESSAGES READERS */
/********************/

/* Returns -1 on error (errno set), amount of data received otherwise */
/* may have partially filled the buffer on some error conditions */
static ssize_t xrecv(const int socket, const int timeout, uint8_t *buf, const size_t buf_size)
{
    fd_set rset, rset_master;
    struct timeval tv_timeo;

    if (socket < 0 || timeout < 0 || !buf || !buf_size || buf_size >= SSIZE_MAX) {
	errno = EINVAL;
	return -1;
    }

    memset(buf, 0, buf_size);
    FD_ZERO(&rset_master);
    FD_SET(socket, &rset_master);

    tv_timeo.tv_sec = timeout;
    tv_timeo.tv_usec = 0;

    size_t recv_total = 0;
    size_t buf_free = buf_size;
    while (buf_free > 0) {
        memcpy(&rset, &rset_master, sizeof(rset_master));

	/* we depend on linux select() behavior that updates the timeout */
        int fd_ready = select(socket+1, &rset, NULL, NULL, &tv_timeo);
	if (fd_ready < 0 && errno != EINTR) {
	    goto err_exit;
	} else if (fd_ready == 0) {
	    errno = ETIMEDOUT;
	    goto err_exit;
	} else if (fd_ready > 0 && FD_ISSET(socket, &rset)) {
	    ssize_t recv_size = recv(socket, buf, buf_free, MSG_DONTWAIT);
	    if (recv_size < 0) {
		if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
		    continue;
		goto err_exit;
	    } else {
		if (recv_size == 0)
		    break; /* socket closed / shutdown */
		buf += recv_size;
		recv_total += (size_t) recv_size; /* verified, recv_size > 0 */
		buf_free -= (size_t) recv_size; /* verified, recv_size > 0 */
	    }
	}
    }

    return (ssize_t) recv_total; /* verified, buf_size fits ssize_t, recv_total <= bufsize */

err_exit:
    print_err("error receiving data from server: %s", strerror(errno));
    return -1;
}

/* Returns -1 on error (errno set), ETIMEDOUT/EBADMSG if not enough data received, msg_size otherwise */
static ssize_t xrecv_msg(const int socket, const int timeout, void * const msg, const size_t msg_size)
{
    ssize_t r = xrecv(socket, timeout, (uint8_t *)msg, msg_size);
    if (r < 0)
	return -1;
    if (r != (ssize_t)msg_size) {
	errno = EBADMSG;
	return -1;
    }
    return r;
}

ssize_t message_server_greetings(const int socket, const int timeout, ServerGreeting * const srvGreetings) {
    print_msg(MSG_DEBUG, "Waiting server gretings message");
    ssize_t r = xrecv_msg(socket, timeout, srvGreetings, sizeof(ServerGreeting));
    if (r < 0)
	return -1;

    srvGreetings->Modes = ntohl(srvGreetings->Modes);
    srvGreetings->Count = ntohl(srvGreetings->Count);

    return r;
}

ssize_t message_server_start(const int socket, const int timeout, ServerStart * const srvStart) {
    print_msg(MSG_DEBUG, "Waiting server start message");

    ssize_t r = xrecv_msg(socket, timeout, srvStart, sizeof(ServerStart));
    if (r < 0)
	return -1;

    srvStart->StartTime.integer = ntohl(srvStart->StartTime.integer);
    srvStart->StartTime.fractional = ntohl(srvStart->StartTime.fractional);

    return r;
}

ssize_t message_accept_session(const int socket, const int timeout, AcceptSession * const actSession) {
    print_msg(MSG_DEBUG, "Waiting acept session message");

    ssize_t r = xrecv_msg(socket, timeout, actSession, sizeof(AcceptSession));
    if (r < 0)
	return -1;

    actSession->Port = ntohs(actSession->Port);

    return r;
}

ssize_t message_start_ack(const int socket, const int timeout, StartAck * const strAck) {
    print_msg(MSG_DEBUG, "Waiting start ack message");

    return xrecv_msg(socket, timeout, strAck, sizeof(StartAck));
}

/********************/
/* MESSAGES SENDERS */
/********************/

/* Returns -1 on error, errno set. amount of data sent otherwise */
/* note: used both for TCP (TWAMP_CONTROL) and UDP (TWAMP_TEST) */
ssize_t message_send(const int socket, const int timeout, void * const message, const size_t len) {
    fd_set wset, wset_master;
    struct timeval tv_timeo;
    int err;

    if (!message || socket < 0 || len >= SSIZE_MAX) {
	errno = EINVAL;
	return -1;
    }

    FD_ZERO(&wset_master);
    FD_SET(socket, &wset_master);

    tv_timeo.tv_sec = timeout;
    tv_timeo.tv_usec = 0;

    uint8_t *buf = message;
    size_t buf_remain = len;
    size_t total_sent = 0;
    while (buf_remain > 0) {
        memcpy(&wset, &wset_master, sizeof(wset_master));

	/* we depend on linux select() behavior that updates the timeout */
        int fd_ready = select(socket+1, NULL, &wset, NULL, &tv_timeo);
	if (fd_ready < 0 && errno != EINTR) {
	    goto err_exit;
	} else if (fd_ready == 0) {
	    errno = ETIMEDOUT;
	    goto err_exit;
	} else if (fd_ready > 0 && FD_ISSET(socket, &wset)) {
            ssize_t sent_size = send(socket, buf, buf_remain, MSG_DONTWAIT);
	    if (sent_size < 0) {
		if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
		    continue;
		goto err_exit;
	    } else {
		buf += sent_size;
		total_sent += (size_t) sent_size; /* verified, sent_size >= 0 */
		buf_remain -= (size_t) sent_size; /* verified, sent_size >= 0 */
	    }
	}
    }

    /* should never happen, but callers would break if we don't flag it as an error */
    if (total_sent != len) {
	errno = EBADMSG; /* for symmetry with xrecv() */
	goto err_exit;
    }

    return (ssize_t) total_sent; /* verified, len < SSIZE_MAX, total_sent <= len */

err_exit:
    err = errno;
    print_err("error sending data to server: %s", strerror(err));
    errno = err;
    return -1;
}


/***********************/
/* MESSAGES VALIDATORS */
/***********************/

int message_validate_server_greetings(ServerGreeting *srvGreetings) {
    if (srvGreetings->Modes == 0) {
        print_msg(MSG_IMPORTANT, "the server does not wish to communicate");
        return -1;
    }
    if ((srvGreetings->Modes & 1) != 1) {
	print_msg(MSG_IMPORTANT, "the server does not support unauthenticated mode");
	return -1;
    }

    if ((srvGreetings->Modes & 64) != 64) {
	print_msg(MSG_IMPORTANT, "the server seems not to support symmetric mode, measurement may fail");

	/* We just warn about it because older versions of the SIMET2
	 * server did not set this bit correctly.  The perfSonar server
	 * doesn't announce symmetric mode support either, and yet
	 * replies with symmetric-compatible packets just like we used
	 * to.
	 *
	 * For that reason, it is best if we simply try the measurement,
	 * we can add heuristics that abort with the appropriate error
	 * when we discard an incorrectly-sized reply if bit 6 is
	 * unset...
	 */
    }

    return 0;
}

/***********************/
/* MESSAGES FORMATTERS */
/***********************/

int message_format_setup_response(ServerGreeting *srvGreetings, SetupResponse *stpResponse) {
    /* We want TWAMP unauthenticated mode, and RFC-6038 symmetric packets */

    /* note: older SIMET2 twamp reflectors do not set bit 6 but always operate in symmetric mode */
    stpResponse->Mode = htonl(srvGreetings->Modes & (0b1000001U));

    return 0;
}

int message_format_request_session(int ipvn, size_t padding_size, uint16_t sender_port, RequestSession *rqtSession) {
    rqtSession->Type = 5;

    /* redundant, all zeroes already */
    rqtSession->ConfSender = 0;
    rqtSession->ConfReceiver = 0;
    rqtSession->SlotsNo = 0;
    rqtSession->PacketsNo = 0;

    rqtSession->IPVN = (uint8_t)ipvn;

    uint16_t size;
    if (padding_size > MAX_TSTPKT_SIZE || padding_size > UINT16_MAX) {
	size = MAX_TSTPKT_SIZE;
    } else if (padding_size < MIN_TSTPKT_SIZE) {
	size = MIN_TSTPKT_SIZE;
    } else {
	size = (uint16_t)padding_size;
    }
    rqtSession->PaddingLength = htonl(size - OWAMP_PAD_OFFSET); /* FIXME: auth packet changes this */

    /* redundant, all zeroes already */
    rqtSession->SenderAddress = htonl(0);
    rqtSession->ReceiverAddress = htonl(0);

    rqtSession->SenderPort = htons(sender_port);
    rqtSession->ReceiverPort = htons(862);

    /* Timeout and StartTime are already all-zeroes timestamps,
     * and this is correct for TWAMP.  We do not need any wait
     * after we issue the Stop Sessions command */

    return 0;
}

int message_format_stop_sessions(StopSessions *stpSessions) {
    stpSessions->Type = 3;
    stpSessions->Accept = 0;

    stpSessions->SessionsNo = htonl(1);

    return 0;
}
