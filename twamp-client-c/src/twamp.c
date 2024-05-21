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

#include "twampc_config.h"
#include "twamp.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <stdio.h>

#include <unistd.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>
#include <arpa/inet.h>

#include <assert.h>
#if !defined(static_assert) && defined(__STDC_VERSION__) && (__STDC_VERSION__ < 202301L)
#  define static_assert _Static_assert
#endif

#include "retry.h"
#include "simet_err.h"
#include "logger.h"
#include "report.h"
#include "timespec.h"

#include "libubox/usock.h"

/* Ensure some invariants the code assumes */
static_assert(sizeof(int) >= 4, "code assumes (int) is at least 32 bits");
static_assert(sizeof(long long) >= 8, "code assumes (long long int) is at least 64 bits");

static int receive_reflected_packet(int socket, const struct timespec * const ts_stop,
                                    UnauthReflectedPacket *reflectedPacket,
                                    size_t expected_size, size_t *recv_total,
                                    struct timespec * const ts_recv);
static void *twamp_callback_thread(void *param);
static int twamp_test(TWAMPContext * const);

static int usock_convert_family(sa_family_t family) {
    if (family == AF_INET) {
        return USOCK_IPV4ONLY;
    } else if (family == AF_INET6) {
        return USOCK_IPV6ONLY;
    } else {
        return 0;
    }
}

static char *get_ip_str(const struct sockaddr_storage *sa, char *s, socklen_t maxlen)
{
    switch(sa->ss_family) {
        case AF_INET:
            inet_ntop(AF_INET, &(((struct sockaddr_in *)sa)->sin_addr),s, maxlen);
            break;

        case AF_INET6:
            inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)sa)->sin6_addr),s, maxlen);
            break;

        default:
            strncpy(s, "Unknown AF", maxlen);
            return NULL;
    }

    return s;
}

static void sa_set_port(struct sockaddr_storage *sa, in_port_t port) {
    /* htons() */
    static_assert(sizeof(in_port_t) == sizeof(unsigned short), "in_port_t is not an alias for unsigned short int");

    switch(sa->ss_family) {
        case AF_INET:
            ((struct sockaddr_in *)sa)->sin_port = htons(port);
            break;

        case AF_INET6:
            ((struct sockaddr_in6 *)sa)->sin6_port = htons(port);
            break;
    }
}

/* generates an "id cookie" from server data; returns 0 for cookie disabled */
static int simet_generate_cookie(struct simet_cookie *cookie, const void * const src, size_t src_sz)
{
    if (!cookie || !src || !src_sz)
        return 0;

    uint8_t * sbuf = (uint8_t *)src;
    size_t i;
    for (i = 0; sbuf[i] == 0 && i < src_sz; i++);
    if (i >= src_sz)
        return 0; /* all zeroes */

    cookie->sig = htonl(SIMET_TWAMP_IDCOOKIE_V1SIG);
    size_t s = sizeof(cookie->data);
    if (s > src_sz) {
        memset(cookie->data, 0, sizeof(cookie->data));
        s = src_sz;
    }
    memcpy(cookie->data, src, s);
    return 1;
}

/* embedds cookie into padding, if there's enough space */
static void simet_cookie_as_padding(void * const dst, size_t dst_sz, const struct simet_cookie * const cookie)
{
    if (dst && dst_sz && cookie)
        memcpy(dst, cookie, sizeof(struct simet_cookie) <= dst_sz ? sizeof(struct simet_cookie) : dst_sz);
}
static_assert(sizeof(struct simet_cookie) < MIN_TSTPKT_SIZE - offsetof(UnauthPacket, Padding),
              "struct simet_cookie must fit inside the padding of the smallest acceptable TEST packet");

static void simet_auth_as_padding(void * const dst, size_t dst_sz, const TWAMPKey *key)
{
    if (key && key->len > 0 && dst_sz > sizeof(struct stamp_private_tlv) + key->len) {
        struct stamp_private_tlv * const a = (struct stamp_private_tlv *)dst;
        const size_t len = key->len + (offsetof(struct stamp_private_tlv, data) - sizeof(struct stamp_tlv_header));
        if (len <= 0xffff) {
            a->hdr.flags  = 0x80; /* U=1 */
            a->hdr.type   = SIMET_STAMP_AUTHTLV_TYPE;
            a->hdr.length = htons((uint16_t)len);
            a->private_enterprise_number = htonl(SIMET_STAMP_TLV_PEN);
            a->simet_tlv_sub_type = htons(SIMET_STAMP_TLV_AUTHCOOKIE);
            memcpy(&a->data, key->data, key->len);
        }
    }
}
static_assert(offsetof(struct stamp_private_tlv, data) > sizeof(struct stamp_tlv_header), "code incompatible with struct stamp_private_tlv, refactor it!");
static_assert(sizeof(struct stamp_private_tlv) + SIMET_TWAMP_AUTH_MAXKEYSIZE < MIN_TSTPKT_SIZE - offsetof(UnauthPacket, Padding),
              "struct stamp_private_tlv + SIMET_TWAMP_AUTH_MAXKEYSIZE must fit inside the padding of the smallest acceptable TEST packet");

static int twamp_pktdata_init(unsigned int num_packets, ReportPacket **pbuffer)
{
    if (!pbuffer)
        return SEXIT_INTERNALERR;

    *pbuffer = calloc(num_packets, sizeof(ReportPacket));
    if (! *pbuffer) {
        print_err("Error allocating memory for raw_data");
        return SEXIT_OUTOFRESOURCE;
    }

    return 0;
}

static int twamp_run_prepare(TWAMPContext *t_ctx, TWAMPParameters *param)
{
    if (!t_ctx || !param)
        return SEXIT_INTERNALERR;

    memset(t_ctx, 0, sizeof(*t_ctx));

    if (param->packets_count > param->packets_max) {
        print_err("Configuration error: packet train length (%u) too big (max %u)", param->packets_count, param->packets_max);
        return SEXIT_BADCMDLINE;
    }

    if (param->packets_count <= 0) {
        print_err("Configuration error: packet train length too small");
        return SEXIT_BADCMDLINE;
    }

    /* Make room for one extra packet, which acts as a sentinel of
     * too-many-dupes.
     *
     * This only exists because we have an external requirement that we
     * have to be able to handle at least 100% packet duplication.
     *
     * NOTE: we do not process this last packet, it is received and
     * stored, but discarded as lost when processing.  If you remove
     * this line, you must adjust the post-receive routines to not
     * ignore the last packet when packets_received == packets_max.
     */
    param->packets_max++;

    // Create TWAMPReport
    TWAMPReport * report = twamp_report_init(param->family, param->host);
    if (!report || !report->result) {
        print_err("Error initializing TWAMP report");
        return SEXIT_OUTOFRESOURCE;
    }
    // Init receive buffer
    int rc = twamp_pktdata_init(param->packets_max, &report->result->pkt_data);
    if (rc)
        return rc;

    memcpy(&t_ctx->param, param, sizeof(t_ctx->param));
    t_ctx->report = report;
    return 0;
}

/* Returns -1 on error (error messages printed), 0 + res on success */
/* caller needs to freeaddrinfo(res) when done.  res == NULL is possible */
static int twamp_resolve_host(const char * const host, const char * const port, const sa_family_t family,
                       const int socktype, const int protocol, struct addrinfo ** const res)
{
    if (!res)
        return -1; /* should never happen */

    struct addrinfo hints = {
        .ai_family = family,
        .ai_socktype = socktype,
        .ai_protocol = protocol,
        .ai_flags = AI_ADDRCONFIG,
    };

    int r = RETRY_GAI(getaddrinfo(host, port, &hints, res));
    if (r) {
        print_err("could not resolve %s%s%s: %s", (host)? host : "", (port)? ":" : "", (port)? port : "", gai_strerror(r));
        return -1;
    }

    return 0;
}

/* Returns bound and connected socket, or -1 + errno */
/* note: ss_source better be compatible with the contents of dest_list, or else this call *will* fail */
/* note: optiized for UDP right now, so assumes immediate connect() */
static int twamp_connect(const struct sockaddr_storage * const ss_source, struct sockaddr_storage * const sa, struct addrinfo *dest_list)
{
    int family = AF_UNSPEC;
    int fd_test = -1;
    int err = ENOENT;

    for (const struct addrinfo *ai = dest_list; ai != NULL; ai = ai->ai_next) {
        if (ai->ai_addrlen > sizeof(struct sockaddr_storage)) {
            /* HUH?! */
            err = EINVAL;
            break;
        }

        if (fd_test < 0 || family != ai->ai_family) {
            if (fd_test >= 0)
                close(fd_test);

            family = ai->ai_family;
            fd_test = socket(family, ai->ai_socktype, ai->ai_protocol);
            if (fd_test < 0) {
                return -1;
            }
        }

        /* local address override */
        if (ss_source &&
                bind(fd_test, (const struct sockaddr *)ss_source, sizeof(*ss_source)) < 0) {
            err = errno;
            continue;
        }

        if (RETRY_EINTR(connect(fd_test, ai->ai_addr, ai->ai_addrlen) < 0)) {
            err = errno;
            continue;
        }

        /* connected */
        err = 0;
        if (sa) {
            memcpy(sa, ai->ai_addr, ai->ai_addrlen);
        }
        break;
    }

    if (err) {
        if (fd_test >= 0)
            close(fd_test);

        fd_test = -1;
    }
    errno = err;
    return fd_test;
}

int twamp_run_light_client(TWAMPParameters * const param)
{
    struct addrinfo *res = NULL;
    struct sockaddr_storage remote_addr_measure;
    int fd_test = -1;
    int do_report = 0;

    TWAMPContext t_ctx;
    int rc = twamp_run_prepare(&t_ctx, param);
    if (rc != 0)
        return rc;

    memset(&remote_addr_measure, 0, sizeof(remote_addr_measure));

    if (twamp_resolve_host(param->host, param->port, param->family, SOCK_DGRAM, IPPROTO_UDP, &res) < 0) {
        return SEXIT_FAILURE;
    }

    fd_test = twamp_connect(param->source_ss, &remote_addr_measure, res);
    freeaddrinfo(res);
    res = NULL;
    if (fd_test < 0) {
        print_err("could not create TWAMP-TEST connection");
        rc = SEXIT_MP_REFUSED;
        goto TEST_EXIT;
    }
    /* possibly update from AF_UNSPEC to real one */
    param->family = remote_addr_measure.ss_family;

    print_msg(MSG_NORMAL, "TEST socket connected");

    /* Store remote address for report */
    char hostAddr[INET6_ADDRSTRLEN];
    if (get_ip_str(&remote_addr_measure, hostAddr, INET6_ADDRSTRLEN) == NULL) {
        print_warn("get_ip_str problem");
    }
    t_ctx.report->address = hostAddr;

    if (twamp_report_testsession_connection(t_ctx.report, fd_test)) {
        print_warn("failed to add TEST socket information to report, proceeding anyway...");
    } else {
        print_msg(MSG_DEBUG, "TEST socket ambient metrics added to report");
    }

    print_msg(MSG_NORMAL, "measurement starting...");
    t_ctx.test_socket = fd_test;

    rc = twamp_test(&t_ctx);
    do_report = (rc == SEXIT_SUCCESS || (rc == SEXIT_MP_TIMEOUT && t_ctx.report->result->packets_received > 0));

    /* Change to SEXIT_OUTOFRESOURCE if we got way too many duplicates */
    if (rc == SEXIT_SUCCESS &&
            t_ctx.report->result->packets_received >= t_ctx.param.packets_max) {
        rc = SEXIT_OUTOFRESOURCE;
        print_warn("Received too many packets, test aborted with partial results");
    }

    print_msg(MSG_IMPORTANT, "measurement finished %s",
            (rc == SEXIT_SUCCESS) ? "successfully" : "unsuccessfully");

    print_msg(MSG_DEBUG, "total packets sent: %u, received: %u (%u received too late)",
            t_ctx.report->result->packets_sent, t_ctx.report->result->packets_received,
            t_ctx.report->result->packets_late);

TEST_EXIT:
    if (fd_test >= 0) {
        if (shutdown(fd_test, SHUT_RDWR) != 0) {
            print_warn("TEST socket shutdown problem: %s", strerror(errno));
        }

        if (close(fd_test) != 0) {
            print_warn("TEST socket close problem: %s", strerror(errno));
        }
        print_msg(MSG_DEBUG, "TEST socket close OK");

        fd_test = -1;
    }

    if (do_report) {
        twamp_report_statistics(t_ctx.report, param);
        twamp_report_render_lmap(t_ctx.report, param);
        twamp_report_render_summary(t_ctx.report, param);
    }
    if (t_ctx.report->result)
        twamp_results_callback(t_ctx.report->result);
    twamp_report_done(t_ctx.report);
    t_ctx.report = NULL;

    return rc;
}

int twamp_run_client(TWAMPParameters * const param)
{
    int fd_control, fd_test;
    int rc;
    struct sockaddr_storage remote_addr_control, local_addr_control, remote_addr_measure, local_addr_measure;
    char * testPort = NULL;
    int do_report = 0;

    TWAMPContext t_ctx;
    rc = twamp_run_prepare(&t_ctx, param);
    if (rc)
        return rc;

    ServerGreeting *srvGreetings = malloc(SERVER_GREETINGS_SIZE);
    if (!srvGreetings) {
        print_err("Error allocating memory for ServerGreeting");
        return SEXIT_OUTOFRESOURCE;
    }
    SetupResponse *stpResponse = malloc(SETUP_RESPONSE_SIZE);
    if (!stpResponse) {
        print_err("Error allocating memory for SetupResponse");
        return SEXIT_OUTOFRESOURCE;
    }
    memset(stpResponse, 0 , SETUP_RESPONSE_SIZE);
    ServerStart *srvStart = malloc(SERVER_START_SIZE);
    if (!srvStart) {
        print_err("Error allocating memory for ServerStart");
        return SEXIT_OUTOFRESOURCE;
    }
    RequestSession *rqtSession = malloc(REQUEST_SESSION_SIZE);
    if (!rqtSession) {
        print_err("Error allocating memory for RequestSession");
        return SEXIT_OUTOFRESOURCE;
    }
    memset(rqtSession, 0 , REQUEST_SESSION_SIZE);
    AcceptSession *actSession = malloc(ACCEPT_SESSION_SIZE);
    if (!actSession) {
        print_err("Error allocating memory for AcceptSession");
        return SEXIT_OUTOFRESOURCE;
    }
    StartSessions *strSession = malloc(START_SESSIONS_SIZE);
    if (!strSession) {
        print_err("Error allocating memory for StartSessions");
        return SEXIT_OUTOFRESOURCE;
    }
    memset(strSession, 0 , START_SESSIONS_SIZE);
    StartAck *strAck = malloc(START_ACK_SIZE);
    if (!strAck) {
        print_err("Error allocating memory for StartAck");
        return SEXIT_OUTOFRESOURCE;
    }
    StopSessions *stpSessions = malloc(sizeof(StopSessions));
    if (!stpSessions) {
        print_err("Error allocating memory for StartAck");
        return SEXIT_OUTOFRESOURCE;
    }
    memset(stpSessions, 0 , sizeof(StopSessions));

    /* CREATE CONTROL CONNECTION */
    memset(&remote_addr_control, 0, sizeof(struct sockaddr_storage));
    fd_control = usock_inet_timeout(USOCK_TCP | usock_convert_family(param->family), param->host, param->port, &remote_addr_control, param->connect_timeout*1000);
    if (fd_control < 0) {
        print_err("could not resolve server name or address");
        rc = SEXIT_DNSERR;
        goto MEM_FREE;
    }

    if (usock_wait_ready(fd_control, 5000) != 0) {
        print_err("connection to server failed");
        rc = SEXIT_MP_REFUSED;
        goto MEM_FREE;
    }

    print_msg(MSG_NORMAL, "CONTROL socket connected");

    // Store remote address for report
    char hostAddr[INET6_ADDRSTRLEN];
    if (get_ip_str(&remote_addr_control, hostAddr, INET6_ADDRSTRLEN) == NULL) {
        print_warn("get_ip_str problem");
    }
    t_ctx.report->address = hostAddr;

    /* Update possibly AF_UNSPEC to real family */
    param->family = remote_addr_control.ss_family;

    rc = SEXIT_CTRLPROT_ERR;

    // SERVER GREETINGS
    if (message_server_greetings(fd_control, 10, srvGreetings) < 0) {
        print_err("message_server_greetings problem");
        goto CONTROL_CLOSE;
    }

    print_msg(MSG_DEBUG, "server Greetings received");

    if (message_validate_server_greetings(srvGreetings) != 0) {
        print_err("message_validate_server_greetings problem");
        goto CONTROL_CLOSE;
    }

    // SETUP RESPONSE
    print_msg(MSG_DEBUG, "preparing Setup Response message");

    if (message_format_setup_response(srvGreetings, stpResponse) != 0) {
        print_err("message_setup_response problem");
        goto CONTROL_CLOSE;
    }

    if (message_send(fd_control, 10, stpResponse, SETUP_RESPONSE_SIZE) < 0) {
        print_err("message_send problem sending stpResponse");
        goto CONTROL_CLOSE;
    }

    print_msg(MSG_DEBUG, "Setup Response message sent");

    // SERVER START
    if (message_server_start(fd_control, 10, srvStart) < 0) {
        print_err("message_server_start problem");
        goto CONTROL_CLOSE;
    }

    if(srvStart->Accept != 0) {
        print_err("test not accepted: %" PRIu8 ,srvStart->Accept);
        rc = SEXIT_MP_REFUSED;
        goto CONTROL_CLOSE;
    }

    print_msg(MSG_NORMAL, "Server Start received, creating test session(s)...");

    // REQUEST SESSION
    socklen_t addr_len = sizeof(local_addr_control);
    memset(&local_addr_control, 0, addr_len);
    if (getsockname(fd_control, (struct sockaddr *) &local_addr_control, &addr_len) < 0){
        print_err("getsockname problem on control socket");
        rc = SEXIT_INTERNALERR;
        goto CONTROL_CLOSE;
    }

    char str[INET6_ADDRSTRLEN];
    if (get_ip_str(&local_addr_control, str, INET6_ADDRSTRLEN) == NULL) {
        print_err("get_ip_str problem on control socket");
        rc = SEXIT_INTERNALERR;
        goto CONTROL_CLOSE;
    }

    print_msg(MSG_NORMAL, "local address is %s", str);

    // CREATE UDP SOCKET FOR THE TEST
    memset(&remote_addr_measure, 0, sizeof(struct sockaddr_storage));
    fd_test = usock_inet_timeout(USOCK_UDP | usock_convert_family(param->family), param->host, "862", &remote_addr_measure, param->connect_timeout * 1000);
    if (fd_test < 0) {
        print_err("usock_inet_timeout problem on test socket");
        rc = SEXIT_MP_REFUSED;
        goto CONTROL_CLOSE;
    }

    if (usock_wait_ready(fd_test, 5000) != 0) {
        print_err("usock_wait_ready problem on test socket");
        rc = SEXIT_MP_TIMEOUT;
        goto TEST_CLOSE;
    }

    print_msg(MSG_NORMAL, "TEST socket connected");

    // Get Sender Port
    uint16_t sender_port = 862;
    addr_len = sizeof(local_addr_measure);
    memset(&local_addr_measure, 0, addr_len);
    if (getsockname(fd_test, (struct sockaddr *) &local_addr_measure, (socklen_t *) &addr_len) < 0) {
        print_err("getsockname problem on test socket");
        rc = SEXIT_INTERNALERR;
        goto TEST_CLOSE;
    }

    switch(local_addr_measure.ss_family) {
        case AF_INET:
            sender_port = ntohs(((struct sockaddr_in *) &local_addr_measure)->sin_port);
            print_msg(MSG_DEBUG, "PORT IPv4 %u", sender_port);
            break;

        case AF_INET6:
            sender_port = ntohs(((struct sockaddr_in6 *) &local_addr_measure)->sin6_port);
            print_msg(MSG_DEBUG, "PORT IPv6: %u", sender_port);
            break;

        default:
            break;
    }

    if (message_format_request_session(param->family, param->payload_size, sender_port, rqtSession) != 0) {
        print_err("message_format_request_session problem");
        rc = SEXIT_CTRLPROT_ERR;
        goto TEST_CLOSE;
    }

    if (message_send(fd_control, 10, rqtSession, REQUEST_SESSION_SIZE) < 0) {
        print_err("message_send problem sending rqtSession");
        rc = SEXIT_MP_TIMEOUT;
        goto TEST_CLOSE;
    }

    // ACCEPT SESSION
    if (message_accept_session(fd_control, 10, actSession) < 0) {
        print_err("message_accept_session problem");
        rc = SEXIT_CTRLPROT_ERR;
        goto TEST_CLOSE;
    }

    if(actSession->Accept != 0) {
        print_err("test not accepted on accept session message: %" PRIu8 ,actSession->Accept);
        rc = SEXIT_MP_REFUSED;
        goto TEST_CLOSE;
    }

    t_ctx.cookie_enabled = simet_generate_cookie(&t_ctx.cookie, actSession->SID, sizeof(actSession->SID));

    /* FIXME: log this better */
    uint16_t receiver_port = actSession->Port;
    t_ctx.report->serverPort = (unsigned int)receiver_port;
    print_msg(MSG_DEBUG, "session port: %" PRIu16, receiver_port);

    testPort = malloc(sizeof(char) * 6);
    if (!testPort) {
        print_err("Error allocating memory for testPort");
        rc = SEXIT_OUTOFRESOURCE;
        goto TEST_CLOSE;
    }
    snprintf(testPort, 6, "%u", receiver_port);

    sa_set_port(&remote_addr_measure, receiver_port);
    addr_len = sizeof(remote_addr_measure);

    /* FIXME: log it like inetupc, this is broken
    print_msg(MSG_DEBUG, "update remote port: %u", ntohs(((struct sockaddr_in *)&remote_addr_measure)->sin_port));
    print_msg(MSG_DEBUG, "addr value: %u", ((struct sockaddr_in *)&remote_addr_measure)->sin_addr);
    */

    if (RETRY_EINTR(connect(fd_test, (struct sockaddr *) &remote_addr_measure,
                remote_addr_measure.ss_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6)) != 0)) {
        print_err("connect to remote measurement peer problem: %s", strerror(errno));
        rc = SEXIT_MP_REFUSED;
        goto TEST_CLOSE;
    }

    if (twamp_report_testsession_connection(t_ctx.report, fd_test))
        print_warn("failed to add TEST socket information to report, proceeding anyway...");
    else
        print_msg(MSG_DEBUG, "TEST socket ambient metrics added to report");

    rc = SEXIT_CTRLPROT_ERR;

    // START SESSION
    strSession->Type = 2;
    if (message_send(fd_control, 10, strSession, START_SESSIONS_SIZE) < 0) {
        print_err("message_send problem on start session on control socket");
        goto TEST_CLOSE;
    }

    // START ACK
    if (message_start_ack(fd_control, 10, strAck) < 0) {
        print_err("message_start_ack problem on start session on control socket");
        goto TEST_CLOSE;
    }

    if (strAck->Accept != 0) {
        print_err("server refused to start session, reason %" PRIu8, strAck->Accept);
        rc = SEXIT_MP_REFUSED;
        goto TEST_CLOSE;
    }

    /* From this point onwards, we do output a result report */
    do_report = 1;

    print_msg(MSG_NORMAL, "measurement starting...");
    t_ctx.test_socket = fd_test;

    rc = twamp_test(&t_ctx);
    if (rc == SEXIT_OUTOFRESOURCE)
        goto TEST_CLOSE;

    /* Change to SEXIT_OUTOFRESOURCE if we got way too many duplicates */
    if (rc == SEXIT_SUCCESS &&
            t_ctx.report->result->packets_received >= t_ctx.param.packets_max) {
        rc = SEXIT_OUTOFRESOURCE;
        print_warn("Received too many packets, test aborted with partial results");
    }

    message_format_stop_sessions(stpSessions);
    if (message_send(fd_control, 10, stpSessions, sizeof(StopSessions)) < 0) {
       print_err("message_send problem on stop session on control socket");
       if (rc == SEXIT_SUCCESS)
           rc = SEXIT_CTRLPROT_ERR;
    }

    print_msg(MSG_IMPORTANT, "measurement finished %s",
            (rc == SEXIT_SUCCESS) ? "successfully" : "unsuccessfully");

    print_msg(MSG_DEBUG, "total packets sent: %u, received: %u (%u received too late)",
            t_ctx.report->result->packets_sent, t_ctx.report->result->packets_received,
            t_ctx.report->result->packets_late);

TEST_CLOSE:
    if (shutdown(fd_test, SHUT_RDWR) != 0) {
        print_warn("TEST socket shutdown problem: %s", strerror(errno));
    }

    if (close(fd_test) != 0) {
        print_warn("TEST socket close problem: %s", strerror(errno));
    }
    print_msg(MSG_DEBUG, "TEST socket close OK");

CONTROL_CLOSE:
    if (shutdown(fd_control, SHUT_RDWR) != 0) {
        print_warn("CONTROL socket shutdown problem: %s", strerror(errno));
    }

    if (close(fd_control) != 0) {
        print_warn("CONTROL socket close problem: %s", strerror(errno));
    }
    print_msg(MSG_DEBUG, "CONTROL socket close OK");

MEM_FREE:
    free(srvGreetings);
    free(stpResponse);
    free(srvStart);
    free(rqtSession);
    free(actSession);
    free(strSession);
    free(strAck);
    free(stpSessions);
    free(testPort);

    if (do_report) {
        twamp_report_statistics(t_ctx.report, param);
        twamp_report_render_lmap(t_ctx.report, param);
        twamp_report_render_summary(t_ctx.report, param);
    }
    if (t_ctx.report->result)
        twamp_results_callback(t_ctx.report->result);
    twamp_report_done(t_ctx.report);
    t_ctx.report = NULL;

    return rc;
}

/* Must "fast-detect" badly corrupted packets, such as what a recursive
 * DNS resolver would send in reply to a twamp-test packet, etc.
 */
/* Returns Z for OK, NZ for invalid */
static inline int twamp_process_pkt(const UnauthReflectedPacket * const rpkt,
                                    const uint32_t max_pkt, const uint32_t pkt_count,
                                    const struct timespec * const ts_recv,
                                    const struct timespec * const ts_offset,
                                    ReportPacket * const pktd)
{
    if (!rpkt || !pktd || pkt_count >= max_pkt)
        return 0;

    /* works regardless of host endianess */
    if (!rpkt->SenderTime.integer && !rpkt->SenderTime.fractional)
        return 0;

    pktd->senderSeqNumber    = ntohl(rpkt->SenderSeqNumber);
    pktd->reflectorSeqNumber = ntohl(rpkt->SeqNumber);
    pktd->receiverSeqNumber  = pkt_count; /* approximate, final analysis might drop some */

    if (pktd->senderSeqNumber >= max_pkt || pktd->reflectorSeqNumber >= max_pkt)
        return 0;

    pktd->senderTime_us        = timestamp_to_microsec(ntoh_timestamp(rpkt->SenderTime));
    pktd->reflectorRecvTime_us = timestamp_to_microsec(ntoh_timestamp(rpkt->RecvTime));
    pktd->reflectorSendTime_us = timestamp_to_microsec(ntoh_timestamp(rpkt->Time));
    pktd->receiverTime_us      = timestamp_to_microsec(relative_timespec_to_timestamp(ts_recv, ts_offset));

    /* clamp rtt_us to zero in case of invalid time sequence, analysis will count it
     * as invalid later */
    pktd->rtt_us = 0;
    if (pktd->reflectorSendTime_us >= pktd->reflectorRecvTime_us && pktd->receiverTime_us >= pktd->senderTime_us) {
        uint64_t reflectorDelay = pktd->reflectorSendTime_us - pktd->reflectorRecvTime_us;
        uint64_t rtt_full = pktd->receiverTime_us - pktd->senderTime_us;
        if (rtt_full >= reflectorDelay) {
            pktd->rtt_us = rtt_full - reflectorDelay;
        }
    }
    return 1;
}

/* twamp_callback_thread receive the reflected packets and return the result array
   non-reentrant due to static return_result */
static void *twamp_callback_thread(void *p) {
    size_t bytes_recv = 0;
    int ret;
    unsigned int pkg_count = 0;
    unsigned int pkg_corrupt = 0;

    struct timespec ts_cur, ts_stop, ts_recv;

    static int return_result; /* must be static! */

    if (!p) {
        /* better than a segfault, at least... */
        return_result = SEXIT_INTERNALERR;
        return &return_result;
    }

    TWAMPContext * const t_ctx = (TWAMPContext *)p;

    /* what we need to add to CLOCK_MONOTONIC to get absolute time */
    const struct timespec ts_offset = t_ctx->clock_offset;

    const unsigned int expected_pktsize = t_ctx->param.payload_size;
    assert(expected_pktsize >= sizeof(UnauthReflectedPacket));
    // FIXME: drop this double copying
    UnauthReflectedPacket *reflectedPacket = calloc(1, expected_pktsize);
    if (!reflectedPacket) {
       print_err("Error allocating memory for reflected packet");
       ret = SEXIT_OUTOFRESOURCE;
       goto error_out;
    }

    print_msg(MSG_NORMAL, "reflected packet receiving thread started");

    /* we wait for (number of packets * inter-packet interval) + last-packet reflector timeout */
    int64_t tt_us = t_ctx->param.packets_count * t_ctx->param.packets_interval_us
                    + t_ctx->param.packets_timeout_us;
    /* clamp to 10 minutes */
    if (tt_us > 600000000)
        tt_us = 600000000;

    if (clock_gettime(CLOCK_MONOTONIC, &ts_cur)) {
        ret = SEXIT_INTERNALERR;
        goto error_out;
    }
    ts_stop = timespec_add_microseconds(&ts_cur, tt_us);

    if (twamp_pkt_callback(0, &ts_cur, NULL)) {
        ret = SEXIT_FAILURE;
        goto error_out;
    }

    while (!t_ctx->abort_test && timespec_lt(&ts_cur, &ts_stop) && (pkg_count < t_ctx->param.packets_max)) {
        // Read message
        ret = receive_reflected_packet(t_ctx->test_socket, &ts_stop, reflectedPacket, expected_pktsize, &bytes_recv, &ts_recv);

        if (ret == SEXIT_MP_TIMEOUT)
            break; /* test time limit reached, not an error */
        if (ret != SEXIT_SUCCESS)
            goto error_out;

        if (bytes_recv == expected_pktsize && twamp_process_pkt(reflectedPacket, t_ctx->param.packets_max, pkg_count,
                    &ts_recv, &ts_offset, &t_ctx->report->result->pkt_data[pkg_count])) {

            if (twamp_pkt_callback(1, &ts_recv, &t_ctx->report->result->pkt_data[pkg_count])) {
                ret = SEXIT_FAILURE;
                goto error_out;
            }

            pkg_count++;
        } else {
            // Something is wrong
            pkg_corrupt++;

            if (pkg_corrupt >= 3 && pkg_count == 0) {
                /* abort early if all we get are corrupt packets */
                ret = SEXIT_CTRLPROT_ERR; /* just in case, error_out can change it */
                goto error_out;
            }
        }

        if (clock_gettime(CLOCK_MONOTONIC, &ts_cur)) {
            ret = SEXIT_INTERNALERR;
            goto error_out;
        }
    }

    ret = SEXIT_SUCCESS;

    if (t_ctx->abort_test)
        print_msg(MSG_DEBUG, "[THREAD] receiving thread stopping early due to abort_test flag");

error_out:
    // Store total received packets
    t_ctx->report->result->packets_received = pkg_count;

    if (pkg_corrupt > 0) {
        print_warn("received and dropped %u incorrecly reflected packets", pkg_corrupt);
        /* if every packet received was corrupt, abort the test !*/
        if (!pkg_count) {
            print_err("all received packets were dropped for being incorrect, assuming software error");
            ret = SEXIT_CTRLPROT_ERR;
        }
    }

    if (ret != SEXIT_SUCCESS) {
        /* signal sending thread that it can stop early */
        t_ctx->abort_test = 1;
    }

    if (twamp_pkt_callback((ret != SEXIT_SUCCESS)? 3 : 2, NULL, NULL)) {
        ret = SEXIT_FAILURE;
        goto error_out;
    }

    free(reflectedPacket);
    return_result = ret;
    return &return_result;
}

static int twamp_test(TWAMPContext * const test_ctx) {
    struct timespec ts_offset, ts_cur, ts_realtime;
    struct timespec ts_sleep = { 0 };
    unsigned int counter = 0;
    unsigned int error_counter = 0;
    void *thread_retval = NULL;
    int thread_started = 0;
    int rc = SEXIT_SUCCESS;
    int ret;


    const unsigned int pktsize = test_ctx->param.payload_size;
    assert(pktsize >= sizeof(UnauthReflectedPacket));
    const size_t padsize = pktsize - offsetof(UnauthReflectedPacket, Padding);
    UnauthPacket *packet = calloc(1, pktsize);
    if (!packet) {
       print_err("Error allocating memory for test packet to send");
       return SEXIT_OUTOFRESOURCE;
    }

    /* right now it is one fresh context per test... */
    if (test_ctx->abort_test)
        return SEXIT_FAILURE;

    if (test_ctx->cookie_enabled) {
        print_msg(MSG_DEBUG, "inserting a cookie in the padding, to work around broken NAT should the reflector support it");
        simet_cookie_as_padding(&packet->Padding, padsize, &(test_ctx->cookie));
    } else {
        simet_auth_as_padding(&packet->Padding, padsize, &(test_ctx->param.key));
    }

    const int ttl = (test_ctx->param.ttl > 0 && test_ctx->param.ttl < 256)? (int)test_ctx->param.ttl : 255;
    RETRY_EINTR(setsockopt(test_ctx->test_socket, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)));

    if (clock_gettime(CLOCK_REALTIME, &ts_realtime) || clock_gettime(CLOCK_MONOTONIC, &ts_cur)) {
        rc = SEXIT_INTERNALERR;
        goto err_out;
    }
    ts_offset = timespec_sub(&ts_realtime, &ts_cur);

    test_ctx->clock_offset = ts_offset;

    pthread_t receiver_thread;
    ret = pthread_create(&receiver_thread, NULL, twamp_callback_thread, test_ctx);
    if (ret) {
       if (ret == EAGAIN) {
          print_err("No resources to create reflected packets receiving thread");
          rc = SEXIT_OUTOFRESOURCE;
       } else {
          print_err("Error creating reflected packets receiving thread");
          rc = SEXIT_INTERNALERR;
       }
       goto err_out;
    }
    thread_started = 1;

    print_msg(MSG_DEBUG, "sending test packets...");

    // Sending test packets
    while (!test_ctx->abort_test && counter < test_ctx->param.packets_count) {
        // Set packet counter
        packet->SeqNumber = htonl(counter);

        // Set packet timestamp
        if (clock_gettime(CLOCK_MONOTONIC, &ts_cur)) {
            rc = SEXIT_INTERNALERR;
            goto err_out;
        }
        packet->Time = hton_timestamp(relative_timespec_to_timestamp(&ts_cur, &ts_offset));

        /* TODO: send directly? */
        if (message_send(test_ctx->test_socket, 5, packet, test_ctx->param.payload_size) >= 0) {
            counter++;
        } else {
            error_counter++;
            print_warn("failed to send test packet %u", counter);
            if (error_counter > 3 || errno == ECONNREFUSED) {
                print_err("Cancelling measurement due to sending errors");
                rc = SEXIT_MP_REFUSED; /* FIXME: most usual reason, but we could do better */
                goto err_out;
            }
        }

        if (!ts_sleep.tv_sec && !ts_sleep.tv_nsec)
            ts_sleep = ts_cur;

        ts_sleep.tv_nsec += test_ctx->param.packets_interval_us * 1000;
        while (ts_sleep.tv_nsec > 1000000000) {
            ts_sleep.tv_sec++;
            ts_sleep.tv_nsec -= 1000000000;
        }

        if (!test_ctx->abort_test) {
            int tries = MAXIMUM_SYSCALL_RETRIES;

#ifdef HAVE_CLOCK_NANOSLEEP
            int r;
            do {
                r = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &ts_sleep, NULL);
            } while (r == EINTR && (--tries > 0));
            if (r) {
                rc = (r == EINTR)? SEXIT_FAILURE : SEXIT_INTERNALERR;
                goto err_out;
            }
#else /* !HAVE_CLOCK_NANOSLEEP */
            clock_gettime(CLOCK_MONOTONIC, &ts_cur);
            while (timespec_lt(&ts_cur, &ts_sleep) && !test_ctx->abort_test) {
                const struct timespec ts_o = timespec_sub(&ts_sleep, &ts_cur);
#ifdef HAVE_NANOSLEEP
                if (nanosleep(&ts_o, NULL))
#else
                /* limit usleep to one second. POSIX. */
                if (usleep( (ts_o.tv_sec > 0)? MICROSECONDS_IN_SECOND : (useconds_t)(ts_o.tv_nsec / 1000) ))
#endif
                {
                    if (errno == EINTR && tries > 0) {
                        tries--;
                    } else {
                        rc = (errno == EINTR)? SEXIT_FAILURE : SEXIT_INTERNALERR;
                        goto err_out;
                    }
                }
                clock_gettime(CLOCK_MONOTONIC, &ts_cur);
            }
#endif /* HAVE_CLOCK_NANOSLEEP */
        }
    }

    if (test_ctx->abort_test)
        print_msg(MSG_DEBUG, "[THREAD] sending thread stopping early due to abort_test flag");

err_out:
    if (thread_started) {
        int trc = SEXIT_INTERNALERR;

        /* signal other thread to exit */
        if (rc != SEXIT_SUCCESS)
            test_ctx->abort_test = 1;

        if (pthread_join(receiver_thread, &thread_retval) == 0) {
            trc = (thread_retval) ? *(int *)thread_retval : SEXIT_SUCCESS;
            if (trc == SEXIT_SUCCESS) {
               print_msg(MSG_DEBUG, "[THREAD] twamp_callback_thread finished successfully");
            }
        } else {
            print_err("[THREAD] failed to join twamp_callback_thread");
        }
        if (rc == SEXIT_SUCCESS && trc != SEXIT_SUCCESS) {
            rc = trc;
        }
    }

    /* update this after threads have been quiesced, just in case */
    test_ctx->report->result->packets_sent = counter;

    free(packet);

    return (rc != SEXIT_SUCCESS)? rc : ((test_ctx->abort_test)? SEXIT_FAILURE : SEXIT_SUCCESS);
}

static int receive_reflected_packet(int socket, const struct timespec * const ts_stop,
                                    UnauthReflectedPacket *reflectedPacket,
                                    size_t expected_size, size_t *recv_total,
                                    struct timespec * const ts_recv) {
    ssize_t recv_size;
    int fd_ready = 0;
    fd_set rset, rset_master;

    struct timespec ts_cur;

    FD_ZERO(&rset_master);
    FD_SET(socket, &rset_master);

    *recv_total = 0;

    clock_gettime(CLOCK_MONOTONIC, &ts_cur);
    do {
        memcpy(&rset, &rset_master, sizeof(rset_master));

        /* we depend on Linux semanthics for *timeout (i.e. it gets updated) */
        struct timespec ts_to = timespec_sub_saturated(ts_stop, &ts_cur, 0);
        fd_ready = pselect(socket+1, &rset, NULL, NULL, &ts_to, NULL);
        if (fd_ready > 0 && FD_ISSET(socket, &rset)) {
            /* "receives" up to bufsize, but sets recv_size to the *real* size */
            /* any extra data (recv_size > bufsize) is discarded */
            recv_size = recv(socket, reflectedPacket, expected_size, MSG_TRUNC | MSG_DONTWAIT);
            clock_gettime(CLOCK_MONOTONIC, &ts_cur);
            if (recv_size < 0) {
                if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
                    continue;
                } else {
                    print_err("recv message problem receiving reflected packet: %s", strerror(errno));
                    return SEXIT_FAILURE;
                }
            }

            if ((size_t) recv_size == expected_size) {
                *recv_total = (size_t) recv_size; /* verified, recv_size can never be negative */
                memcpy(ts_recv, &ts_cur, sizeof(*ts_recv));
                return 0;
            }

            print_warn("unexpected reflected packet size: %zd, ignoring packet", recv_size);
            return 0;
        } else if (fd_ready < 0 && errno != EINTR) {
            print_err("receive_reflected_packet select problem");
            return SEXIT_FAILURE;
        } else if (fd_ready == 0) {
            return SEXIT_MP_TIMEOUT;
        }

        clock_gettime(CLOCK_MONOTONIC, &ts_cur);
    } while (timespec_lt(&ts_cur, ts_stop));

    return SEXIT_MP_TIMEOUT;
}

/* vim: set et ts=8 sw=4 : */
