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

#include "simet_err.h"
#include "logger.h"
#include "report.h"

#include "libubox/usock.h"

static char *get_ip_str(const struct sockaddr_storage *sa, char *s, socklen_t maxlen);
static int convert_family(int family);
static int cp_remote_addr(const struct sockaddr_storage *sa_src, struct sockaddr_storage *sa_dst);
static int add_remote_port(struct sockaddr_storage *sa, uint16_t remote_port);
static int receive_reflected_packet(int socket, struct timeval *timeout, UnauthReflectedPacket* reflectedPacket, size_t *bytes_recv);
static void *twamp_callback_thread(void *param);

static int twamp_test(TestParameters);

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

int twamp_run_client(TWAMPParameters param) {
    int fd_control, fd_test;
    struct sockaddr_storage remote_addr_control, local_addr_control, remote_addr_measure, local_addr_measure;
    char * testPort = NULL;
    int do_report = 0;

    if (param.packets_count > param.packets_max) {
        print_err("Configuration error: packet train size (%u) too big (max %u)", param.packets_count, param.packets_max);
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
    param.packets_max++;

    // Create TWAMPReport
    TWAMPReport * report = twamp_report_init();
    if (!report) {
        print_err("Error initializing TWAMP report");
        return SEXIT_OUTOFRESOURCE;
    }
    report->result->raw_data = malloc(sizeof(TWAMPRawData) * param.packets_max);
    if (!report->result->raw_data) {
        print_err("Error allocating memory for raw_data");
        return SEXIT_OUTOFRESOURCE;
    }

    report->family = param.family;
    report->host = param.host;

    TestParameters t_param;
    t_param.param = param;
    t_param.report = report;

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

    int rc;

    // CREATE SOCKET
    memset(&remote_addr_control, 0, sizeof(struct sockaddr_storage));
    fd_control = usock_inet_timeout(USOCK_TCP | convert_family(param.family), param.host, param.port, &remote_addr_control, 2000);
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
    report->address = hostAddr;

    memset(&local_addr_measure, 0, sizeof(struct sockaddr_storage));
    cp_remote_addr(&remote_addr_control, &local_addr_measure);

    if (remote_addr_control.ss_family == AF_INET) {
        param.family = 4;
    } else {
        param.family = 6;
    }

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
    if (getsockname(fd_control, (struct sockaddr *) &local_addr_control, (socklen_t *) &addr_len) < 0){
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
    fd_test = usock_inet_timeout(USOCK_UDP | convert_family(param.family), param.host, "862", &remote_addr_measure, 2000);
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

    // Verificar se o Endian está invertido....
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

    if (message_format_request_session(param.family, sender_port, rqtSession) != 0) {
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

    t_param.cookie_enabled = simet_generate_cookie(&t_param.cookie, actSession->SID, sizeof(actSession->SID));

    /* FIXME: log this better */
    uint16_t receiver_port = actSession->Port;
    report->serverPort = (unsigned int)receiver_port;
    print_msg(MSG_DEBUG, "session port: %" PRIu16, receiver_port);

    testPort = malloc(sizeof(char) * 6);
    if (!testPort) {
        print_err("Error allocating memory for testPort");
        rc = SEXIT_OUTOFRESOURCE;
        goto TEST_CLOSE;
    }
    snprintf(testPort, 6, "%u", receiver_port);

    add_remote_port(&remote_addr_measure, receiver_port);
    addr_len = sizeof(remote_addr_measure);

    /* FIXME: log it like inetupc, this is broken
    print_msg(MSG_DEBUG, "update remote port: %u", ntohs(((struct sockaddr_in *)&remote_addr_measure)->sin_port));
    print_msg(MSG_DEBUG, "addr value: %u", ((struct sockaddr_in *)&remote_addr_measure)->sin_addr);
    */

    if (connect(fd_test, (struct sockaddr *) &remote_addr_measure,
                remote_addr_measure.ss_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6)) != 0) {
        print_err("connect to remote measurement peer problem: %s", strerror(errno));
        rc = SEXIT_MP_REFUSED;
        goto TEST_CLOSE;
    }

    if (report_socket_metrics(report, fd_test, IPPROTO_UDP))
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
    t_param.test_socket = fd_test;

    rc = twamp_test(t_param);
    if (rc == SEXIT_OUTOFRESOURCE)
        goto TEST_CLOSE;

    /* Change to SEXIT_OUTOFRESOURCE if we got way too many duplicates */
    if (rc == SEXIT_SUCCESS &&
            t_param.report->result->packets_received >= t_param.param.packets_max) {
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

    /* FIXME: remove or repurpose packets_dropped_timeout */
    print_msg(MSG_DEBUG, "total packets sent: %u, received: %u (%u discarded due to timeout)",
            t_param.report->result->packets_sent, t_param.report->result->packets_received,
            t_param.report->result->packets_dropped_timeout);

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

    if (do_report)
        twamp_report(report, &param);
    twamp_report_done(report);
    report = NULL;

    return rc;
}

static int convert_family(int family) {
    if (family == 4) {
        return USOCK_IPV4ONLY;
    } else if (family == 6) {
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

static int cp_remote_addr(const struct sockaddr_storage *sa_src, struct sockaddr_storage *sa_dst) {
    switch(sa_src->ss_family) {
        case AF_INET:
            ((struct sockaddr_in *)sa_dst)->sin_addr = ((struct sockaddr_in *)sa_src)->sin_addr;
            break;

        case AF_INET6:
            ((struct sockaddr_in6 *)sa_dst)->sin6_addr = ((struct sockaddr_in6 *)sa_src)->sin6_addr;
            break;
    }

    return 0;
}

static int add_remote_port(struct sockaddr_storage *sa, uint16_t remote_port) {
    switch(sa->ss_family) {
        case AF_INET:
            ((struct sockaddr_in *)sa)->sin_port = htons(remote_port);
            break;

        case AF_INET6:
            ((struct sockaddr_in6 *)sa)->sin6_port = htons(remote_port);
            break;
    }

    return 0;
}

// twamp_callback_thread receive the reflected packets and return the result array
// non-reentrant due to static return_result
static void *twamp_callback_thread(void *p) {
    TestParameters *t_param = (TestParameters *)p;
    UnauthReflectedPacket *reflectedPacket = NULL;
    size_t bytes_recv = 0;
    int ret;
    unsigned int pkg_count = 0;
    unsigned int pkg_corrupt = 0;

    struct timeval tv_cur, tv_stop, to;
    struct timespec ts_recv;

    static int return_result; /* must be static! */

    /* what we need to add to CLOCK_MONOTONIC to get absolute time */
    const struct timespec ts_offset = t_param->clock_offset;

    print_msg(MSG_NORMAL, "reflected packet receiveing thread started");

    // FIXME: drop this double copying
    reflectedPacket = malloc(sizeof(UnauthReflectedPacket));
    if (!reflectedPacket) {
       print_err("Error allocating memory for reflected packet");
       ret = SEXIT_OUTOFRESOURCE;
       goto error_out;
    }
    memset(reflectedPacket, 0, sizeof(UnauthReflectedPacket)); /* FIXME */

    /* we wait for (number of packets * inter-packet interval) + last-packet reflector timeout */
    unsigned long long int tt_us = t_param->param.packets_count * t_param->param.packets_interval_us
                                   + t_param->param.packets_timeout_us;
    /* clamp to 10 minutes */
    if (tt_us > 600000000UL)
        tt_us = 600000000UL;
    to.tv_sec = tt_us / 1000000U;
    to.tv_usec = tt_us - (to.tv_sec * 1000000U);

    gettimeofday(&tv_cur, NULL);
    timeradd(&tv_cur, &to, &tv_stop);

    while (timercmp(&tv_cur, &tv_stop, <) && (pkg_count < t_param->param.packets_max)) {
        // Read message
        ret = receive_reflected_packet(t_param->test_socket, &to, reflectedPacket, &bytes_recv);

        if (clock_gettime(CLOCK_MONOTONIC, &ts_recv)) {
            ret = SEXIT_INTERNALERR;
            goto error_out;
        }

        if (ret == SEXIT_MP_TIMEOUT)
            break; /* test time limit reached, not an error */
        if (ret != SEXIT_SUCCESS)
            goto error_out;

        if (bytes_recv == sizeof(UnauthReflectedPacket)) {
            // Save result
            t_param->report->result->raw_data[pkg_count].time = relative_timespec_to_timestamp(&ts_recv, &ts_offset);
            memcpy(&(t_param->report->result->raw_data[pkg_count].data), reflectedPacket, sizeof(UnauthReflectedPacket));
            pkg_count++;
        } else {
            // Something is wrong
            pkg_corrupt++;
        }
        gettimeofday(&tv_cur, NULL);
    }

    ret = SEXIT_SUCCESS;

error_out:
    // Store total received packets
    t_param->report->result->packets_received = pkg_count;

    if (pkg_corrupt > 0) {
        print_warn("received and dropped %u incorrecly sized packets", pkg_corrupt);
        /* if every packet received was corrupt, abort the test !*/
        if (!pkg_count) {
            print_err("all received packets were dropped for being incorrect, assuming software error");
            ret = SEXIT_CTRLPROT_ERR;
        }
    }

    free(reflectedPacket);
    return_result = ret;
    return &return_result;
}

static int twamp_test(TestParameters test_param) {
    struct timespec ts_offset, ts_cur;
    uint counter = 0;
    void *thread_retval = NULL;
    int rc = SEXIT_SUCCESS;
    int ret;

    UnauthPacket *packet = malloc(sizeof(UnauthPacket));
    if (!packet) {
       print_err("Error allocating memory for test packet to send");
       return SEXIT_OUTOFRESOURCE;
    }
    memset(packet, 0 , sizeof(UnauthPacket));

    if (test_param.cookie_enabled) {
        print_msg(MSG_DEBUG, "inserting a cookie in the padding, to work around broken NAT should the reflector support it");
        simet_cookie_as_padding(&packet->Cookie, sizeof(packet->Cookie), &test_param.cookie);
    }

    if (clock_gettime(CLOCK_REALTIME, &ts_offset) || clock_gettime(CLOCK_MONOTONIC, &ts_cur)) {
        rc = SEXIT_INTERNALERR;
        goto err_out;
    }
    timespec_to_offset(&ts_offset, &ts_cur);

    test_param.clock_offset = ts_offset;

    pthread_t receiver_thread;
    ret = pthread_create(&receiver_thread, NULL, twamp_callback_thread, &test_param);
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

    print_msg(MSG_DEBUG, "sending test packets...");

    // Sending test packets
    while (counter < test_param.param.packets_count) {
        // Set packet counter
        packet->SeqNumber = htonl(counter++);

        // Set packet timestamp
        if (clock_gettime(CLOCK_MONOTONIC, &ts_cur)) {
            rc = SEXIT_INTERNALERR;
            goto err_out;
        }
        Timestamp ts = relative_timespec_to_timestamp(&ts_cur, &ts_offset);
        encode_be_timestamp(&ts);
        packet->Time = ts;

        /* TODO: send directly */
        if (message_send(test_param.test_socket, 5, packet, sizeof(UnauthPacket)) < 0) {
            print_warn("message_send returned -1 for test packet %u", counter-1);
            counter--;
        }
        usleep(test_param.param.packets_interval_us);
    }

    test_param.report->result->packets_sent = counter;

    /* we expect to wait here on pthread_join */
    if (pthread_join(receiver_thread, &thread_retval) == 0) {
        rc = (thread_retval) ? *(int *)thread_retval : SEXIT_SUCCESS;
        if (rc == SEXIT_SUCCESS)
           print_msg(MSG_DEBUG, "[THREAD] twamp_callback_thread ended OK!");
    } else {
        print_warn("[THREAD] twamp_callback_thread ended with problem!");
        rc = SEXIT_INTERNALERR;
    }

err_out:
    free(packet);
    return rc;
}

static int receive_reflected_packet(int socket, struct timeval *timeout,
                                    UnauthReflectedPacket *reflectedPacket, size_t *recv_total) {
    ssize_t recv_size;
    int fd_ready = 0;
    fd_set rset, rset_master;

    FD_ZERO(&rset_master);
    FD_SET((unsigned long)socket, &rset_master);

    *recv_total = 0;

    do {
        memcpy(&rset, &rset_master, sizeof(rset_master));

        /* we depend on Linux semanthics for *timeout (i.e. it gets updated) */
        fd_ready = select(socket+1, &rset, NULL, NULL, timeout);
        if (fd_ready > 0 && FD_ISSET(socket, &rset)) {
            recv_size = recv(socket, reflectedPacket, sizeof(UnauthReflectedPacket), MSG_TRUNC || MSG_DONTWAIT);

            // Caso recv apresente algum erro
            if (recv_size < 0) {
                // Se o erro for EAGAIN e EWOULDBLOCK, tentar novamente
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    continue;
                } else {
                    print_err("recv message problem receiving reflected packet: %s", strerror(errno));
                    return SEXIT_FAILURE;
                }
            }

            if (recv_size == sizeof(UnauthReflectedPacket)) {
                // Sender info
                reflectedPacket->SenderSeqNumber = ntohl(reflectedPacket->SenderSeqNumber);
                decode_be_timestamp(&reflectedPacket->SenderTime);

                // Reflector info
                reflectedPacket->SeqNumber = ntohl(reflectedPacket->SeqNumber);
                decode_be_timestamp(&reflectedPacket->RecvTime);
                decode_be_timestamp(&reflectedPacket->Time);

                *recv_total = (size_t) recv_size; /* verified, recv_size can never be negative */
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
    } while ((timeout->tv_sec > 0) && (timeout->tv_usec > 0));

    return SEXIT_MP_TIMEOUT;
}

/* vim: set et ts=4 sw=4 : */
