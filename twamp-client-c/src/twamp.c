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

static char *get_ip_str(const struct sockaddr_storage *sa, char *s, size_t maxlen);
static int convert_family(int family);
static int cp_remote_addr(const struct sockaddr_storage *sa_src, struct sockaddr_storage *sa_dst);
static int add_remote_port(struct sockaddr_storage *sa, uint16_t remote_port);
static int receive_reflected_packet(int socket, struct timeval *timeout, UnauthReflectedPacket* reflectedPacket);
static void *twamp_callback_thread(void *param);

static int twamp_test(TestParameters);

int twamp_run_client(TWAMPParameters param) {
    int ret_socket, fd_control, fd_test;
    int fd_ready;
    struct sockaddr_storage remote_addr_control, local_addr_control, remote_addr_measure, local_addr_measure;
    char * testPort = NULL;

    assert(param.packets_count < param.packets_max);

    // Create TWAMPReport
    TWAMPReport * report = twamp_report_init();
    if (!report)
        return SEXIT_OUTOFRESOURCE;
    report->device_id = param.device_id ? param.device_id : "(unknown)";
    report->result->raw_data = malloc(sizeof(TWAMPRawData) * param.packets_max);
    report->family = param.family;
    report->host = param.host;

    TestParameters t_param;
    t_param.param = param;
    t_param.report = report;

    ServerGreeting *srvGreetings = malloc(SERVER_GREETINGS_SIZE);
    SetupResponse *stpResponse = malloc(SETUP_RESPONSE_SIZE);
    if (!srvGreetings || !stpResponse)
        return SEXIT_OUTOFRESOURCE;
    memset(stpResponse, 0 , SETUP_RESPONSE_SIZE);
    ServerStart *srvStart = malloc(SERVER_START_SIZE);
    if (!srvStart)
        return SEXIT_OUTOFRESOURCE;

    RequestSession *rqtSession = malloc(REQUEST_SESSION_SIZE);
    if (!rqtSession)
        return SEXIT_OUTOFRESOURCE;
    memset(rqtSession, 0 , REQUEST_SESSION_SIZE);
    AcceptSession *actSession = malloc(ACCEPT_SESSION_SIZE);
    StartSessions *strSession = malloc(START_SESSIONS_SIZE);
    if (!actSession || !strSession)
        return SEXIT_OUTOFRESOURCE;
    memset(strSession, 0 , START_SESSIONS_SIZE);
    StartAck *strAck = malloc(START_ACK_SIZE);
    if (!strAck)
        return SEXIT_OUTOFRESOURCE;

    StopSessions *stpSessions = malloc(sizeof(StopSessions));
    if (!stpSessions)
        return SEXIT_OUTOFRESOURCE;
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

    fd_ready = usock_wait_ready(fd_control, 5000);
    if (fd_ready != 0) {
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
    ret_socket = message_server_greetings(fd_control, 10, srvGreetings);
    if (ret_socket != SERVER_GREETINGS_SIZE) {
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

    ret_socket = message_send(fd_control, 10, stpResponse, SETUP_RESPONSE_SIZE);
    if (ret_socket <= 0) {
        print_err("message_send problem");
        goto CONTROL_CLOSE;
    }

    print_msg(MSG_DEBUG, "Setup Response message sent");

    // SERVER START
    ret_socket = message_server_start(fd_control, 10, srvStart);
    if (ret_socket <= 0) {
        print_err("message_server_start problem");
        goto CONTROL_CLOSE;
    }

    if(srvStart->Accept != 0) {
        print_err("test not accepted: %"PRIu8 ,srvStart->Accept);
        goto CONTROL_CLOSE;
    }

    print_msg(MSG_NORMAL, "Server Start received, creating test session(s)...");

    // REQUEST SESSION
    socklen_t addr_len = sizeof(local_addr_control);
    memset(&local_addr_control, 0, addr_len);
    if (getsockname(fd_control, (struct sockaddr *) &local_addr_control, (socklen_t *) &addr_len) < 0){
        print_err("getsockname problem");
        rc = SEXIT_INTERNALERR;
        goto CONTROL_CLOSE;
    }

    char str[INET6_ADDRSTRLEN];
    if (get_ip_str(&local_addr_control, str, INET6_ADDRSTRLEN) == NULL) {
        print_err("get_ip_str problem");
        rc = SEXIT_INTERNALERR;
        goto CONTROL_CLOSE;
    }

    print_msg(MSG_NORMAL, "local address is %s", str);

    // CREATE SOCKET
    memset(&remote_addr_measure, 0, sizeof(struct sockaddr_storage));
    fd_test = usock_inet_timeout(USOCK_UDP | convert_family(param.family), param.host, "862", &remote_addr_measure, 2000);
    if (fd_test < 0) {
        print_err("usock_inet_timeout problem");
    rc = SEXIT_MP_REFUSED;
        goto CONTROL_CLOSE;
    }

    fd_ready = usock_wait_ready(fd_test, 5000);
    if (fd_ready != 0) {
        print_err("usock_wait_ready problem");
    rc = SEXIT_MP_TIMEOUT;
        goto TEST_CLOSE;
    }

    print_msg(MSG_NORMAL, "TEST socket connected");

    // Get Sender Port
    uint16_t sender_port = 862;
    addr_len = sizeof(local_addr_measure);
    memset(&local_addr_measure, 0, addr_len);
    if (getsockname(fd_test, (struct sockaddr *) &local_addr_measure, (socklen_t *) &addr_len) < 0) {
        print_msg(MSG_DEBUG, "getsockname problem");
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
        print_msg(MSG_DEBUG, "message_format_request_session problem");
        goto TEST_CLOSE;
    }

    ret_socket = message_send(fd_control, 10, rqtSession, REQUEST_SESSION_SIZE);
    if (ret_socket <= 0) {
        print_msg(MSG_DEBUG, "message_send problem");
        goto TEST_CLOSE;
    }

    // ACCEPT SESSION
    ret_socket = message_accept_session(fd_control, 10, actSession);
    if (ret_socket <= 0) {
        print_msg(MSG_DEBUG, "message_server_start problem");
        goto TEST_CLOSE;
    }

    if(actSession->Accept != 0) {
        print_err("test not accepted: %"PRIu8 ,actSession->Accept);
        goto TEST_CLOSE;
    }

    /* FIXME: log this better */
    uint16_t receiver_port = actSession->Port;
    report->serverPort = (unsigned int)receiver_port;
    print_msg(MSG_DEBUG, "session port: %"PRIu16, receiver_port);

    testPort = malloc(sizeof(char) * 6);
    if (!testPort) {
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

    print_msg(MSG_DEBUG, "fd_test before: %d", fd_test);

    if (connect(fd_test, (struct sockaddr *) &remote_addr_measure,
                remote_addr_measure.ss_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6)) != 0) {
        print_err("connect to remote measurement peer problem: %s", strerror(errno));
        rc = SEXIT_MP_REFUSED;
        goto TEST_CLOSE;
    }

    print_msg(MSG_DEBUG, "fd_test after: %d", fd_test);
    if (report_socket_metrics(report, fd_test, IPPROTO_UDP))
    print_warn("failed to add TEST socket information to report, proceeding anyway...");
    else
        print_msg(MSG_DEBUG, "TEST socket ambient metrics added to report");

    rc = SEXIT_CTRLPROT_ERR;

    // START SESSION
    strSession->Type = 2;
    ret_socket = message_send(fd_control, 10, strSession, START_SESSIONS_SIZE);
    if (ret_socket <= 0) {
        print_err("message_send problem");
        goto TEST_CLOSE;
    }

    // START ACK
    ret_socket = message_start_ack(fd_control, 10, strAck);
    if (ret_socket <= 0) {
        print_err("message_start_ack problem");
        goto TEST_CLOSE;
    }

    if (strAck->Accept == 0) {
        print_msg(MSG_NORMAL, "measurement starting...");
        t_param.test_socket = fd_test;

        twamp_test(t_param);

        message_format_stop_sessions(stpSessions);
        message_send(fd_control, 10, stpSessions, sizeof(StopSessions));
    } else {
        print_err("Accept != 0, got %"PRIu8, strAck->Accept);
        goto TEST_CLOSE;
    }

    print_msg(MSG_IMPORTANT, "measurement finished");

    twamp_report(report, &param);

    print_msg(MSG_DEBUG, "total packets sent: %u, received: %u (%u discarded due to timeout)",
            t_param.report->result->packets_sent, t_param.report->result->packets_received,
            t_param.report->result->packets_dropped_timeout);

    rc = SEXIT_SUCCESS;

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

static char *get_ip_str(const struct sockaddr_storage *sa, char *s, size_t maxlen)
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
static void *twamp_callback_thread(void *p) {
    TestParameters *t_param = (TestParameters *)p;
    int bytes_recv = 0;
    unsigned int pkg_count = 0;

    struct timeval tv_cur, tv_stop, tv_recv, to;

    UnauthReflectedPacket *reflectedPacket = malloc(sizeof(UnauthReflectedPacket));
    memset(reflectedPacket, 0, sizeof(UnauthReflectedPacket)); /* FIXME */

    /* we wait for (number of packets * inter-packet interval) + per-packet timeout */
    long long int tt_us = t_param->param.packets_count * t_param->param.packets_interval_us
			  + t_param->param.packets_timeout_us;
    to.tv_sec = tt_us / 1000000;
    to.tv_usec = tt_us - (to.tv_sec * 1000000);

    gettimeofday(&tv_cur, NULL);
    timeradd(&tv_cur, &to, &tv_stop);

    while (timercmp(&tv_cur, &tv_stop, <) && (pkg_count < t_param->param.packets_max)) {
        // Read message
        bytes_recv = receive_reflected_packet(t_param->test_socket, &to, reflectedPacket);

        gettimeofday(&tv_recv, NULL);

        if (bytes_recv != sizeof(UnauthReflectedPacket)) {
            // Somthing is wrong
            print_warn("unexpected message size. bytes_recv(%d) != sizeof(UnauthReflectedPacket)", bytes_recv);
        } else {
            // Save result
            t_param->report->result->raw_data[pkg_count].time = timeval_to_timestamp(&tv_recv);
            memcpy(&(t_param->report->result->raw_data[pkg_count].data), reflectedPacket, sizeof(UnauthReflectedPacket));
            pkg_count++;
        }

        gettimeofday(&tv_cur, NULL);
    }

    // Store total received packets
    t_param->report->result->packets_received = pkg_count;

    free(reflectedPacket);

    return NULL;
}

static int twamp_test(TestParameters test_param) {
    struct timeval tv_cur;
    uint counter = 0;
    int send_resp = 0;

    UnauthPacket *packet = malloc(sizeof(UnauthPacket));
    memset(packet, 0 , sizeof(UnauthPacket));

    pthread_t receiver_thread;
    pthread_create(&receiver_thread, NULL, twamp_callback_thread, &test_param);

    // Sending test packets
    gettimeofday(&tv_cur, NULL);
    while (counter < test_param.param.packets_count) {
        // Set packet counter
        packet->SeqNumber = htonl(counter++);

        // Set packet timestamp
        Timestamp ts = timeval_to_timestamp(&tv_cur);
        encode_be_timestamp(&ts);
        packet->Time = ts;

        /* TODO: send directly */
        send_resp = message_send(test_param.test_socket, 5, packet, sizeof(UnauthPacket));
        if (send_resp == -1) {
            print_warn("message_send returned -1");
            counter--;
        }
        usleep(test_param.param.packets_interval_us);
        gettimeofday(&tv_cur, NULL);
    }

    /* we expect to wait here on pthread_join */
    if (pthread_join(receiver_thread, NULL) == 0) {
        print_msg(MSG_DEBUG, "[THREAD] twamp_callback_thread ended OK!");
    } else {
        print_warn("[THREAD] twamp_callback_thread ended with problem!");
    }

    test_param.report->result->packets_sent = counter;

    // FREE
    free(packet);

    return 0;
}

static int receive_reflected_packet(int socket, struct timeval *timeout,
	UnauthReflectedPacket *reflectedPacket) {
    int recv_size = 0, recv_total = 0;
    uint8_t message[MAX_SIZE_MESSAGE];
    int fd_ready = 0;
    fd_set rset, rset_master;
    struct timeval tv_cur;

    FD_ZERO(&rset_master);
    FD_SET((unsigned long)socket, &rset_master);

    do {
        memset(&message, 0, MAX_SIZE_MESSAGE);
        memcpy(&rset, &rset_master, sizeof(rset_master));

	/* we depend on Linux semanthics for *timeout (i.e. it gets updated) */
        fd_ready = select(socket+1, &rset, NULL, NULL, timeout);

        if (fd_ready <= 0) {
            if (fd_ready == 0) {
                print_msg(MSG_DEBUG, "receive_reflected_packet select timeout");
            } else {
                print_msg(MSG_DEBUG, "receive_reflected_packet select problem");
            }

            break;
        } else {
            if (FD_ISSET((unsigned long)socket, &rset)) {
                recv_size = recv(socket, message, MAX_SIZE_MESSAGE, 0);

                gettimeofday(&tv_cur, NULL);

                // Caso recv apresente algum erro
                if (recv_size <= 0) {
                    if (recv_size == 0) {
                        print_msg(MSG_DEBUG, "recv problem: recv_size == 0");
                        break;
                    }

                    // Se o erro for EAGAIN e EWOULDBLOCK, tentar novamente
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        continue;
                    } else {
                        print_err("recv message problem: %s", strerror(errno));
                        break;
                    }
                }

                memcpy(reflectedPacket + recv_total, &message, recv_size);

                recv_total += recv_size;

                if (recv_total == sizeof(UnauthReflectedPacket)) {
                    // Sender info
                    reflectedPacket->SenderSeqNumber = ntohl(reflectedPacket->SenderSeqNumber);
                    decode_be_timestamp(&reflectedPacket->SenderTime);

                    // Reflector info
                    reflectedPacket->SeqNumber = ntohl(reflectedPacket->SeqNumber);
                    decode_be_timestamp(&reflectedPacket->RecvTime);
                    decode_be_timestamp(&reflectedPacket->Time);

                    return recv_total;
                }

                print_warn("recv_total different then expected");
            } else {
                print_warn("socket not in rset");
            }
        }
    } while ((timeout->tv_sec > 0) && (timeout->tv_usec > 0));

    return -1;
}

/* vim: set et ts=4 sw=4 : */
