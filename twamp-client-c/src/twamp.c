/*
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

#include "twampc_config.h"
#include "twamp.h"

#include "logger.h"
#include "report.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <stdio.h>

#include <unistd.h>
#include <netdb.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>
#include <arpa/inet.h>

#include "libubox/usock.h"

static char *get_ip_str(const struct sockaddr_storage *sa, char *s, size_t maxlen);
static int convert_family(int family);
static int cp_remote_addr(const struct sockaddr_storage *sa_src, struct sockaddr_storage *sa_dst);
static int add_remote_port(struct sockaddr_storage *sa, uint16_t remote_port);
static int receive_reflected_packet(int socket, int timeout, UnauthReflectedPacket* reflectedPacket);
static void *twamp_callback_thread(void *param);

static int twamp_test(TestParameters);

int twamp_run_client(TWAMPParameters param) {
    int ret_socket, fd_control, fd_test;
    int fd_ready;
    struct sockaddr_storage remote_addr_control, local_addr_control, remote_addr_measure, local_addr_measure;
    char * testPort = NULL;

    // Create TWAMPReport
    TWAMPReport * report = malloc(sizeof(TWAMPReport));
    report->device_id = param.device_id ? param.device_id : "(unknown)";
    report->result = malloc(sizeof(TWAMPResult));
    report->result->raw_data = malloc(sizeof(TWAMPRawData) * param.packets_count);
    report->family = param.family;
    report->host = param.host;

    TestParameters t_param;
    t_param.param = param;
    t_param.report = report;

    int simet_err = 0;

    INFO_LOG("Start TWAMP Client");

    ServerGreeting *srvGreetings = malloc(SERVER_GREETINGS_SIZE);
    SetupResponse *stpResponse = malloc(SETUP_RESPONSE_SIZE);
    memset(stpResponse, 0 , SETUP_RESPONSE_SIZE);
    ServerStart *srvStart = malloc(SERVER_START_SIZE);
    
    RequestSession *rqtSession = malloc(REQUEST_SESSION_SIZE);
    memset(rqtSession, 0 , REQUEST_SESSION_SIZE);
    AcceptSession *actSession = malloc(ACCEPT_SESSION_SIZE);
    StartSessions *strSession = malloc(START_SESSIONS_SIZE);
    memset(strSession, 0 , START_SESSIONS_SIZE);
    StartAck *strAck = malloc(START_ACK_SIZE);

    StopSessions *stpSessions = malloc(sizeof(StopSessions));
    memset(stpSessions, 0 , sizeof(StopSessions));

    // CREATE SOCKET
    memset(&remote_addr_control, 0, sizeof(struct sockaddr_storage));
    fd_control = usock_inet_timeout(USOCK_TCP | convert_family(param.family), param.host, param.port, &remote_addr_control, 2000);
    if (fd_control < 0) {
        ERROR_LOG(fd_control, "could not resolve server name or address");
        simet_err = 1;
        goto MEM_FREE;
    }

    fd_ready = usock_wait_ready(fd_control, 5000);
    if (fd_ready != 0) {
        ERROR_LOG(fd_ready, "connection to server failed");
        simet_err = 1;
        goto MEM_FREE;
    }

    INFO_LOG("CONTROL socket connected");

    // Store remote address for report
    char hostAddr[INET6_ADDRSTRLEN];
    if (get_ip_str(&remote_addr_control, hostAddr, INET6_ADDRSTRLEN) == NULL) {
        WARNING_LOG("get_ip_str problem");
    }
    report->address = hostAddr;

    memset(&local_addr_measure, 0, sizeof(struct sockaddr_storage));
    cp_remote_addr(&remote_addr_control, &local_addr_measure);

    if (remote_addr_control.ss_family == AF_INET) {
        param.family = 4;
    } else {
        param.family = 6;
    }

    // SERVER GREETINGS
    ret_socket = message_server_greetings(fd_control, 10, srvGreetings);
    if (ret_socket != SERVER_GREETINGS_SIZE) {
        INFO_LOG("message_server_greetings problem");
        simet_err = 1;
        goto CONTROL_CLOSE;
    }

    INFO_LOG("Server Greetings received");

    if (message_validate_server_greetings(srvGreetings) != 0) {
        ERROR_LOG(0, "message_validate_server_greetings problem");
        simet_err = 1;
        goto CONTROL_CLOSE;
    }

    // SETUP RESPONSE
    INFO_LOG("Preparing Setup Response message");

    if (message_format_setup_response(srvGreetings, stpResponse) != 0) {
        ERROR_LOG(0, "message_setup_response problem");
        simet_err = 1;
        goto CONTROL_CLOSE;
    }

    ret_socket = message_send(fd_control, 10, stpResponse, SETUP_RESPONSE_SIZE);
    if (ret_socket <= 0) {
        INFO_LOG("message_send problem");
        simet_err = 1;
        goto CONTROL_CLOSE;
    }

    INFO_LOG("Setup Response message sent");

    // SERVER START
    ret_socket = message_server_start(fd_control, 10, srvStart);
    if (ret_socket <= 0) {
        INFO_LOG("message_server_start problem");
        simet_err = 1;
        goto CONTROL_CLOSE;
    }

    if(srvStart->Accept != 0) {
        INFO_LOG("Test not accepted: %"PRIu8 ,srvStart->Accept);
        simet_err = 1;
        goto CONTROL_CLOSE;
    }

    INFO_LOG("Server Start received");

    // REQUEST SESSION
    socklen_t addr_len = sizeof(local_addr_control);
    memset(&local_addr_control, 0, addr_len);
	if (getsockname(fd_control, (struct sockaddr *) &local_addr_control, (socklen_t *) &addr_len) < 0){
        INFO_LOG("getsockname problem");
        simet_err = 1;
        goto CONTROL_CLOSE;
	}

    char str[INET6_ADDRSTRLEN];
    if (get_ip_str(&local_addr_control, str, INET6_ADDRSTRLEN) == NULL) {
        INFO_LOG("get_ip_str problem");
        simet_err = 1;
        goto CONTROL_CLOSE;
    }

    INFO_LOG("local address is %s", str);

    // CREATE SOCKET
    memset(&remote_addr_measure, 0, sizeof(struct sockaddr_storage));
    fd_test = usock_inet_timeout(USOCK_UDP | convert_family(param.family), param.host, "862", &remote_addr_measure, 2000);
    if (fd_test < 0) {
        ERROR_LOG(fd_test, "usock_inet_timeout problem");
        simet_err = 1;
        goto CONTROL_CLOSE;
    }

    fd_ready = usock_wait_ready(fd_test, 5000);
    if (fd_ready != 0) {
        ERROR_LOG(fd_ready, "usock_wait_ready problem");
        simet_err = 1;
        goto TEST_CLOSE;
    }

    INFO_LOG("TEST socket connected");
    DEBUG_LOG("sin_addr: %u", ((struct sockaddr_in *)&remote_addr_measure)->sin_addr);
    DEBUG_LOG("sin_port: %u", ntohs(((struct sockaddr_in *)&remote_addr_measure)->sin_port));

    // Get Sender Port
    uint16_t sender_port = 862;
    addr_len = sizeof(local_addr_measure);
    memset(&local_addr_measure, 0, addr_len);
	if (getsockname(fd_test, (struct sockaddr *) &local_addr_measure, (socklen_t *) &addr_len) < 0){
        INFO_LOG("getsockname problem");
        simet_err = 1;
        goto TEST_CLOSE;
	}

    // Verificar se o Endian está invertido....
    switch(local_addr_measure.ss_family) {
        case AF_INET:
            sender_port = ntohs(((struct sockaddr_in *) &local_addr_measure)->sin_port);
            INFO_LOG("PORT IPv4 %u", sender_port);
            break;

        case AF_INET6:
            sender_port = ntohs(((struct sockaddr_in6 *) &local_addr_measure)->sin6_port);
            INFO_LOG("PORT IPv6: %u", sender_port);
            break;

        default:
            break;
    }

    if (message_format_request_session(param.family, sender_port, rqtSession) != 0) {
        INFO_LOG("message_format_request_session problem");
        simet_err = 1;
        goto TEST_CLOSE;
    }

    ret_socket = message_send(fd_control, 10, rqtSession, REQUEST_SESSION_SIZE);
    if (ret_socket <= 0) {
        INFO_LOG("message_send problem");
        simet_err = 1;
        goto TEST_CLOSE;
    }

    // ACCEPT SESSION
    ret_socket = message_accept_session(fd_control, 10, actSession);
    if (ret_socket <= 0) {
        INFO_LOG("message_server_start problem");
        simet_err = 1;
        goto TEST_CLOSE;
    }

    if(actSession->Accept != 0) {
        INFO_LOG("Test not accepted: %"PRIu8 ,actSession->Accept);
        simet_err = 1;
        goto TEST_CLOSE;
    }

    uint16_t receiver_port = actSession->Port;
    report->serverPort = (unsigned int)receiver_port;
    DEBUG_LOG("Session Port: %"PRIu16, receiver_port);

    testPort = malloc(sizeof(char) * 6);
    snprintf(testPort, 6, "%u", receiver_port);

    add_remote_port(&remote_addr_measure, receiver_port);
    addr_len = sizeof(remote_addr_measure);

    DEBUG_LOG("Update Remote Port: %u", ntohs(((struct sockaddr_in *)&remote_addr_measure)->sin_port));
    DEBUG_LOG("Addr value: %u", ((struct sockaddr_in *)&remote_addr_measure)->sin_addr);

    DEBUG_LOG("fd_test before: %d", fd_test);

    if (connect(fd_test, (struct sockaddr *) &remote_addr_measure, remote_addr_measure.ss_family == AF_INET ? sizeof(struct sockaddr_in) :
sizeof(struct sockaddr_in6)) != 0) {
        ERRNO_LOG("connect to remote measurement peer problem");
        simet_err = 1;
        goto TEST_CLOSE;
    }

    DEBUG_LOG("fd_test after: %d", fd_test);

    // START SESSION
    strSession->Type = 2;
    ret_socket = message_send(fd_control, 10, strSession, START_SESSIONS_SIZE);
    if (ret_socket <= 0) {
        INFO_LOG("message_send problem");
        simet_err = 1;
        goto TEST_CLOSE;
    }

    // START ACK
    ret_socket = message_start_ack(fd_control, 10, strAck);
    if (ret_socket <= 0) {
        INFO_LOG("message_start_ack problem");
        simet_err = 1;
        goto TEST_CLOSE;
    }
    
    if (strAck->Accept == 0) {
        INFO_LOG("Accept == 0. Start Test");
        t_param.test_socket = fd_test;
        twamp_test(t_param);

        message_format_stop_sessions(stpSessions);
        message_send(fd_control, 10, stpSessions, sizeof(StopSessions));
    } else {
        INFO_LOG("Accept != 0. Accept: %"PRIu8, strAck->Accept);
        goto TEST_CLOSE;
    }

    twamp_report(report);

    DEBUG_LOG("Total packet sent: %u -- Total packets received: %u", t_param.report->result->packets_sent, t_param.report->result->received_packets);

TEST_CLOSE:
    if (shutdown(fd_test, SHUT_RDWR) != 0) {
        ERRNO_LOG("TEST socket shutdown problem");
        goto CONTROL_CLOSE;
    }
    INFO_LOG("TEST socket shutdown OK");

    if (close(fd_test) != 0) {
        ERRNO_LOG("TEST socket close problem");
        goto CONTROL_CLOSE;
    }
    INFO_LOG("TEST socket close OK");

CONTROL_CLOSE:
    if (shutdown(fd_control, SHUT_RDWR) != 0) {
        ERRNO_LOG("CONTROL socket shutdown problem");
        goto MEM_FREE;
    }
    INFO_LOG("CONTROL socket shutdown OK");

    if (close(fd_control) != 0) {
        ERRNO_LOG("CONTROL socket close problem");
        goto MEM_FREE;
    }
    INFO_LOG("CONTROL socket close OK");

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

    // free report data
    if (report) {
        if (report->result)
                free(report->result->raw_data);
        free(report->result);
        free(report);
    }

    return simet_err;
}

static int convert_family(int family) {
    if (family == 4)
		return USOCK_IPV4ONLY;
	else if (family == 6)
		return USOCK_IPV6ONLY;
	else
		return 0;
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
    uint pkg_count = 0;

	struct timeval tv_cur, tv_stop, tv_recv;
    UnauthReflectedPacket *reflectedPacket = malloc(sizeof(UnauthReflectedPacket));
    memset(reflectedPacket, 0, sizeof(UnauthReflectedPacket));

    // Get the current time and set the timeout value in tv_stop
	gettimeofday(&tv_cur, NULL);
	tv_stop.tv_usec = tv_cur.tv_usec;
	tv_stop.tv_sec = tv_cur.tv_sec + (long)t_param->param.timeout_test;

	while (timercmp(&tv_cur, &tv_stop, <) && (pkg_count < t_param->param.packets_count)) {
        // Read message
		bytes_recv = receive_reflected_packet(t_param->test_socket, 10, reflectedPacket);

        gettimeofday(&tv_recv, NULL);

		if (bytes_recv != sizeof(UnauthReflectedPacket)) {
            // Somthing is wrong
            WARNING_LOG("Unexpected message size. bytes_recv(%d) != sizeof(UnauthReflectedPacket)", bytes_recv);
        } else {
            // Save result
            t_param->report->result->raw_data[pkg_count].time = timeval_to_timestamp(&tv_recv);
            memcpy(&(t_param->report->result->raw_data[pkg_count].data), reflectedPacket, sizeof(UnauthReflectedPacket));
            pkg_count++;
		}

		gettimeofday(&tv_cur, NULL);
	}

    // Store total received packets
    t_param->report->result->received_packets = pkg_count;

    free(reflectedPacket);

	return NULL;
}

static int twamp_test(TestParameters test_param) {
    struct timeval tv_cur, tv_stop;
    uint counter = 0;
    int send_resp = 0;
	
    UnauthPacket *packet = malloc(sizeof(UnauthPacket));
    memset(packet, 0 , sizeof(UnauthPacket));

    pthread_t receiver_thread;
	pthread_create(&receiver_thread, NULL, twamp_callback_thread, &test_param);

    // Sending test packets
    gettimeofday(&tv_cur, NULL);
    tv_stop.tv_sec = tv_cur.tv_sec + (long)test_param.param.timeout_test;
    tv_stop.tv_usec = tv_cur.tv_usec;

    while(timercmp(&tv_cur, &tv_stop, <) && (counter < test_param.param.packets_count)) {
        // Set packet counter
        packet->SeqNumber = htonl(counter++);
    
        // Set packet timestamp
        Timestamp ts = timeval_to_timestamp(&tv_cur);
        encode_be_timestamp(&ts);
        packet->Time = ts;

        send_resp = message_send(test_param.test_socket, 5, packet, sizeof(UnauthPacket));
        if (send_resp == -1) {
            WARNING_LOG("message_send returned -1");
            counter--;
        }
        usleep(test_param.param.packets_interval_ns);
        gettimeofday(&tv_cur, NULL);
    }

    if (pthread_join(receiver_thread, NULL) == 0) {
        DEBUG_LOG("[THREAD] twamp_callback_thread ended OK!");
    } else {
        WARNING_LOG("[THREAD] twamp_callback_thread ended with problem!");
    }

    test_param.report->result->packets_sent = counter;

    // FREE
    free(packet);

    return 0;
}

static int receive_reflected_packet(int socket, int timeout, UnauthReflectedPacket* reflectedPacket) {
    int recv_size = 0, recv_total = 0;
    uint8_t message[MAX_SIZE_MESSAGE];
    int fd_ready = 0;
    fd_set rset, rset_master;
    struct timeval tv_timeo, tv_cur;

    FD_ZERO(&rset_master);
    FD_SET((unsigned long)socket, &rset_master);

    do {
        memset(&message, 0, MAX_SIZE_MESSAGE);
        memcpy(&rset, &rset_master, sizeof(rset_master));

        tv_timeo.tv_sec = 5;
        tv_timeo.tv_usec = 0;

        fd_ready = select(socket+1, &rset, NULL, NULL, &tv_timeo);

        if (fd_ready <= 0) {
            if (fd_ready == 0) {
                INFO_LOG("receive_reflected_packet select timeout");
            } else {
                ERROR_LOG(fd_ready, "receive_reflected_packet select problem");
            }

            break;
        } else {
            if (FD_ISSET((unsigned long)socket, &rset)) {
                recv_size = recv(socket, message, MAX_SIZE_MESSAGE, 0);

                gettimeofday(&tv_cur, NULL);

                // Caso recv apresente algum erro
                if (recv_size <= 0) {
                    if (recv_size == 0) {
                        INFO_LOG("recv problem: recv_size == 0");
                        break;
                    }

                    // Se o erro for EAGAIN e EWOULDBLOCK, tentar novamente
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        continue;
                    } else {
                        ERRNO_LOG("recv message problem");
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

                WARNING_LOG("recv_total different then expected");
            } else {
                WARNING_LOG("socket not in rset");
            }
        }

    } while ((tv_timeo.tv_sec > 0) && (tv_timeo.tv_usec > 0));

    return -1;
}
