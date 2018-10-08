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

#include "message.h"

#include "logger.h"

#include <stdint.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>

#include <arpa/inet.h>

/********************/
/* MESSAGES READERS */
/********************/

int message_server_greetings(int socket, int timeout, ServerGreeting *srvGreetings) {
    int recv_size = 0, recv_total = 0;
    uint8_t message[MAX_SIZE_MESSAGE];
    int fd_ready = 0;
    fd_set rset, rset_master;
    struct timeval tv_timeo;

    FD_ZERO(&rset_master);
    FD_SET((unsigned long)socket, &rset_master);

    tv_timeo.tv_sec = timeout;
    tv_timeo.tv_usec = 0;

    do {
        memset(&message, 0, MAX_SIZE_MESSAGE);
        memcpy(&rset, &rset_master, sizeof(rset_master));

        fd_ready = select(socket+1, &rset, NULL, NULL, &tv_timeo);

        if (fd_ready <= 0) {
            if (fd_ready == 0) {
                WARNING_LOG("message_server_greetings select timeout!");
            } else {
                ERROR_LOG(fd_ready, "message_server_greetings select problem!");
            }
        } else {
            if (FD_ISSET((unsigned long)socket, &rset)) {
                recv_size = recv(socket, message, MAX_SIZE_MESSAGE, 0);

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

                memcpy(srvGreetings + recv_total, &message, (unsigned int)recv_size);
                recv_total += recv_size;

                if (recv_total == SERVER_GREETINGS_SIZE) {

                    srvGreetings->Modes = ntohl(srvGreetings->Modes);
                    srvGreetings->Count = ntohl(srvGreetings->Count);

                    return recv_total;
                }

                WARNING_LOG("recv_total different then expected!");
            } else {
                WARNING_LOG("socket not in rset!");
            }
        }

    } while (tv_timeo.tv_sec > 0);

    return -1;
}

int message_server_start(int socket, int timeout, ServerStart *srvStart) {
    int recv_size = 0, recv_total = 0;
    uint8_t message[MAX_SIZE_MESSAGE];
    int fd_ready = 0;
    fd_set rset, rset_master;
    struct timeval tv_timeo;

    FD_ZERO(&rset_master);
    FD_SET((unsigned long)socket, &rset_master);

    tv_timeo.tv_sec = timeout;
    tv_timeo.tv_usec = 0;

    do {
        memset(&message, 0, MAX_SIZE_MESSAGE);
        memcpy(&rset, &rset_master, sizeof(rset_master));

        fd_ready = select(socket+1, &rset, NULL, NULL, &tv_timeo);

        if (fd_ready <= 0) {
            if (fd_ready == 0) {
                WARNING_LOG("message_server_greetings select timeout!");
            } else {
                ERROR_LOG(fd_ready, "message_server_greetings select problem!");
            }
        } else {
            if (FD_ISSET((unsigned long)socket, &rset)) {
                recv_size = recv(socket, message, MAX_SIZE_MESSAGE, 0);

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

                memcpy(srvStart + recv_total, &message, (unsigned int)recv_size);
                recv_total += recv_size;

                if (recv_total == SERVER_START_SIZE) {
                    srvStart->StartTime.integer = ntohl(srvStart->StartTime.integer);
                    srvStart->StartTime.fractional = ntohl(srvStart->StartTime.fractional);

                    return recv_total;
                }

                WARNING_LOG("recv_total different then expected!");
            } else {
                WARNING_LOG("socket not in rset!");
            }
        }

    } while (tv_timeo.tv_sec > 0);

    return -1;
}

int message_accept_session(int socket, int timeout, AcceptSession *actSession) {
    int recv_size = 0, recv_total = 0;
    uint8_t message[MAX_SIZE_MESSAGE];
    int fd_ready = 0;
    fd_set rset, rset_master;
    struct timeval tv_timeo;

    FD_ZERO(&rset_master);
    FD_SET((unsigned long)socket, &rset_master);

    tv_timeo.tv_sec = timeout;
    tv_timeo.tv_usec = 0;

    do {
        memset(&message, 0, MAX_SIZE_MESSAGE);
        memcpy(&rset, &rset_master, sizeof(rset_master));

        fd_ready = select(socket+1, &rset, NULL, NULL, &tv_timeo);

        if (fd_ready <= 0) {
            if (fd_ready == 0) {
                WARNING_LOG("message_accept_session select timeout!");
            } else {
                ERROR_LOG(fd_ready, "message_accept_session select problem!");
            }
        } else {
            if (FD_ISSET((unsigned long)socket, &rset)) {
                recv_size = recv(socket, message, MAX_SIZE_MESSAGE, 0);

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

                memcpy(actSession + recv_total, &message, (unsigned int)recv_size);
                recv_total += recv_size;

                if (recv_total == ACCEPT_SESSION_SIZE) {
                    actSession->Port = ntohs(actSession->Port);

                    return recv_total;
                }

                WARNING_LOG("recv_total different then expected!");
            } else {
                WARNING_LOG("socket not in rset!");
            }
        }

    } while (tv_timeo.tv_sec > 0);

    return -1;
}

int message_start_ack(int socket, int timeout, StartAck *strAck) {
    int recv_size = 0, recv_total = 0;
    uint8_t message[MAX_SIZE_MESSAGE];
    int fd_ready = 0;
    fd_set rset, rset_master;
    struct timeval tv_timeo;

    FD_ZERO(&rset_master);
    FD_SET((unsigned long)socket, &rset_master);

    tv_timeo.tv_sec = timeout;
    tv_timeo.tv_usec = 0;

    do {
        memset(&message, 0, MAX_SIZE_MESSAGE);
        memcpy(&rset, &rset_master, sizeof(rset_master));

        fd_ready = select(socket+1, &rset, NULL, NULL, &tv_timeo);

        if (fd_ready <= 0) {
            if (fd_ready == 0) {
                WARNING_LOG("message_accept_session select timeout!");
            } else {
                ERROR_LOG(fd_ready, "message_accept_session select problem!");
            }
        } else {
            if (FD_ISSET((unsigned long)socket, &rset)) {
                recv_size = recv(socket, message, MAX_SIZE_MESSAGE, 0);

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

                memcpy(strAck + recv_total, &message, (unsigned int)recv_size);
                recv_total += recv_size;

                if (recv_total == START_ACK_SIZE) {
                    return recv_total;
                }

                WARNING_LOG("recv_total different then expected!");
            } else {
                WARNING_LOG("socket not in rset!");
            }
        }

    } while (tv_timeo.tv_sec > 0);

    return -1;
}

/********************/
/* MESSAGES SENDERS */
/********************/

int message_send(int socket, int timeout, void *message, size_t len) {
    int send_size = 0, send_total = 0;
    int fd_ready = 0;
    fd_set wset, wset_master;
    struct timeval tv_timeo;

    FD_ZERO(&wset_master);
    FD_SET((unsigned long)socket, &wset_master);

    tv_timeo.tv_sec = timeout;
    tv_timeo.tv_usec = 0;
    
    do {
        memcpy(&wset, &wset_master, sizeof(wset_master));

        fd_ready = select(socket+1, NULL, &wset, NULL, &tv_timeo);

        if (fd_ready <= 0) {
            if (fd_ready == 0) {
                WARNING_LOG("message_send select timeout!");
            } else {
                ERROR_LOG(fd_ready, "message_send select problem!");
            }
        } else {
            if (FD_ISSET((unsigned long)socket, &wset)) {
                send_size = send(socket, message + send_total, len - (unsigned long)send_total, 0);
                send_total += send_size;

                if ((unsigned long)send_total == len) {
                    return send_size;
                }

                WARNING_LOG("send_total different then expected!");
            } else {
                WARNING_LOG("socket not in wset!");
            }
        }
    } while ((tv_timeo.tv_sec > 0) && (tv_timeo.tv_usec > 0));
    
    return -1;
}


/***********************/
/* MESSAGES VALIDATORS */
/***********************/

int message_validate_server_greetings(ServerGreeting *srvGreetings) {
    if (srvGreetings->Modes == 0) {
        INFO_LOG("Modes == 0 - the server does not wish to communicate");
        return -1;
    }

    return 0;
}

/***********************/
/* MESSAGES FORMATTERS */
/***********************/

int message_format_setup_response(ServerGreeting *srvGreetings, SetupResponse *stpResponse) {
    stpResponse->Mode = srvGreetings->Modes & (01);
    stpResponse->Mode = htonl(stpResponse->Mode);

    return 0;
}

int message_format_request_session(int ipvn, uint16_t sender_port, RequestSession *rqtSession) {
    rqtSession->Type = 5;
    
    // Set 0 as default
    rqtSession->ConfSender = 0;
    rqtSession->ConfReceiver = 0;
    rqtSession->SlotsNo = 0;
    rqtSession->PacketsNo = 0;
    rqtSession->IPVN = (uint8_t)ipvn;
    rqtSession->PaddingLength = htonl(TST_PKT_SIZE - 14); /* FIXME */

    rqtSession->SenderAddress = htonl(0);
    rqtSession->ReceiverAddress = htonl(0);

    rqtSession->SenderPort = htons(sender_port);
    rqtSession->ReceiverPort = htons(862);

    return 0;
}

int message_format_stop_sessions(StopSessions *stpSessions) {
    stpSessions->Type = 3;
    stpSessions->Accept = 0;

    stpSessions->SessionsNo = htonl(1);

    return 0;
}
