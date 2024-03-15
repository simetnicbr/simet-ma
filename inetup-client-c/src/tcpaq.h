/*
 * tcp-aq: tcp async queueing layer
 * Copyright (c) 2018-2024 NIC.br <medicoes@simet.nic.br>
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

#ifndef SIMET_TCPAQ_H
#define SIMET_TCPAQ_H

#include <sys/socket.h>

#define SIMET_TCPAQ_QUEUESIZE 8192U
struct tcpaq_queue {
    char *buffer;
    size_t buffer_size;
    size_t rd_pos;
    size_t wr_pos_reserved;
    size_t wr_pos;
};

struct tcpaq_conn {
    struct tcpaq_queue in_queue;
    struct tcpaq_queue out_queue;

    sa_family_t ai_family;
    int socket;
};

int tcpaq_init(struct tcpaq_conn * const s, size_t qsize);
void tcpaq_free_members(struct tcpaq_conn * const s);
void tcpaq_close(struct tcpaq_conn * const s);
int tcpaq_reserve(struct tcpaq_conn * const s, size_t size);
int tcpaq_unreserve(struct tcpaq_conn * const s, size_t size);
int tcpaq_queue(struct tcpaq_conn * const s, void *data, size_t size, int reserved);
int tcpaq_is_out_queue_empty(struct tcpaq_conn * const s);
int tcpaq_flush_nowait(struct tcpaq_conn * const s); /* same as send_nowait but returns -EAGAIN, -EINTR */
int tcpaq_send_nowait(struct tcpaq_conn * const s);
int tcpaq_drain(struct tcpaq_conn * const s);
int tcpaq_discard(struct tcpaq_conn * const s, size_t object_size);
int tcpaq_receive_nowait(struct tcpaq_conn * const s, size_t object_size, void *buf) __attribute__((__unused__));
int tcpaq_peek_nowait(struct tcpaq_conn * const s, size_t object_size, const char **pbuf);

#endif /* SIMET_TCPAQ_H */

/* vim: set et ts=4 sw=4 : */
