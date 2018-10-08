/*
 * SIMET2 MA - TCP Bandwidth Measurement (tcpbw) client
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

#ifndef TCP_H_
#define TCP_H_

#include <sys/types.h>

/* TCP measure context struct */
typedef struct measure_context {
    char *agent_id;
    char *host_name;
    char *control_url;
    char *port;
    char *token;
    char *sessionid;
    int family;
    unsigned int timeout_test;
    unsigned int numstreams;
    unsigned int test_duration;
    unsigned int sample_period_ms;
} MeasureContext;

struct MemoryStruct {
    char *memory;
    size_t used;
    size_t allocated;
};

int tcp_client_run(MeasureContext);

#define MAX_CONCURRENT_SESSIONS 10U

#endif /* TCP_H_ */
