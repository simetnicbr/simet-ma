/*
 * SIMET2 MA - TWAMP client
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

#ifndef TWAMP_H_
#define TWAMP_H_

#include "report.h"

#ifdef  HAVE_JSON_C_JSON_H
#include <json-c/json.h>
#elif HAVE_JSON_JSON_H
#include <json/json.h>
#elif HAVE_JSON_H
#include <json.h>
#endif

/* TWAMP parameters struct */
typedef struct twamp_parameters {
    char *device_id;
    char *host;
    char *port;
    int family;
    int connect_timeout;
    unsigned int packets_count;
    long int packets_interval_us;
    long int packets_timeout_us;
} TWAMPParameters;

typedef struct twamp_test_parameters {
    int test_socket;
    TWAMPParameters param;
    TWAMPReport * report;
} TestParameters;

int twamp_run_client(TWAMPParameters param);
int twamp_report(TWAMPReport*, TWAMPParameters*);
TWAMPReport * twamp_report_init(void);
void twamp_report_done(TWAMPReport *);
int report_socket_metrics(TWAMPReport *, int sockfd, int sock_protocol);

#endif /* TWAMP_H_ */
