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
#include "timestamp.h"

#include <inttypes.h>

#include <arpa/inet.h>
 
Timestamp timeval_to_timestamp(const struct timeval *tv) {
    Timestamp ret_timestamp = { .integer = 0, .fractional = 0 };

    if (!tv)
        return ret_timestamp;

    // Convert UNIX epoch (1970) seconds to NTP epoch (1900) seconds
    // 70 years = 2208988800 seconds
    ret_timestamp.integer = tv->tv_sec + 2208988800uL;

    // Convert 10^6 base to 2^32 base
    ret_timestamp.fractional = (uint32_t) ( (double)tv->tv_usec * ( (double)(1uLL<<32) / (double)1e6 ) );

    return ret_timestamp;
}

struct timeval timestamp_to_timeval(const Timestamp *ts) {
    struct timeval ret_tv = { .tv_sec = 0, .tv_usec = 0 };

    ret_tv.tv_sec = ts->integer - 2208988800uL;

    ret_tv.tv_usec = (uint32_t)( (double)ts->fractional * ((double)1e6 / (double)(1uLL<<32)) );

    return ret_tv;
}

void encode_be_timestamp(Timestamp *ts) {
    ts->integer = htonl(ts->integer);
    ts->fractional = htonl(ts->fractional);
}

void decode_be_timestamp(Timestamp *ts) {
    ts->integer = ntohl(ts->integer);
    ts->fractional = ntohl(ts->fractional);
}

uint64_t timeval_to_microsec(const struct timeval *tv) {
    uint64_t ret_microsec = tv->tv_sec * (1000000);
    ret_microsec += tv->tv_usec;

    return ret_microsec;
}
