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

Timestamp relative_timespec_to_timestamp(const struct timespec * const ts_now, const struct timespec * const ts_offset)
{
    Timestamp ret_timestamp = { .integer = 0, .fractional = 0 };
    unsigned long sec;
    long nsec;

    if (!ts_now || !ts_offset)
        return ret_timestamp;

    /* Realtime is based on UNIX epoch (1970), timestamps are NTP epoch (1900) */
    /* 70 years = 2208988800 seconds */
    sec = ts_now->tv_sec + ts_offset->tv_sec + 2208988800L;
    nsec = ts_now->tv_nsec + ts_offset->tv_nsec;

    /* our two input timespecs are assumed to be normalized already,
     * but we MUST normalize the result or Bad Things Will Happen */
    while (nsec > 1000000000L) {
	sec++;
	nsec -= 1000000000L;
    }
    while (nsec < 0) {
	sec--;
	nsec += 1000000000L;
    }

    /* should never happen */
    if (sec < 0)
	return ret_timestamp;

    ret_timestamp.integer = sec;
    /* NTP fraction has base 2^32 */
    ret_timestamp.fractional = (uint32_t) ( (double)(nsec) * ( (double)(1uLL<<32) / (double)1e9 ) );

    return ret_timestamp;
}

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
    uint64_t ret_microsec = (uint64_t)tv->tv_sec * 1000000U;
    ret_microsec += tv->tv_usec;

    return ret_microsec;
}
