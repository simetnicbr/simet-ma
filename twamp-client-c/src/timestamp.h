/*
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
 *
 * Y2k36 safety (NTP): safe for y2010-y2145
 * Y2k38 safety (unix int32_t time_t rollover): unsafe.
 */

#ifndef TWAMP_NTP_TIMESTAMP_H_
#define TWAMP_NTP_TIMESTAMP_H_

#include <inttypes.h>

#include <time.h>      /* for struct timespec */
#include <sys/time.h>  /* for struct timeval, suseconds_t */

#include <arpa/inet.h> /* for hton* */

/* Timestamp is NTP time (RFC1305).
 * Should be in network byte order!      */
typedef struct ntp_timestamp {
    uint32_t integer;
    uint32_t fractional;
} Timestamp;


/***********/
/* HELPERS */
/***********/

// converts ts_now + ts_offset to Timestamp
Timestamp relative_timespec_to_timestamp(const struct timespec * const ts_now, const struct timespec * const ts_offset);

// timeval_to_timestamp converts struct timeval to Timestamp
Timestamp timeval_to_timestamp(const struct timeval *tv);

/* timestamp_to_timeval converts Timestamp to struct timeval */
struct timeval timestamp_to_timeval(const Timestamp ts);

/* local endian to network endian, for Timestamp */
static inline Timestamp hton_timestamp(Timestamp ts) {
    ts.integer = htonl(ts.integer);
    ts.fractional = htonl(ts.fractional);
    return ts;
}

/* network endian to local endian, for Timestamp */
static inline Timestamp ntoh_timestamp(Timestamp ts) {
    ts.integer = ntohl(ts.integer);
    ts.fractional = ntohl(ts.fractional);
    return ts;
}

static inline uint64_t timeval_to_microsec(const struct timeval tv) {
    int64_t ret_microsec = (int64_t)tv.tv_sec * 1000000;
    ret_microsec += tv.tv_usec;
    return (ret_microsec >= 0) ? (uint64_t)ret_microsec : 0;
}

static inline uint64_t timestamp_to_microsec(const Timestamp ts) {
    return timeval_to_microsec(timestamp_to_timeval(ts));
}

#endif /* TWAMP_NTP_TIMESTAMP_H_ */
