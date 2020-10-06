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

#ifndef NTP_TIMESTAMP_H_
#define NTP_TIMESTAMP_H_

#include <inttypes.h>

#include <sys/types.h>

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

// timestamp_to_timeval converts Timestamp to struct timeval
struct timeval timestamp_to_timeval(const Timestamp *ts);

// encode_be_timestamp converts Timestamp to Big Endian (Network)
void encode_be_timestamp(Timestamp *ts);

// decode_be_timestamp converts Big Endian (Network) to local Endian
void decode_be_timestamp(Timestamp *ts);

uint64_t timeval_to_microsec(const struct timeval *tv);

static inline void timespec_to_offset(struct timespec * const ts_target, const struct timespec * const ts_reference)
{
    ts_target->tv_sec  -= ts_reference->tv_sec;
    ts_target->tv_nsec -= ts_reference->tv_nsec;
}

#endif /* NTP_TIMESTAMP_H_ */
