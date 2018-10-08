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

// timeval_to_timestamp converts struct timeval to Timestamp
Timestamp timeval_to_timestamp(const struct timeval *tv);

// timestamp_to_timeval converts Timestamp to struct timeval
struct timeval timestamp_to_timeval(const Timestamp *ts);

// encode_be_timestamp converts Timestamp to Big Endian (Network)
void encode_be_timestamp(Timestamp *ts);

// decode_be_timestamp converts Big Endian (Network) to local Endian
void decode_be_timestamp(Timestamp *ts);

uint64_t timeval_to_microsec(const struct timeval *tv);

#endif /* NTP_TIMESTAMP_H_ */
