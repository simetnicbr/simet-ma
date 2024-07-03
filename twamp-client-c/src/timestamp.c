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

#include <assert.h>
#if !defined(static_assert) && defined(__STDC_VERSION__) && (__STDC_VERSION__ < 202301L)
#  define static_assert _Static_assert
#endif

/* NTP era 0 (1900-01-01) to UNIX epoch offset (1970-01-01) */
#define NTP_TIMESTAMP_UNIX_EPOCH    (2208988800U)   /* 70 years = 2208988800 seconds */
#define NTP_TIMESTAMP_UNIX_EPOCH_LL (2208988800LL)

/* UNIX timestamp when to switch from NTP era 0 to era 1 */
#define UNIX_TIMESTAMP_2K10      (1262304000U)

struct timeval timestamp_to_timeval(const Timestamp ts) {
    struct timeval ret_tv;

    static_assert(NTP_TIMESTAMP_UNIX_EPOCH < UINT32_MAX - UNIX_TIMESTAMP_2K10,
		  "NTP era rollover detection point must be < UINT32_MAX");
    if (ts.integer >= NTP_TIMESTAMP_UNIX_EPOCH + UNIX_TIMESTAMP_2K10) {
	/* ntp era 0, 32-bit time_t safe */
	static_assert(UINT32_MAX - NTP_TIMESTAMP_UNIX_EPOCH < INT32_MAX, "Something insane happaned");
        ret_tv.tv_sec = (time_t)(ts.integer - NTP_TIMESTAMP_UNIX_EPOCH);
    } else {
	/* ntp era 1, needs 64-bit time_t */
	int64_t ut_sec = (int64_t)ts.integer - NTP_TIMESTAMP_UNIX_EPOCH + UINT32_MAX + 1;
	ret_tv.tv_sec = ut_sec; /* y2k38: warn on 32-bit time_t */
    }

    ret_tv.tv_usec = (suseconds_t)((double)ts.fractional * ((double)1e6 / (double)(1uLL<<32)) + 0.5); /* lround(n), n>=0 */
    return ret_tv;
}

Timestamp relative_timespec_to_timestamp(const struct timespec * const ts_now, const struct timespec * const ts_offset)
{
    Timestamp ret_timestamp = { .integer = 0, .fractional = 0 };
    int64_t sec;
    long nsec;

    if (!ts_now || !ts_offset)
        return ret_timestamp;

    /* Realtime is based on UNIX epoch (1970), timestamps are NTP epoch (1900) */
    sec = ts_now->tv_sec + ts_offset->tv_sec + NTP_TIMESTAMP_UNIX_EPOCH_LL;
    nsec = ts_now->tv_nsec + ts_offset->tv_nsec;

    /* our two input timespecs are assumed to be normalized already,
     * but we MUST normalize the result or Bad Things Will Happen.
     * Note that POSIX forbids nsec < 0 */
    while (nsec > 1000000000) {
	sec++;
	nsec -= 1000000000;
    }
    while (nsec < 0) {
	sec--;
	nsec += 1000000000;
    }

    /* should never happen */
    if (sec < 0)
	return ret_timestamp;

    ret_timestamp.integer = (uint32_t)sec;
    /* NTP fraction has base 2^32. round to nearest */
    ret_timestamp.fractional = (uint32_t)((double)(nsec) * ( (double)(1uLL<<32) / (double)1e9 ) + 0.5);

    return ret_timestamp;
}

Timestamp timeval_to_timestamp(const struct timeval *tv) {
    Timestamp ret_timestamp = { .integer = 0, .fractional = 0 };

    if (!tv)
        return ret_timestamp;

    // Convert UNIX epoch (1970) seconds to NTP epoch (1900) seconds
    // 70 years = 2208988800 seconds
    ret_timestamp.integer = (uint32_t)tv->tv_sec + 2208988800U;

    /* Convert 10^6 base to 2^32 base, round to nearest */
    ret_timestamp.fractional = (uint32_t)((double)tv->tv_usec * ( (double)(1uLL<<32) / (double)1e6 ) + 0.5);

    return ret_timestamp;
}

