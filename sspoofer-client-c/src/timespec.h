/*
 * Copyright (c) 2023 NIC.br <medicoes@simet.nic.br>
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
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef NICBR_TIMESPEC_H
#define NICBR_TIMESPEC_H

#include <time.h>

#define MICROSECONDS_IN_SECOND 1000000LL
#define NANOSECONDS_IN_SECOND  1000000000LL
#define TIMESPEC_NANOSECONDS(ts) ((ts.tv_sec * NANOSECONDS_IN_SECOND) + ts.tv_nsec)

/* normalize in the general case, suboptimal if just one add or sub */
static inline void timespec_normalize(struct timespec * const ts1)
{
    while (ts1->tv_nsec >= NANOSECONDS_IN_SECOND) {
	++ts1->tv_sec;
	ts1->tv_nsec -= NANOSECONDS_IN_SECOND;
    }
    while (ts1->tv_nsec < 0) {
	--ts1->tv_sec;
	ts1->tv_nsec += NANOSECONDS_IN_SECOND;
    }
}

/* ts1, ts2 must be normalized. Must not be NULL */
static inline int timespec_lt(const struct timespec * const ts1, const struct timespec * const ts2)
{
    return (ts1->tv_sec < ts2->tv_sec || (ts1->tv_sec == ts2->tv_sec && ts1->tv_nsec < ts2->tv_nsec));
}

/* ts1, ts2 must be normalized. Must not be NULL */
static inline int timespec_le(const struct timespec * const ts1, const struct timespec * const ts2)
{
    return (ts1->tv_sec < ts2->tv_sec || (ts1->tv_sec == ts2->tv_sec && ts1->tv_nsec <= ts2->tv_nsec));
}

/* ts1, ts2 must be normalized. Must not be NULL */
static inline struct timespec timespec_add(const struct timespec * const ts1, const struct timespec * const ts2)
{
    struct timespec result;

    result.tv_sec = ts1->tv_sec + ts2->tv_sec;
    result.tv_nsec = ts1->tv_nsec + ts2->tv_nsec;
    if (result.tv_nsec >= NANOSECONDS_IN_SECOND) {
	++result.tv_sec;
	result.tv_nsec -= NANOSECONDS_IN_SECOND;
    }
    return result;
}

static inline struct timespec timespec_add_microseconds(const struct timespec * const base, const long us)
{
    struct timespec result;

    result.tv_sec = base->tv_sec;
    result.tv_nsec = base->tv_nsec + us * 1000L; /* can be negative */
    while (result.tv_nsec < 0) {
	--result.tv_sec;
	result.tv_nsec += NANOSECONDS_IN_SECOND;
    }
    while (result.tv_nsec >= NANOSECONDS_IN_SECOND) {
	++result.tv_sec;
	result.tv_nsec -= NANOSECONDS_IN_SECOND;
    }
    return result;
}

/* returns 0 for no timeout, or a CLOCK_MONOTONIC deadline */
static inline struct timespec timespec_deadline_microseconds(long us_from_now)
{
    struct timespec result = { 0 };
    if (us_from_now > 0) {
	clock_gettime(CLOCK_MONOTONIC, &result);
	while (us_from_now > MICROSECONDS_IN_SECOND) {
	    ++result.tv_sec;
	    us_from_now -= MICROSECONDS_IN_SECOND;
	}
	result.tv_nsec += us_from_now * 1000L;
	while (result.tv_nsec >= NANOSECONDS_IN_SECOND) {
	    ++result.tv_sec;
	    result.tv_nsec -= NANOSECONDS_IN_SECOND;
	}
    }
    return result;
}

/* returns 0 for no timeout, or a CLOCK_MONOTONIC deadline */
static inline struct timespec timespec_deadline_seconds(long s_from_now)
{
    struct timespec result = { 0 };
    if (s_from_now > 0) {
	clock_gettime(CLOCK_MONOTONIC, &result);
	result.tv_sec += s_from_now;
    }
    return result;
}

/* t1, ts2 must be normalized */
static inline struct timespec timespec_sub(const struct timespec * const ts1, const struct timespec * const ts2)
{
    struct timespec result;

    result.tv_sec = ts1->tv_sec - ts2->tv_sec;
    result.tv_nsec = ts1->tv_nsec - ts2->tv_nsec;
    if (result.tv_nsec < 0) {
	--result.tv_sec;
	result.tv_nsec += NANOSECONDS_IN_SECOND;
    }
    return result;
}

/*
 * ts1, ts2 must be normalized. clamps to a minimum of sat_nsec.
 * sat_nsec *must* be in the [0, NANOSECONDS_IN_SECOND) range or the result will be non-normalized
 */
static inline struct timespec timespec_sub_saturated(const struct timespec * const ts1, const struct timespec * const ts2, const long sat_nsec)
{
    struct timespec result;

    result = timespec_sub(ts1, ts2);
    if (result.tv_sec < 0) {
	result.tv_sec = 0;
	result.tv_nsec = sat_nsec;
    }
    return result;
}

static inline long long timespec_sub_nanoseconds(const struct timespec * const ts1, const struct timespec * const ts2)
{
    return (long long)((long long)ts1->tv_sec - ts2->tv_sec) * NANOSECONDS_IN_SECOND + (ts1->tv_nsec - ts2->tv_nsec);
}

static inline long long timespec_sub_microseconds(const struct timespec * const ts1, const struct timespec * const ts2)
{
    return (long long)(ts1->tv_sec - ts2->tv_sec) * MICROSECONDS_IN_SECOND + (ts1->tv_nsec - ts2->tv_nsec)/1000;
}

static inline struct timespec microseconds_to_timespec(long microseconds)
{
    struct timespec result =  { .tv_sec = 0 };
    while (microseconds > MICROSECONDS_IN_SECOND) {
	result.tv_sec++;
	microseconds -= MICROSECONDS_IN_SECOND;
    }
    result.tv_nsec = microseconds * 1000L;
    return result;
}

#endif /* NICBR_TIMESPEC_H */
