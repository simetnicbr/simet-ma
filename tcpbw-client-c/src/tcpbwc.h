/*
 * SIMET2 MA - TCP Bandwidth Measurement (tcpbw) client
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

#ifndef TCPBWC_H_
#define TCPBWC_H_

#include <inttypes.h>
#include <sys/types.h>
#include <stdio.h>
#include <time.h>

/*
 * UI callbacks
 *
 * stage = 0: measurements will start
 * stage = 2: measurement has finished without an error state
 * stage = 3: measurmeent has finished with an error state
 *
 * typedef int (* tcpbw_msmt_cb_fn)(int mode);
 *
 * To enable (example):
 * #define tcpbw_msmt_callback   tcpbw_msmt_android_callback
 *
 * Returns 0 (ok), NZ (SEXIT_* value, terminates measurement with an error)
 */
#ifndef tcpbw_msmt_callback
static inline int tcpbw_msmt_cb(int mode) __attribute__((__unused__));
static inline int tcpbw_msmt_cb(int mode __attribute__((__unused__)))
{
    return 0;
}
#define tcpbw_msmt_callback tcpbw_msmt_cb
#endif

/*
 * Sampling callbacks for the UI
 *
 * mode = 1: during upload measurement (valid: stages 0, 1, 2, 3);
 * mode = 2: during download measurmenet (valid: stages 0, 1, 2, 3);
 *
 * stage = 0: measurement will start, octets is zero. ts is T0 (first timestamp)
 * stage = 1: [over]sample point, octets is *cumulative*, beware uint64_t wrap-around.
 * stage = 2: measurement has finished without an error state.  ts, octets unused.
 * stage = 3: measurement has finished with an error state. ts, octets unused.
 *
 * WARNING: DO NOT DEPEND ON UPLOAD/DOWNLOAD ORDERING, that's why mode 0 exists!
 *
 * typedef int (* tcpbw_sample_cb_fn)(int mode, int stage, const struct timespec * const ts, uint64_t octets);
 *
 * To enable (example):
 * #define tcpbw_sample_callback   tcpbw_sample_android_callback
 *
 * Returns 0 (ok), NZ (SEXIT_* value, terminates measurement with an error)
 */
#ifndef tcpbw_sample_callback
static inline int tcpbw_sample_cb(int mode, int stage,
	const struct timespec * const ts, uint64_t octets)__attribute__((__unused__));
static inline int tcpbw_sample_cb(int mode __attribute__((__unused__)),
	int stage __attribute__((__unused__)),
	const struct timespec * const ts __attribute__((__unused__)),
	uint64_t octets __attribute__((__unused__)))
{
    return 0;
}
#define tcpbw_sample_callback tcpbw_sample_cb
#endif

/* TCP measure context struct */
typedef struct measure_context {
    char *agent_id;
    char *host_name;
    char *control_url;
    char *port;
    char *token;
    char *sessionid;
    int family;
    int report_mode;
    char *streamdata_path;
    FILE *streamdata_file;
    unsigned int timeout_test;
    unsigned int numstreams;
    unsigned int test_duration;
    unsigned int sample_period_ms;
    unsigned int stats_oversampling;
    int stream_start_delay;   /* n < 0: RTT/-n*stream_count; n >= 0: delay (us) */
    unsigned int max_pacing_rate; /* 0: system default */

    size_t outgoing_mss;
    unsigned int rtt; /* smallest RTT (microseconds) */
} MeasureContext;

struct MemoryStruct {
    char *memory;
    size_t used;
    size_t allocated;
};

int tcp_client_run(MeasureContext);

#define MAX_CONCURRENT_SESSIONS 50

#endif /* TCPBWC_H_ */
