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

#include "tcpbwc_config.h"
#include "simet_err.h"
#include "tcpbwc.h"
#include "report.h"
#include "logger.h"

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stdbool.h>

#include <assert.h>
#include <errno.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "tcpinfo.h" /* struct simet_tcp_info, alias for struct tcp_info */
#include <linux/sock_diag.h> /* for SO_MEMINFO, SK_MEMINFO_VARS */

#include "json-c/json.h"
#include "curl/curl.h"
#include "libubox/usock.h"

#include "timespec.h"

#define MAX_URL_SIZE 1024
#define TCP_MAX_BUFSIZE 33554432U
#define TCP_DFL_BUFSIZE 1048576U
#define TCP_MIN_BUFSIZE 14800U

#define TCPBW_MAX_SAMPLES 10000
#define TCPBW_RANDOM_SOURCE "/dev/urandom"
#define TCPBW_EARLY_EXIT_S 2

#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

static fd_set sockListFDs;
int sockList[MAX_CONCURRENT_SESSIONS];
size_t sndposList[MAX_CONCURRENT_SESSIONS];
static int sockListLastFD = -1;
static void *sockBuffer = NULL;
static size_t sockBufferSz = 0;

/* FIXME: properly return the several possible errors,
 * such as connection error, out of memory, etc */

/* Measurement channel handling */

/**
 * new_tcp_buffer - allocated appropriately sized zero-filled tcp buffer
 *
 * Sets @p* to the allocated buffer, NULL on failure.  @sockfd is used to automatically
 * size the buffer, it must already have been connected to be of any use.
 *
 * Returns: size in bytes of the buffer, 0 on failure.
 */
static size_t new_tcp_buffer(int sockfd, void **p)
{
    size_t buflen = TCP_DFL_BUFSIZE; /* default application buffer size */
    int optval = 0;
    socklen_t optvalsz;

    assert(p);

    /* grow application buffer size to handle kernel's default socket buffer size */
    optvalsz = sizeof(optval);
    if (!getsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &optval, &optvalsz)) {
	print_msg(MSG_DEBUG, "TCP Socket initial send buffer size: %d bytes", optval);
	if (optval > 0 && (size_t) optval > buflen)
	    buflen = (size_t) optval;
    }

    optvalsz = sizeof(optval);
    if (!getsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &optval, &optvalsz)) {
	print_msg(MSG_DEBUG, "TCP Socket initial receive buffer size: %d bytes", optval);
	if (optval > 0 && (size_t) optval > buflen)
	    buflen = (size_t) optval;
    }

    if (buflen < TCP_MIN_BUFSIZE) {
	buflen = TCP_MIN_BUFSIZE; /* in case of bugs above */
    } else if (buflen > TCP_MAX_BUFSIZE) {
	buflen = TCP_MAX_BUFSIZE;
    }

    print_msg(MSG_DEBUG, "will send/receive using a buffer of %zu bytes", buflen);

    /* create zero-filled buffer to avoid leaking data to network... */
    uint8_t *buf = calloc(1, buflen);

#ifdef TCPBW_DEFEAT_COMPRESSION
    if (buf) {
	/* we just need something that won't compress well */
	const char * const randompath = TCPBW_RANDOM_SOURCE;
	int rfd = open(randompath, O_RDONLY);
	if (rfd < 0) {
	    /* warn and degrade to compressible */
	    print_warn("could not open %s, using compressible payload", randompath);
	} else {
	    uint8_t *bufpos = buf;
	    size_t rdsize = buflen;

	    print_msg(MSG_DEBUG, "generating incompressible payload using %s", randompath);

	    errno = EAGAIN;
	    while (rdsize > 0 && (errno == EINTR || errno == EAGAIN)) {
		ssize_t rlen = read(rfd, bufpos, rdsize);
		if (rlen <= 0 || (size_t) rlen > rdsize) {
		    /* should never happen, unless reading from a short file */
		    print_warn("random source %s misbehaving, payload may be compressible", randompath);
		    break;
		}
		if (rlen > 0) {
		    bufpos += (size_t) rlen;
		    rdsize -= (size_t) rlen; /* rlen <= rdsize ensured above */
		}
	    }
	    close(rfd);
	}
    }
#endif /* TCPBW_DEFEAT_COMPRESSION */

    *p = buf;
    return buf ? buflen : 0;
}

/* sends full message with a timeout, returns -1 on error */
static ssize_t message_send(const int socket, const int timeout, const void * const message, size_t len)
{
    fd_set wset, wset_master;
    int fd_ready = 0;

    struct timespec ts_cur, ts_stop;

    FD_ZERO(&wset_master);
    FD_SET(socket, &wset_master);

    if (clock_gettime(CLOCK_MONOTONIC, &ts_cur)) {
	return -1;
    }
    ts_stop = ts_cur;
    ts_stop.tv_sec += timeout;

    const uint8_t *buf = message;

    do {
	if (len <= 0) {
	    return 0;
	}

	struct timespec ts_timeo = timespec_sub_saturated(&ts_stop, &ts_cur, 1000);

        memcpy(&wset, &wset_master, sizeof(wset_master));
        fd_ready = pselect(socket + 1, NULL, &wset, NULL, &ts_timeo, NULL);
	if (fd_ready < 0 && errno != EINTR) {
	    print_warn("select error: %s", strerror(errno));
	    return -1;
	} else if (fd_ready > 0 && FD_ISSET(socket, &wset)) {
	    ssize_t rc = send(socket, buf, len, MSG_NOSIGNAL | MSG_DONTWAIT);
	    if (rc < 0 && errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
		print_warn("error sending data: %s", strerror(errno));
		return -1;
	    } else if (rc > 0) {
		if ((size_t)rc > len)
		    rc = (ssize_t)len; /* should never happen */

		buf += (size_t) rc; /* rc > 0 */
		len -= (size_t) rc; /* rc > 0 */
	    }
	}

	if (clock_gettime(CLOCK_MONOTONIC, &ts_cur)) {
	    return -1;
	}
    } while (timespec_lt(&ts_cur, &ts_stop));

    return -1;
}

static int create_measure_socket(const char * const host, const char * const port, const char * const sessionid, size_t * const mss, unsigned int * const srtt, unsigned int pacerate)
{
    const int one = 1;
    const int zero = 0;
    int fd_measure;

    if (!sessionid || !port || !host)
	return -1;

    const size_t sessionid_len = strlen(sessionid);
    if (sessionid_len > UINT_MAX) {
	print_warn("session-id length too large");
	return -1;
    }

    struct sockaddr_storage remote_addr_control;
    memset(&remote_addr_control, 0, sizeof(struct sockaddr_storage));
    fd_measure = usock_inet_timeout(USOCK_TCP, host, port, &remote_addr_control, 2000);
    if (fd_measure < 0) {
        print_warn("usock_inet_timeout fd_measure: %i", fd_measure);
        return -1;
    }

    int fd_ready = usock_wait_ready(fd_measure, 5000);
    if (fd_ready != 0) {
        print_warn("usock_wait_ready fd_ready: %i", fd_ready);
        return -1;
    }

    /* stream start:
     * 32 bits, protocol version (1), network order
     * session-id length, 32bits unsigned, network order
     * session-id, PASCAL-style string (no NUL at end)
     * <test stream>, MSS 1400 bytes ?
     *
     * FIXME: tcp_maxseg (+cli), tcp_user_timeout(?)
     * LOWAT, including TCP_NOTSENT_LOWAT:
     * https://blog.cloudflare.com/optimizing-tcp-for-high-throughput-and-low-latency/
     * https://lwn.net/Articles/560082/
     *
     */
    struct {
	uint32_t version;
	uint32_t session_id_len;
    } __attribute__((__packed__)) tcpbw_hello_msg;
    tcpbw_hello_msg.version = htonl(1);
    tcpbw_hello_msg.session_id_len = htonl((uint32_t)sessionid_len);

    /* Send and flush header */
    setsockopt(fd_measure, IPPROTO_TCP, TCP_CORK, &one, sizeof(one));
    if (message_send(fd_measure, 10, &tcpbw_hello_msg, sizeof(tcpbw_hello_msg)) < 0 ||
	message_send(fd_measure, 10, sessionid, sessionid_len) < 0) {
        print_warn("failed to send test stream header");
        return -1;
    }
    setsockopt(fd_measure, IPPROTO_TCP, TCP_CORK, &zero, sizeof(zero));

    if (mss || srtt) {
	size_t amss = 0;
	struct simet_tcp_info tcpi;
	socklen_t tcpi_len = sizeof(tcpi);
	if (likely(!getsockopt(fd_measure, IPPROTO_TCP, TCP_INFO, &tcpi, &tcpi_len)
		&& tcpi_len >= offsetof(struct simet_tcp_info, tcpi_min_rtt))) {
	    amss = tcpi.tcpi_snd_mss;
	    if (srtt) {
		if (tcpi.tcpi_min_rtt > 0) {
		    *srtt = tcpi.tcpi_min_rtt;
		} else if (tcpi.tcpi_rtt) {
		    *srtt = tcpi.tcpi_rtt;
		}
	    }
	} else if (srtt) {
	    print_warn("failed to read stream's iRTT");
	    *srtt = 0;
	}
	if (!amss && mss) {
	    int iamss = 0;
	    socklen_t iamss_len = sizeof(iamss);
	    if (!getsockopt(fd_measure, IPPROTO_TCP, TCP_MAXSEG, &iamss, &iamss_len) && iamss_len == sizeof(iamss) && iamss > 0) {
		amss = (size_t)iamss;
	    } else {
		print_warn("failed to read stream's MSS");
		amss = 0;
	    }
	}
	if (mss)
	    *mss = amss;
    }

    /* Keep Nagle disabled, no waiting for ACKs */
    setsockopt(fd_measure, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    /* Set TCP_CORK mode from now on: no partial segments */
    if (setsockopt(fd_measure, IPPROTO_TCP, TCP_CORK, &one, sizeof(one))) {
	print_warn("failed to enable TCP_CORK, might send smaller packets");
    }

    /* enable TCP pacing, when requested */
    uint32_t apace = (pacerate > UINT32_MAX) ? UINT32_MAX : (uint32_t) pacerate;
    if (apace > 0 && setsockopt(fd_measure, SOL_SOCKET, SO_MAX_PACING_RATE, &apace, sizeof(apace))) {
	print_warn("failed to enable TCP pacing (%u): %m", apace);
    }

    return fd_measure;
}

/* Command channel handling */

static char *curl_errmsg = NULL;

static int setup_curl_err_handling(CURL * const handle)
{
    assert(handle);
    if (!curl_errmsg)
	curl_errmsg = calloc(1, CURL_ERROR_SIZE);
    if (!curl_errmsg ||
	curl_easy_setopt(handle, CURLOPT_ERRORBUFFER, curl_errmsg) != CURLE_OK)
	return SEXIT_OUTOFRESOURCE;
    return 0;
}

static void free_curl_err_handling(void)
{
    free(curl_errmsg);
    curl_errmsg = NULL;
}

/* if (check_curl_error(curl_easy_*(...)) <an error happened> */
static int check_curl_error(CURLcode e)
{
    if (e == CURLE_OK)
	return 0;
    print_warn("%s: %s", curl_easy_strerror(e), (curl_errmsg) ? curl_errmsg : "(no info)");
    /* Maps from CURLcode to SEXIT_* */
    switch (e) {
	case CURLE_COULDNT_RESOLVE_PROXY:
	case CURLE_COULDNT_RESOLVE_HOST:
		return SEXIT_DNSERR;

	case CURLE_COULDNT_CONNECT:
	case CURLE_REMOTE_ACCESS_DENIED:
		return SEXIT_MP_REFUSED;

	case CURLE_OPERATION_TIMEDOUT:
		return SEXIT_MP_TIMEOUT;

#ifdef CURLE_HTTP2
	case CURLE_HTTP2:
#endif
#ifdef CURLE_HTTP2_STREAM
	case CURLE_HTTP2_STREAM:
#endif
	case CURLE_PARTIAL_FILE:
	case CURLE_HTTP_RETURNED_ERROR:
	case CURLE_TOO_MANY_REDIRECTS:
	case CURLE_GOT_NOTHING:
	case CURLE_SEND_ERROR:
	case CURLE_RECV_ERROR:
		return SEXIT_CTRLPROT_ERR;

	case CURLE_SSL_CONNECT_ERROR:
	case CURLE_PEER_FAILED_VERIFICATION:
	case CURLE_SSL_CERTPROBLEM:
	case CURLE_SSL_CIPHER:
#ifdef CURLE_LOGIN_DENIED
	case CURLE_LOGIN_DENIED:
#endif
#ifdef CURLE_SSL_INVALIDCERTSTATUS
	case CURLE_SSL_INVALIDCERTSTATUS:
#endif
#ifdef CURLE_SSL_PINNEDPUBKEYNOTMATCH
	case CURLE_SSL_PINNEDPUBKEYNOTMATCH:
#endif
#ifdef CURLE_SSL_ISSUER_ERROR
	case CURLE_SSL_ISSUER_ERROR:
#endif
		return SEXIT_AUTHERR;

	case CURLE_WRITE_ERROR: /* our write callbacks fail due to ENOMEM */
	case CURLE_OUT_OF_MEMORY:
		return SEXIT_OUTOFRESOURCE;

	case CURLE_URL_MALFORMAT: /* FIXME: do we get it from cmd line? */
		return SEXIT_BADCMDLINE;

	case CURLE_UNSUPPORTED_PROTOCOL:
	case CURLE_FAILED_INIT:
	case CURLE_NOT_BUILT_IN:
	case CURLE_HTTP_POST_ERROR:
	case CURLE_SEND_FAIL_REWIND:
	case CURLE_SSL_CACERT_BADFILE:
	case CURLE_SSL_SHUTDOWN_FAILED:
		return SEXIT_INTERNALERR;

	default:
		return SEXIT_FAILURE;
    }
}

static int prepare_command_channel(CURL * const handle,
				   const char * const baseurl, const char * const endpoint,
				   struct curl_slist * const headers,
				   const unsigned int timeout, const int family)
{
    char url[MAX_URL_SIZE];
    int rc;

    assert(endpoint && baseurl);

    if (!baseurl || !endpoint)
	return SEXIT_INTERNALERR;

    /* skip '/' at start of endpoint if there is already a trailing '/' in baseurl */
    const size_t bl = strlen(baseurl);
    size_t epstart = (endpoint[0] == '/' && bl > 2 && baseurl[bl-2] != '/' && baseurl[bl-1] == '/') ? 1: 0;

    snprintf(url, MAX_URL_SIZE, "%s%s", baseurl, &endpoint[epstart]);
    if ((rc = check_curl_error(curl_easy_setopt(handle, CURLOPT_URL, url))))
	return rc;

    curl_easy_setopt(handle, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
    curl_easy_setopt(handle, CURLOPT_FOLLOWLOCATION, 1);
    curl_easy_setopt(handle, CURLOPT_POSTREDIR, CURL_REDIR_POST_ALL);
    curl_easy_setopt(handle, CURLOPT_MAXREDIRS, 5);
    curl_easy_setopt(handle, CURLOPT_TIMEOUT, timeout);
    curl_easy_setopt(handle, CURLOPT_IPRESOLVE,
			    (family == 6)? CURL_IPRESOLVE_V6 :
			     ((family == 4)? CURL_IPRESOLVE_V4 :
			       CURL_IPRESOLVE_WHATEVER));
    if (headers &&
	(rc = check_curl_error(curl_easy_setopt(handle, CURLOPT_HTTPHEADER, headers))))
	return rc;

    /* FIXME: we have not overriden the default output handling */

    print_msg(MSG_DEBUG, "will issue API call: %s", endpoint);

    return 0;
}

static int issue_simple_command(CURL * const handle, const int emptybody)
{
    assert(handle);
    long status;
    int rc;

    if ((rc = check_curl_error(curl_easy_perform(handle))) ||
        (rc = check_curl_error(curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &status))))
	return rc;
    if (status != ((emptybody)? 204: 200)) {
	print_warn("API call returned unexpected status code: %li", status);
	return SEXIT_CTRLPROT_ERR;
    }

    /* FIXME: em caso de erro 4xx, tem um JSON {errorMessage} para mostrar, que
     * foi para o usuário via default output handling da libcurl */
    return 0;
}

static int tcpc_process_request_answer(MeasureContext * const ctx, char *json)
{
    json_object *j_obj, *j_content;

    j_obj = json_tokener_parse(json);
    if (!j_obj || !json_object_is_type(j_obj, json_type_object))
	goto err_exit;

    /* Process known fields, ignore any unknown. All fields are json strings */
    if (json_object_object_get_ex(j_obj, "measurementPeerAddr", &j_content) &&
	    json_object_is_type(j_content, json_type_string)) {
	free(ctx->host_name);
	ctx->host_name = strdup(json_object_get_string(j_content));
    }
    if (json_object_object_get_ex(j_obj, "measurementPeerPort", &j_content) &&
	    json_object_is_type(j_content, json_type_string)) {
	free(ctx->port);
	ctx->port = strdup(json_object_get_string(j_content));
    }
    if (json_object_object_get_ex(j_obj, "concurrentStreamsAllowed", &j_content) &&
	    json_object_is_type(j_content, json_type_string)) {
	int64_t ns;

	errno = 0;
	ns = json_object_get_int64(j_content);
	if (errno || ns < 1)
	    goto err_exit;
	/* range-checked already. we want min(ours, theirs) */
	if (ns < (int)ctx->numstreams)
	    ctx->numstreams = (unsigned int)ns;
    }
    if (json_object_object_get_ex(j_obj, "measureSeconds", &j_content) &&
	    json_object_is_type(j_content, json_type_string)) {
	int64_t seconds;

	errno = 0;
	seconds = json_object_get_int64(j_content);
	if (errno || seconds < 1)
	    goto err_exit;
	/* FIXME: maybe we want to abort, instead ? */
	if (seconds != (int)ctx->test_duration)
	    ctx->test_duration = (unsigned int)seconds;
    }
    if (json_object_object_get_ex(j_obj, "streamStartDelay", &j_content) &&
	    json_object_is_type(j_content, json_type_string)) {
	int64_t useconds;

	errno = 0;
	useconds = json_object_get_int64(j_content);
	if (errno || useconds < -5 || useconds > 1000000)
	    goto err_exit;
	/* FIXME: maybe we want to abort, instead ? */
	if (useconds != (int64_t)ctx->stream_start_delay)
	    ctx->stream_start_delay = (int)useconds;
    }
    if (json_object_object_get_ex(j_obj, "maxPacingRate", &j_content) &&
	    json_object_is_type(j_content, json_type_string)) {
	int64_t ubps;

	errno = 0;
	ubps = json_object_get_int64(j_content);
	if (errno || ubps < 0)
	    goto err_exit;
	if (ubps > UINT32_MAX)
	    ubps = UINT32_MAX;
	ctx->max_pacing_rate = (uint32_t) ubps;
    }
    if (json_object_object_get_ex(j_obj, "sessionId", &j_content) &&
	    json_object_is_type(j_content, json_type_string)) {
	free(ctx->sessionid);
	ctx->sessionid = strdup(json_object_get_string(j_content));
    }
    if (json_object_object_get_ex(j_obj, "samplePeriodMiliSeconds", &j_content) &&
	    json_object_is_type(j_content, json_type_string)) {
	int64_t period_ms;

	errno = 0;
	period_ms = json_object_get_int64(j_content);
	if (errno || period_ms < 1)
	    goto err_exit;
	/* enforce at least 4 samples */
	if ((unsigned long long)period_ms >= (unsigned long long)ctx->test_duration * 250U)
	    period_ms = ctx->test_duration * 250U;
	if (period_ms > UINT_MAX)
	    goto err_exit;
	ctx->sample_period_ms = (unsigned int) period_ms;
    }

    json_object_put(j_obj);

    print_msg(MSG_DEBUG, "peer=%s : %s, streams=%u, measurement_duration=%us, sampling_period=%ums, stream_start_delay=%d",
	    ctx->host_name, ctx->port, ctx->numstreams, ctx->test_duration, ctx->sample_period_ms, ctx->stream_start_delay);
    if (ctx->max_pacing_rate) {
	print_msg(MSG_NORMAL, "TCP maximum per-stream pacing rate set to %u bytes/s, may limit maximum throughput", ctx->max_pacing_rate);
    }
    return 0;

err_exit:
    if (j_obj)
	json_object_put(j_obj);

    print_warn("invalid/unknown reply from server: %s", json);
    return SEXIT_CTRLPROT_ERR;
}

/**
 * WriteMemoryCallback - libcurl callback that stores contents in zero-terminated memory
 *
 * Allocates memory as needed, stores buffer, ensures it is NUL-terminated.
 */
static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;
    struct MemoryStruct * const mem = (struct MemoryStruct *)userp;

    if (!mem || !realsize)
	return 0;
    if (realsize > 0x40000000) {
	print_warn("insanely large body received, refusing it!");
	return 0;
    }

    if (!mem->memory || mem->allocated <= mem->used + realsize) {
	/* the expression below must ensure we have at least one extra byte for NUL */
	mem->allocated += (realsize >= CURL_MAX_WRITE_SIZE) ? realsize + 16 : CURL_MAX_WRITE_SIZE;
	mem->memory = realloc(mem->memory, mem->allocated);
    }
    if (!mem->memory) {
        print_warn("out of memory (realloc returned NULL)");
        return 0;
    }

    memcpy(&(mem->memory[mem->used]), contents, realsize);
    mem->used += realsize;
    assert(mem->used < mem->allocated);
    mem->memory[mem->used] = 0;

    return realsize;
}


/* main loop */

static void postprocess_tcpi(TcpInfoSample *samples, size_t total_sample_count, struct timespec *zerotime)
{
    if (samples) {
	for (TcpInfoSample *p = samples; total_sample_count > 0; p++, total_sample_count--) {
	    p->timestamp = timespec_sub(&(p->timestamp), zerotime);
	}
    }
}

static void postprocess_skmem(SkmemSample *samples, size_t total_sample_count, struct timespec *zerotime)
{
    if (samples) {
	for (SkmemSample *p = samples; total_sample_count > 0; p++, total_sample_count--) {
	    p->timestamp = timespec_sub(&(p->timestamp), zerotime);
	}
    }
}

static int sendUploadPackets(const MeasureContext * const ctx, ReportContext * const rctx)
{
    struct timespec ts_start, ts_cur, ts_stop, ts_sample, ts_oversample, ts_streamstart, ts_nextstream;
    TcpInfoSample *upload_tcpi = NULL;
    SkmemSample *upload_skmem = NULL;
    fd_set wset, masterset;
    unsigned int i;
    int rc = -1;

    assert(sockBuffer);
    assert(sockBufferSz && sockBufferSz > ctx->outgoing_mss);

    memcpy(&masterset, &sockListFDs, sizeof(fd_set));
    memset(&sndposList, 0, sizeof(sndposList));

    const size_t omss = ctx->outgoing_mss;

    if (ctx->test_duration > 1000 || ctx->sample_period_ms <= 0)
	return -EINVAL;
    unsigned int max_samples = (ctx->test_duration * 1000U) / ctx->sample_period_ms;

    /* clamp, just in case */
    if (max_samples > TCPBW_MAX_SAMPLES)
	max_samples = TCPBW_MAX_SAMPLES;

    const size_t max_tcpi_samples = ctx->numstreams * max_samples;
    if (ctx->streamdata_file) {
	upload_tcpi = calloc(max_tcpi_samples, sizeof(TcpInfoSample));
	if (!upload_tcpi)
	    goto err_exit;
    }
#if HAVE_DECL_SO_MEMINFO != 0
    const size_t max_skmem_samples = (ctx->streamdata_file) ?
	ctx->numstreams * max_samples * ctx->stats_oversampling : 0;
#else
    const size_t max_skmem_samples = 0;
#endif
    if (max_skmem_samples) {
	upload_skmem = calloc(max_skmem_samples, sizeof(SkmemSample));
	if (!upload_skmem)
	    goto err_exit;
    }

    unsigned int next_stream_to_start = ctx->numstreams;
    const long streamdelay_us = (ctx->stream_start_delay < 0) ?
		    (long)ctx->rtt / (-ctx->stream_start_delay * (long)ctx->numstreams) :
		    ctx->stream_start_delay;
    bool delay_streams = (streamdelay_us > 0 && ctx->numstreams > 0);
    if (delay_streams && ctx->numstreams > 1) {
	print_msg(MSG_DEBUG, "will delay stream start using steps of %ldus", streamdelay_us);

	/* note: we skip the first stream below, so it starts immediately */
	next_stream_to_start = 1;
	for (i = next_stream_to_start; i < ctx->numstreams; i++) {
	    if (sockList[i] >= 0) {
		FD_CLR(sockList[i], &masterset);
	    }
	}
    }
    ts_streamstart = microseconds_to_timespec(streamdelay_us);

    const struct timespec ts_samplingperiod = {
	.tv_sec = ctx->sample_period_ms / 1000,
	.tv_nsec = (ctx->sample_period_ms % 1000) * 1000000,
    };
    const unsigned int oversample_period_ms = ctx->sample_period_ms / ((ctx->stats_oversampling)? ctx->stats_oversampling : 1);
    const struct timespec ts_oversamplingperiod = {
	.tv_sec = oversample_period_ms / 1000,
	.tv_nsec = (oversample_period_ms % 1000) * 1000000,
    };

    /* FIXME: switch to blocking IO, using one thread per socket, so that it will sleep without blocking the others?
     *        right now, we return from select to write a bit to large socket buffers that are still far from empty...
     *        this is Not Ok.
     *
     *        Consider vmsplice and ring buffers if absolutely required.
     */

    TcpInfoSample *current_tcpi = upload_tcpi;
    SkmemSample *current_skmem = upload_skmem;
    unsigned long tcpi_sample_cnt = 0;
    unsigned long skmem_sample_cnt = 0;

    int active_streams = (int)ctx->numstreams; /* safe, numstreams <<< INT_MAX */

    if (clock_gettime(CLOCK_MONOTONIC, &ts_cur)) {
	return -1;
    }
    ts_start = ts_cur;
    ts_stop = ts_cur;
    ts_stop.tv_sec += ctx->test_duration;
    ts_sample = timespec_add(&ts_cur, &ts_samplingperiod);
    ts_oversample = timespec_add(&ts_cur, &ts_oversamplingperiod);
    ts_nextstream = timespec_add(&ts_cur, &ts_streamstart);

    /*
     * we fill TCP buffers for the whole test time window, and they will
     * take some time to empty even after we stop queing data to be
     * transmitted, here.
     *
     * Thus we actually ensure enough dataflow for the last sample.  On
     * a future version of the protocol that does a shutdown(), it may
     * be necessary to revisit this
     */
    while (timespec_lt(&ts_cur, &ts_stop) && active_streams > 0) {
	struct timespec ts_timeo = timespec_sub_saturated(
		(delay_streams && timespec_lt(&ts_nextstream, &ts_oversample)) ? &ts_nextstream : &ts_oversample,
		&ts_cur, 0);
        memcpy(&wset, &masterset, sizeof(fd_set));
        int rc_select = pselect(sockListLastFD + 1, NULL, &wset, NULL, &ts_timeo, NULL);
	if (rc_select >= 0) {
	    if (clock_gettime(CLOCK_MONOTONIC, &ts_cur))
		goto err_exit;

	    for (i = 0; i < ctx->numstreams; i++) {
		/* start the stream if necessary */
		if (i >= next_stream_to_start && timespec_le(&ts_nextstream, &ts_cur)) {
		    if (sockList[i] >= 0) {
			FD_SET(sockList[i], &masterset);
			FD_SET(sockList[i], &wset); /* O_NONBLOCK, so it is safe */
		    }
		    next_stream_to_start++;
		    ts_nextstream = timespec_add(&ts_nextstream, &ts_streamstart);

		    if (next_stream_to_start >= ctx->numstreams)
			delay_streams = 0; /* all streams are already running */
		}

		if (sockList[i] < 0)
		    continue;

#if HAVE_DECL_SO_MEMINFO != 0
		if (current_skmem && timespec_le(&ts_oversample, &ts_cur) && skmem_sample_cnt < max_skmem_samples) {
		    socklen_t meminfo_len = sizeof(current_skmem->sk_meminfo);
		    if (likely(!getsockopt(sockList[i], SOL_SOCKET, SO_MEMINFO, &(current_skmem->sk_meminfo), &meminfo_len)
				&& meminfo_len == sizeof(current_skmem->sk_meminfo))) {
			current_skmem->timestamp = ts_cur;
			current_skmem->stream_id = i;
			current_skmem++;
			skmem_sample_cnt++;
		    } else {
			/* stop sampling */
			current_skmem = NULL;
			skmem_sample_cnt = 0;
		    }
		}
#endif

		if (FD_ISSET(sockList[i], &wset)) {
		    const uint8_t *txbuf = (uint8_t *)sockBuffer ;//+ sndposList[i];
		    const size_t iosz = sockBufferSz ;//- sndposList[i];

		    ssize_t res = send(sockList[i], txbuf, iosz, MSG_DONTWAIT | MSG_NOSIGNAL);
		    if (res >= 0) {
			sndposList[i] += (size_t) res;
			if (sndposList[i] >= sockBufferSz - 2*omss)
			    sndposList[i] = 0;
		    } else if (errno == EPIPE || errno == ECONNRESET) {
			FD_CLR(sockList[i], &masterset);
			active_streams--;
		    }
		}
	    }
	} else if (rc_select < 0 && errno != EINTR) {
	    rc = -errno;
	    goto err_exit;
        }

	/* do this before updating ts_cur, or we risk skipping samples with oversampling=1 */
	while (timespec_le(&ts_oversample, &ts_cur)) {
	    /* if this runs more than once, we were too slow and lost one oversampling window */
	    ts_oversample = timespec_add(&ts_oversample, &ts_oversamplingperiod);
	}

	if (clock_gettime(CLOCK_MONOTONIC, &ts_cur))
	    goto err_exit;

	if (current_tcpi && timespec_le(&ts_sample, &ts_cur) && tcpi_sample_cnt < max_tcpi_samples) {
	    for (i = 0; i < ctx->numstreams; i++) {
		if (sockList[i] >= 0) {
		    socklen_t tcpi_len = sizeof(current_tcpi->tcpi);
		    if (likely(!getsockopt(sockList[i], IPPROTO_TCP, TCP_INFO, &(current_tcpi->tcpi), &tcpi_len)
			    && tcpi_len >= offsetof(struct simet_tcp_info, tcpi_bytes_retrans))) {
		        current_tcpi->timestamp = ts_cur;
			current_tcpi->stream_id = i;
			current_tcpi++;
			tcpi_sample_cnt++;
		    } else {
			/* stop sampling */
			current_tcpi = NULL;
			tcpi_sample_cnt = 0;
		    }
		}
	    }

	    /* the above can be very, very expensive. */
	    if (clock_gettime(CLOCK_MONOTONIC, &ts_cur))
		goto err_exit;
	}

	while (timespec_le(&ts_sample, &ts_cur)) {
	    /* if this runs more than once, we were too slow and lost one sampling window */
	    ts_sample = timespec_add(&ts_sample, &ts_samplingperiod);
	}
    }

    /* Too early an exit fails the measurement... */
    if (active_streams <= 0 && timespec_sub(&ts_stop, &ts_cur).tv_sec > TCPBW_EARLY_EXIT_S) {
	print_err("measurement connections were closed by the peer");
	rc = -ECONNRESET;
	goto err_exit;
    }

    /* Report some TCP statistics to aid debugging */
    uint64_t bytes_retrans = 0;
    uint64_t bytes_total = 0;
    uint64_t bytes_acked = 0;
    bool sndbuf_limited = false;
    for (i = 0; i < ctx->numstreams; i++) {
	if (sockList[i] >= 0) {
	    struct simet_tcp_info tcpi = { 0 };
	    socklen_t tcpi_len = sizeof(tcpi);
	    if (!getsockopt(sockList[i], IPPROTO_TCP, TCP_INFO, &tcpi, &tcpi_len)
		    && tcpi_len > offsetof(struct simet_tcp_info, tcpi_bytes_retrans) + sizeof(tcpi.tcpi_bytes_retrans)) {
		bytes_retrans += tcpi.tcpi_bytes_retrans;
		bytes_total   += tcpi.tcpi_bytes_sent;
		bytes_acked   += tcpi.tcpi_bytes_acked;
		sndbuf_limited |= (tcpi.tcpi_sndbuf_limited > 0);
	    }
	}
    }
    if (bytes_total > 0) {
	print_msg(MSG_NORMAL, "TCP: %zu bytes transmitted (including retransmissions, if any)", bytes_total);
	print_msg(MSG_NORMAL, "TCP: %zu bytes acknowleged as received by the peer (%.3f%% of transmitted)", bytes_acked,
		100 * (double)bytes_acked / (double)bytes_total);
	if (bytes_retrans > 0) {
	   print_msg(MSG_NORMAL, "TCP: %zu bytes (%.3f%%) were TCP retransmissons, and not accounted for in throughput rate",
		   bytes_retrans, 100 * (double)bytes_retrans / (double)bytes_total);
	}
    }

    /* possible transmission bottleneck warnings */
    if (sndbuf_limited)
	print_warn("TCP: sending rate was limited by lack of kernel buffer memory");

    /* discard partial samples if necessary */
    if (!current_skmem && upload_skmem) {
	free(upload_skmem);
	upload_skmem = NULL;
	skmem_sample_cnt = 0;
    }
    if (!current_tcpi && upload_tcpi) {
	free(upload_tcpi);
	upload_tcpi= NULL;
	tcpi_sample_cnt = 0;
    }

    postprocess_tcpi(upload_tcpi, tcpi_sample_cnt, &ts_start);
    postprocess_skmem(upload_skmem, skmem_sample_cnt, &ts_start);
    rctx->upload_tcpi = upload_tcpi;
    rctx->upload_tcpi_count = tcpi_sample_cnt;
    rctx->upload_skmem = upload_skmem;
    rctx->upload_skmem_count = skmem_sample_cnt;
    rctx->upload_streams_count = ctx->numstreams;
    return 0;

err_exit:
    free(upload_tcpi);
    free(upload_skmem);
    return rc;
}

static int receiveDownloadPackets(const MeasureContext * const ctx, ReportContext * const rctx)
{
    struct timespec ts_start, ts_cur, ts_stop, ts_last, ts_sample, ts_oversample;
    TcpInfoSample *download_tcpi = NULL;
    SkmemSample *download_skmem = NULL;
    ssize_t bytes_recv = 0;
    fd_set rset, masterset;
    uint64_t total = 0;
    unsigned int rCounter = 0;
    int rc = -1;

    assert(ctx && rctx && sockBufferSz > 0);
    const size_t io_size = sockBufferSz;

    if (ctx->test_duration > 1000 || ctx->sample_period_ms <= 0)
	return -EINVAL;
    unsigned int max_samples = (ctx->test_duration * 1000U) / ctx->sample_period_ms;

    /* clamp, just in case */
    if (max_samples > TCPBW_MAX_SAMPLES)
	max_samples = TCPBW_MAX_SAMPLES;

    const size_t max_tcpi_samples = ctx->numstreams * max_samples;
    if (ctx->streamdata_file) {
	download_tcpi = calloc(max_tcpi_samples, sizeof(TcpInfoSample));
	if (!download_tcpi)
	    goto err_exit;
    }
#if HAVE_DECL_SO_MEMINFO != 0
    const size_t max_skmem_samples = (ctx->streamdata_file) ?
	ctx->numstreams * max_samples * ctx->stats_oversampling : 0;
#else
    const size_t max_skmem_samples = 0;
#endif
    if (max_skmem_samples) {
	download_skmem = calloc(max_skmem_samples, sizeof(SkmemSample));
	if (!download_skmem)
	    goto err_exit;
    }

    TcpInfoSample *current_tcpi = download_tcpi;
    SkmemSample *current_skmem = download_skmem;
    unsigned long tcpi_sample_cnt = 0;
    unsigned long skmem_sample_cnt = 0;

    int active_streams = (int)ctx->numstreams; /* safe, numstreams <<< INT_MAX */

    const struct timespec ts_samplingperiod = {
	.tv_sec = ctx->sample_period_ms / 1000,
	.tv_nsec = (ctx->sample_period_ms % 1000) * 1000000,
    };
    const unsigned int oversample_period_ms = ctx->sample_period_ms / ((ctx->stats_oversampling)? ctx->stats_oversampling : 1);
    const struct timespec ts_oversamplingperiod = {
	.tv_sec = oversample_period_ms / 1000,
	.tv_nsec = (oversample_period_ms % 1000) * 1000000,
    };

    rc = -ENOMEM;

    DownResult *downloadResults = calloc(max_samples, sizeof(DownResult));
    if (!downloadResults)
	goto err_exit;

    memcpy(&masterset, &sockListFDs, sizeof(fd_set));

    rc = -EINVAL;

    if (clock_gettime(CLOCK_MONOTONIC, &ts_cur))
	goto err_exit;
    ts_start = ts_cur;
    ts_stop = ts_cur;
    ts_stop.tv_sec += ctx->test_duration;
    ts_sample = timespec_add(&ts_cur, &ts_samplingperiod);
    ts_last = ts_cur;
    ts_oversample = timespec_add(&ts_cur, &ts_oversamplingperiod);

    uint64_t payload_total = 0;
    while (rCounter < max_samples && active_streams > 0) {
	struct timespec ts_timeo = timespec_sub_saturated(&ts_oversample, &ts_cur, 0);

	memcpy(&rset, &masterset, sizeof(fd_set));
	int rc_select = pselect(sockListLastFD + 1, &rset, NULL, NULL, &ts_timeo, NULL);
	if (rc_select >= 0) {
	    if (clock_gettime(CLOCK_MONOTONIC, &ts_cur))
		goto err_exit;

	    for (unsigned int i = 0; i < ctx->numstreams; i++) {
		if (sockList[i] < 0)
		    continue;

#if HAVE_DECL_SO_MEMINFO != 0
		if (current_skmem && timespec_le(&ts_oversample, &ts_cur) && skmem_sample_cnt < max_skmem_samples) {
		    socklen_t meminfo_len = sizeof(current_skmem->sk_meminfo);
		    if (likely(!getsockopt(sockList[i], SOL_SOCKET, SO_MEMINFO, &(current_skmem->sk_meminfo), &meminfo_len)
				&& meminfo_len == sizeof(current_skmem->sk_meminfo))) {
			current_skmem->timestamp = ts_cur;
			current_skmem->stream_id = i;
			current_skmem++;
			skmem_sample_cnt++;
		    } else {
			/* stop sampling */
			current_skmem = NULL;
			skmem_sample_cnt = 0;
		    }
		}
#endif

		if (FD_ISSET(sockList[i], &rset)) {
		    /* drain stream buffer before switching to next,
		     * try to avoid the recv() that would result in EAGAIN */
		    do {
			bytes_recv = recv(sockList[i], sockBuffer, io_size, MSG_DONTWAIT | MSG_TRUNC);
			if (bytes_recv > 0)
			    total += (size_t)bytes_recv; /* bytes_rcv > 0 */
		    } while (bytes_recv == (ssize_t) io_size);
		    if (!bytes_recv) {
			/* EOF */
			FD_CLR(sockList[i], &masterset);
			active_streams--;
		    }
		}
	    }
	} else if (rc_select < 0 && errno != EINTR) {
	    rc = -errno;
	    goto err_exit;
	}

	/* do this before updating ts_cur, or we risk skipping samples with oversampling=1 */
	while (timespec_le(&ts_oversample, &ts_cur)) {
	    /* if this runs more than once, we were too slow and lost one oversampling window */
	    ts_oversample = timespec_add(&ts_oversample, &ts_oversamplingperiod);
	}

	if (clock_gettime(CLOCK_MONOTONIC, &ts_cur))
	    goto err_exit;

	if (timespec_le(&ts_sample, &ts_cur) && rCounter < max_samples) {
	    downloadResults[rCounter].nstreams = ctx->numstreams;
	    downloadResults[rCounter].bytes = total;
	    downloadResults[rCounter].interval_ns = (uint64_t)timespec_sub_nanoseconds(&ts_cur, &ts_last); /* ts_last <= ts_cur */

	    ts_last = ts_cur;

	    rCounter++;
	    payload_total += total;
	    total = 0;

	    if (current_tcpi && tcpi_sample_cnt < max_tcpi_samples) {
		for (unsigned int i = 0; i < ctx->numstreams; i++) {
		    if (sockList[i] >= 0) {
			socklen_t tcpi_len = sizeof(current_tcpi->tcpi);
			if (likely(!getsockopt(sockList[i], IPPROTO_TCP, TCP_INFO, &(current_tcpi->tcpi), &tcpi_len)
				&& tcpi_len >= offsetof(struct simet_tcp_info, tcpi_bytes_retrans))) {
			    current_tcpi->timestamp = ts_cur;
			    current_tcpi->stream_id = i;
			    current_tcpi++;
			    tcpi_sample_cnt++;
			} else {
			    /* stop sampling */
			    current_tcpi = NULL;
			    tcpi_sample_cnt = 0;
			}
		    }
		}
	    }
	}

	/* the above can be very, very expensive. */
	if (clock_gettime(CLOCK_MONOTONIC, &ts_cur))
	    goto err_exit;

	if (timespec_lt(&ts_stop, &ts_cur)) /* lt, not le ! */
	    break;

	while (timespec_le(&ts_sample, &ts_cur)) {
	    /* if this runs more than once, we were too slow and lost one sampling window */
	    ts_sample = timespec_add(&ts_sample, &ts_samplingperiod);
	}
    }

    /* Too early an exit fails the measurement... */
    if (active_streams <= 0 && timespec_sub(&ts_stop, &ts_cur).tv_sec > TCPBW_EARLY_EXIT_S) {
	print_err("measurement connections were closed by the peer");
	rc = -ECONNRESET;
	goto err_exit;
    }

    /* Report some TCP statistics to aid debugging */
    uint64_t bytes_total  = 0;
    for (unsigned int i = 0; i < ctx->numstreams; i++) {
	if (sockList[i] >= 0) {
	    struct simet_tcp_info tcpi = { 0 };
	    socklen_t tcpi_len = sizeof(tcpi);
	    if (!getsockopt(sockList[i], IPPROTO_TCP, TCP_INFO, &tcpi, &tcpi_len)
		    && tcpi_len > offsetof(struct simet_tcp_info, tcpi_bytes_retrans) + sizeof(tcpi.tcpi_bytes_retrans)) {
		bytes_total   += tcpi.tcpi_bytes_received;
	    }
	}
    }
    if (bytes_total > 0) {
	print_msg(MSG_NORMAL, "TCP: %zu bytes received (%.2f%% delivered to application)", bytes_total,
		100 * (double)payload_total / (double)bytes_total);
    }

    /* discard partial samples if necessary */
    if (!current_skmem && download_skmem) {
	free(download_skmem);
	download_skmem = NULL;
	skmem_sample_cnt = 0;
    }
    if (!current_tcpi && download_tcpi) {
	free(download_tcpi);
	download_tcpi= NULL;
	tcpi_sample_cnt = 0;
    }

    postprocess_tcpi(download_tcpi, tcpi_sample_cnt, &ts_start);
    postprocess_skmem(download_skmem, skmem_sample_cnt, &ts_start);
    rctx->download_tcpi = download_tcpi;
    rctx->download_tcpi_count = tcpi_sample_cnt;
    rctx->download_skmem = download_skmem;
    rctx->download_skmem_count = skmem_sample_cnt;
    rctx->download_streams_count = ctx->numstreams;

    rctx->summary_sample_count = rCounter;
    rctx->summary_samples = downloadResults;

    return 0;

err_exit:
    free(download_tcpi);
    free(download_skmem);
    return rc;
}

/* do not call twice */
int tcp_client_run(MeasureContext ctx)
{
    CURL *curl;
    int rc;

    const char *upload_results_json = NULL;

    ReportContext *report_context;

    char strbuf[MAX_URL_SIZE];
    struct MemoryStruct chunk = { 0 };

    struct curl_slist *slist = NULL;

    assert(ctx.control_url);

    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();
    if (!curl || setup_curl_err_handling(curl)) {
	print_err("failed to initialize libcurl");
	return SEXIT_OUTOFRESOURCE;
    }

    report_context = tcpbw_report_init();
    if (!report_context) {
	print_err("failed to initialize report structures");
	return SEXIT_OUTOFRESOURCE;
    }

    /* Authorization header, must go on every API call */
    if (ctx.token) {
        snprintf(strbuf, sizeof(strbuf), "Authorization: Bearer %s", ctx.token);
        slist = curl_slist_append(slist, strbuf);
    }

    print_msg(MSG_IMPORTANT, "measurent session setup...");
    if ((rc = prepare_command_channel(curl, ctx.control_url, "/session/request", slist, ctx.timeout_test, ctx.family)))
	goto err_exit;

    curl_easy_setopt(curl, CURLOPT_POST, 1);
    snprintf(strbuf, sizeof(strbuf), "version=1&ipvn=%i&concurrentStreams=%u&measureSeconds=%u&samplePeriodMiliSeconds=%u&streamStartDelay=%d&maxPacingRate=%u&agentId=%s",
	     ctx.family, ctx.numstreams, ctx.test_duration, ctx.sample_period_ms, ctx.stream_start_delay, ctx.max_pacing_rate, ctx.agent_id ? ctx.agent_id : "");
    curl_easy_setopt(curl, CURLOPT_COPYPOSTFIELDS, strbuf);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    if ((rc = issue_simple_command(curl, 0)))
	goto err_exit;
    if ((rc = tcpc_process_request_answer(&ctx, chunk.memory)))
	goto err_exit;

    unsigned int streamcount = 0;
    size_t mss = 0;
    int warnmss = 0;
    if (ctx.numstreams >= MAX_CONCURRENT_SESSIONS)
	ctx.numstreams = MAX_CONCURRENT_SESSIONS;
    print_msg(MSG_NORMAL, "opening %u measurement streams", ctx.numstreams);
    FD_ZERO(&sockListFDs);
    for (unsigned int i = 0; i < ctx.numstreams; i++) {
	size_t smss = 0;
	unsigned int srtt = 0;
	int m_socket = create_measure_socket(ctx.host_name, ctx.port,
					     ctx.sessionid ? ctx.sessionid : ctx.token,
					     &smss, &srtt, ctx.max_pacing_rate);
	if (m_socket != -1) {
	    streamcount++;
	    FD_SET(m_socket, &sockListFDs);
	    if (m_socket > sockListLastFD)
		sockListLastFD = m_socket;
	} else {
	    /* stop measurement if we did not get all the streams we need */
	    break;
	}
	sockList[i] = m_socket;
	if (smss > 0) {
	    warnmss = warnmss | (mss > 0 && mss != smss);
	    if (smss > mss)
		mss = smss;
	}
	if (srtt < ctx.rtt || !ctx.rtt) {
	    ctx.rtt = srtt;
	}
    }
    if (!streamcount) {
	print_warn("could not open any test streams, aborting test");
	return SEXIT_MP_TIMEOUT;
    } else if (ctx.numstreams != streamcount) {
	print_warn("could not open enough test streams, aborting test");
	return SEXIT_MP_TIMEOUT;
    }

    if (ctx.rtt) {
	print_msg(MSG_DEBUG, "optimizing for a RTT of %u microseconds", ctx.rtt);
    } else {
	print_warn("could not retrieve the RTT from tcp streams");
    }

    if (warnmss)
	print_warn("streams have different outgoing MSS");
    if (mss > 65536) {
	mss = 65536;
    } else if (!mss) {
	mss = 1400; /* we need *something* to work with... */
    }
    print_msg(MSG_DEBUG, "optimizing for streams with an outgoing MSS of %zu bytes", mss);
    ctx.outgoing_mss = mss;

    print_msg(MSG_DEBUG, "creating socket information report");
    for (unsigned int i = 0; i < ctx.numstreams; i++) {
	if (sockList[i] != -1 && report_socket_metrics(report_context, sockList[i], IPPROTO_TCP))
	    print_warn("failed to report socket information for stream %u", i);
    }

    /* Create a single buffer with a good size */
    sockBufferSz = new_tcp_buffer(sockList[0], &sockBuffer);
    if (sockBufferSz < 10*mss) { /* 5*mss, but Linux returns twice that */
	print_err("could not allocate a large enough socket buffer");
	return SEXIT_OUTOFRESOURCE;
    }

    print_msg(MSG_DEBUG, "sending request /session/start-upload");
    if ((rc = prepare_command_channel(curl, ctx.control_url, "/session/start-upload", slist, ctx.timeout_test, ctx.family)))
	goto err_exit;
    if ((rc = issue_simple_command(curl, 1)))
	goto err_exit;

    print_msg(MSG_IMPORTANT, "starting upload measurement (send)");
    if (sendUploadPackets(&ctx, report_context) < 0) {
	print_err("failed while sending packets");
	rc = SEXIT_FAILURE;
	goto err_exit;
    }

    if ((rc = prepare_command_channel(curl, ctx.control_url, "/session/finish-upload", slist, ctx.timeout_test, ctx.family)))
	goto err_exit;
    if ((rc = issue_simple_command(curl, 1)))
	goto err_exit;

    /* shutdown upload direction */
    for (unsigned int i = 0; i < ctx.numstreams; i++) {
	if (sockList[i] != -1 && shutdown(sockList[i], SHUT_WR) == -1) {
	    if (errno == ENOTCONN) {
		close(sockList[i]);
		FD_CLR(sockList[i], &sockListFDs);
		sockList[i] = -1;
		streamcount--;
	    } else if (errno != 0 && errno != EINTR) {
		rc = SEXIT_FAILURE;
		goto err_exit;
	    }
	}
    }
    if (!streamcount) {
	rc = SEXIT_MP_TIMEOUT; /* FIXME: it aborted on us, really... */
	goto err_exit;
    }

    if ((rc = prepare_command_channel(curl, ctx.control_url, "/session/start-download", slist, ctx.timeout_test, ctx.family)))
	goto err_exit;
    if ((rc = issue_simple_command(curl, 1)))
	goto err_exit;

    print_msg(MSG_IMPORTANT, "starting download measurement (receive)");
    if (receiveDownloadPackets(&ctx, report_context) < 0) {
	print_err("failed while receiving packets");
	rc = SEXIT_FAILURE;
	goto err_exit;
    }

    if ((rc = prepare_command_channel(curl, ctx.control_url, "/session/finish-download", slist, ctx.timeout_test, ctx.family)))
	goto err_exit;
    if ((rc = issue_simple_command(curl, 1)))
	goto err_exit;

    /* shutdown and close sockets */
    for (unsigned int i = 0; i < ctx.numstreams; i++) {
	if (sockList[i] != -1) {
	    shutdown(sockList[i], SHUT_RDWR);
	    close(sockList[i]);
	    sockList[i] = -1;
	    streamcount--;
	}
    }
    if (streamcount) {
	print_msg(MSG_DEBUG, "internal error: stream leak!");
    }
    FD_ZERO(&sockListFDs);
    sockListLastFD = -1;

    print_msg(MSG_NORMAL, "requesting upload measurement results from measurement peer");
    if ((rc = prepare_command_channel(curl, ctx.control_url, "/session/get-upload-samples", slist, ctx.timeout_test, ctx.family)))
	goto err_exit;
    if (chunk.memory && chunk.allocated)
	memset(chunk.memory, 0, chunk.allocated);
    chunk.used = 0;
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    if ((rc = issue_simple_command(curl, 0))) {
	/* FIXME: goto err_exit; ? */
	print_warn("failed to get upload measurements from server");
	/* FIXME: need an empty json of some sort on j_obj_upload? */
    } else {
	upload_results_json = chunk.memory;
    }

    print_msg(MSG_IMPORTANT, "tcp bandwidth measurements finished");
    rc = SEXIT_SUCCESS;

err_exit:
    /* we want the lmap report table (even if it is empty) if we can output it */
    if (tcpbw_report(report_context, upload_results_json, &ctx))
	rc = rc ? rc : SEXIT_FAILURE;

    free(chunk.memory);
    free(sockBuffer);

    if (curl)
	curl_easy_cleanup(curl);
    if (slist)
	curl_slist_free_all(slist);

    curl_global_cleanup();
    free_curl_err_handling();
    tcpbw_report_done(report_context);

    return rc;
}

