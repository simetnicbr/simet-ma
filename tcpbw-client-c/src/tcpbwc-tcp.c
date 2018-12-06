/*
 * Copyright (c) 2018 NIC.br <medicoes@simet.nic.br>
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

#include <assert.h>
#include <errno.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include "json-c/json.h"
#include "curl/curl.h"
#include "libubox/usock.h"

#define TIMEVAL_MICROSECONDS(tv) ((tv.tv_sec * 1e6L) + tv.tv_usec)

#define MAX_URL_SIZE 1024
#define TCP_MAX_BUFSIZE 1048576U
#define TCP_MIN_BUFSIZE 1480U

static fd_set sockListFDs;
int sockList[MAX_CONCURRENT_SESSIONS];
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
    size_t buflen = 128*1024; /* default */
    int optval = 0;
    socklen_t optvalsz = sizeof(optval);

    assert(p);

    if (!getsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &optval, &optvalsz)) {
	if (optval > 0)
	    buflen = optval;
    }

    if (buflen < TCP_MIN_BUFSIZE) {
	buflen = TCP_MIN_BUFSIZE;
    } else if (buflen > TCP_MAX_BUFSIZE) {
	buflen = TCP_MAX_BUFSIZE;
    }

    print_msg(MSG_DEBUG, "will use a TCP buffer of length %zu", buflen);

    void *buf = calloc(1, buflen);
    *p = buf;
    return buf ? buflen : 0;
}

static int message_send(int socket, int timeout, void *message, size_t len)
{
    int send_size = 0, send_total = 0;
    int fd_ready = 0;
    fd_set wset, wset_master;
    struct timeval tv_timeo;

    FD_ZERO(&wset_master);
    FD_SET((unsigned long)socket, &wset_master);

    tv_timeo.tv_sec = timeout;
    tv_timeo.tv_usec = 0;

    do {
        memcpy(&wset, &wset_master, sizeof(wset_master));

        fd_ready = select(socket + 1, NULL, &wset, NULL, &tv_timeo);

        if (fd_ready <= 0) {
            print_warn("select: %i", fd_ready);
	} else {
            if (FD_ISSET((unsigned long)socket, &wset)) {
                send_size = send(socket, message + send_total, len - (unsigned long)send_total, 0);
                send_total += send_size;

                if ((unsigned long)send_total == len)
                    return send_size;

                print_warn("send_total different then expected!");
            } else {
                print_warn("socket not in wset!");
            }
        }
    } while ((tv_timeo.tv_sec > 0) && (tv_timeo.tv_usec > 0));

    return -1;
}

static int create_measure_socket(char *host, char *port, char *sessionid)
{
    const int one = 1;
    int fd_measure;

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
	 * 32 bits, protocol version, network order (número 1)
	 * tamanho do session-id, 32bits unsigned
	 * sessionId, PASCAL-style
	 * <stream de teste>, MSS 1400 bytes - olhar simetbox
	 *
	 * FIXME: tcp_nodelay, tcp_maxseg (+cli), setar tamanho do socket buffer, tcp_user_timeout(?)
	 *
	 */

    uint32_t u32buf = htonl(1);
    if (message_send(fd_measure, 10, &u32buf, sizeof(uint32_t)) <= 0) {
        print_warn("message_send problem");
        return -1;
    }
    uint32_t ss = htonl(strlen(sessionid));
    int ret_socket = message_send(fd_measure, 10, &ss, sizeof(uint32_t));
    if (ret_socket <= 0) {
        print_warn("message_send problem");
        return -1;
    }
    ret_socket = message_send(fd_measure, 10, sessionid, strlen(sessionid));
    if (ret_socket <= 0) {
        print_warn("message_send problem");
        return -1;
    }
    if (setsockopt(fd_measure, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one))) {
	print_warn("failed to set TCP_NODELAY");
	return -1;
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

    snprintf(url, MAX_URL_SIZE, "%s%s", baseurl, endpoint);
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
	ctx->sample_period_ms = period_ms;
    }

    json_object_put(j_obj);

    print_msg(MSG_DEBUG, "peer=%s : %s, streams=%u, measurement_duration=%us, sampling_period=%ums",
	    ctx->host_name, ctx->port, ctx->numstreams, ctx->test_duration, ctx->sample_period_ms);
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

static int sendUploadPackets(const MeasureContext ctx)
{
    int upTimeout = ctx.test_duration;
    struct timeval tv_cur, tv_stop_test, tv_select;
    uint64_t counter = 0;
    fd_set wset, masterset;
    unsigned int i;

    assert(sockBuffer);
    assert(sockBufferSz);

    memcpy(&masterset, &sockListFDs, sizeof(fd_set));

    /* FIXME: fill buffer with uncompressible pseudo-random, it is all-zeros right now */

    /* FIXME: if possible, switch to CLOCK_MONOTONIC, which is also in the VDSO */

    /* FIXME: switch to blocking IO, using one thread per socket, so that it will sleep without blocking the others?
     *        right now, we return from select to write a bit to large socket buffers that are still far from empty...
     *        this is Not Ok.
     *
     *        Consider vmsplice and ring buffers if absolutely required.
     */
    gettimeofday(&tv_cur, NULL);
    tv_stop_test.tv_usec = tv_cur.tv_usec;
    tv_stop_test.tv_sec = tv_cur.tv_sec + (long)upTimeout;

    while (timercmp(&tv_cur, &tv_stop_test, <)) {
        tv_select.tv_sec = tv_stop_test.tv_sec - tv_cur.tv_sec;
        tv_select.tv_usec = 0;

        memcpy(&wset, &masterset, sizeof(fd_set));
        if (select(sockListLastFD + 1, NULL, &wset, NULL, &tv_select) > 0) {
	    for (i = 0; i < ctx.numstreams; i++) {
		if (FD_ISSET(sockList[i], &wset)) {
		    if (send(sockList[i], sockBuffer, sockBufferSz, MSG_DONTWAIT | MSG_NOSIGNAL) == -1 &&
			(errno == EPIPE || errno == ECONNRESET)) {
			    FD_CLR(sockList[i], &masterset);
		    }
		    counter++;
		}
	    }
        }
        gettimeofday(&tv_cur, NULL);
    };

    return 0;
}

static int receiveDownloadPackets(const MeasureContext ctx, DownResult ** const res, unsigned int *numres)
{
    size_t bytes_recv = 0;
    struct timeval tv_cur, tv_start, tv_stop_test, tv_select;
    fd_set rset, masterset;
    uint64_t total = 0;
    unsigned int rCounter = 0;
    long elapsed;
    long interval = ctx.sample_period_ms * 1000UL;
    unsigned int maxResults = ((unsigned long)ctx.test_duration * 1000U) / ctx.sample_period_ms + 1;

    assert(res && numres);

    DownResult *downloadResults = calloc(maxResults, sizeof(DownResult));
    *res = downloadResults;
    *numres = 0;
    if (!downloadResults)
	return -ENOMEM;

    memcpy(&masterset, &sockListFDs, sizeof(fd_set));

    gettimeofday(&tv_cur, NULL);
    tv_start.tv_usec = tv_cur.tv_usec;
    tv_start.tv_sec = tv_cur.tv_sec;
    tv_stop_test.tv_usec = tv_cur.tv_usec;
    tv_stop_test.tv_sec = tv_cur.tv_sec + ctx.test_duration;

    while (timercmp(&tv_cur, &tv_stop_test, <) && (rCounter < maxResults))
    {
	tv_select.tv_sec = tv_stop_test.tv_sec - tv_cur.tv_sec;
	tv_select.tv_usec = 0;

	memcpy(&rset, &masterset, sizeof(fd_set));
	if (select(sockListLastFD + 1, &rset, NULL, NULL, &tv_select) > 0) {
	    for (unsigned int i = 0; i < ctx.numstreams; i++) {
		if (FD_ISSET(sockList[i], &rset)) {
		    bytes_recv = recv(sockList[i], sockBuffer, sockBufferSz-1, MSG_DONTWAIT);
		    if (bytes_recv > 0) {
			total += bytes_recv;
		    } else if (!bytes_recv) {
			FD_CLR(sockList[i], &masterset);
		    }
		}
	    }
	}

	elapsed = TIMEVAL_MICROSECONDS(tv_cur) - TIMEVAL_MICROSECONDS(tv_start);
	if (elapsed >= interval) {
	    downloadResults[rCounter].nstreams = ctx.numstreams;
	    downloadResults[rCounter].bytes = total;
	    downloadResults[rCounter].interval = elapsed;

	    rCounter++;
	    total = 0;
	    tv_start.tv_usec = tv_cur.tv_usec;
	    tv_start.tv_sec = tv_cur.tv_sec;
	}
	gettimeofday(&tv_cur, NULL);
    }

    *numres = rCounter;

    return 0;
}

/* do not call twice */
int tcp_client_run(MeasureContext ctx)
{
    CURL *curl;
    int rc;

    unsigned int rcvcounter;
    DownResult *rcv;

    struct tcpbw_report *report;

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

    report = tcpbw_report_init();
    if (!report) {
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
    snprintf(strbuf, sizeof(strbuf), "version=1;ipvn=%i;concurrentStreams=%u;measureSeconds=%u;samplePeriodMiliSeconds=%u;agentId=%s",
	     ctx.family, ctx.numstreams, ctx.test_duration, ctx.sample_period_ms, ctx.agent_id ? ctx.agent_id : "");
    curl_easy_setopt(curl, CURLOPT_COPYPOSTFIELDS, strbuf);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    if ((rc = issue_simple_command(curl, 0)))
	goto err_exit;
    if ((rc = tcpc_process_request_answer(&ctx, chunk.memory)))
	goto err_exit;

    unsigned int streamcount = 0;
    if (ctx.numstreams >= MAX_CONCURRENT_SESSIONS)
	ctx.numstreams = MAX_CONCURRENT_SESSIONS;
    print_msg(MSG_NORMAL, "opening up to %u measurement streams", ctx.numstreams);
    FD_ZERO(&sockListFDs);
    for (unsigned int i = 0; i < ctx.numstreams; i++) {
	int m_socket = create_measure_socket(ctx.host_name, ctx.port,
					     ctx.sessionid ? ctx.sessionid : ctx.token);
	if (m_socket != -1) {
	    streamcount++;
	    FD_SET(m_socket, &sockListFDs);
	    if (m_socket > sockListLastFD)
		sockListLastFD = m_socket;
	} else {
	    print_warn("m_socket == -1");
	}
	sockList[i] = m_socket;
    }
    if (!streamcount) {
	print_warn("could not open any test streams, aborting test");
	return SEXIT_MP_TIMEOUT;
    }
    print_msg((ctx.numstreams != streamcount)? MSG_NORMAL : MSG_DEBUG,
	      "will use %u measurement streams", streamcount);

    /* Create a single buffer with a good size */
    sockBufferSz = new_tcp_buffer(sockList[0], &sockBuffer);
    if (!sockBufferSz) {
	print_err("could not allocate socket buffer");
	return SEXIT_OUTOFRESOURCE;
    }

    print_msg(MSG_DEBUG, "sending request /session/start-upload");
    if ((rc = prepare_command_channel(curl, ctx.control_url, "/session/start-upload", slist, ctx.timeout_test, ctx.family)))
	goto err_exit;
    if ((rc = issue_simple_command(curl, 1)))
	goto err_exit;

    print_msg(MSG_IMPORTANT, "starting upload measurement (send)");
    sendUploadPackets(ctx);

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
    receiveDownloadPackets(ctx, &rcv, &rcvcounter);

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

    const char *upload_results_json = NULL;

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

    /* FIXME: does not belong here, but on caller */
    rc = (tcpbw_report(report, upload_results_json, rcv, rcvcounter, &ctx)) ?
                SEXIT_FAILURE : SEXIT_SUCCESS;

    print_msg(MSG_IMPORTANT, "tcp bandwidth measurements finished");

err_exit:
    free(chunk.memory);
    free(sockBuffer);

    if (curl)
	curl_easy_cleanup(curl);
    if (slist)
	curl_slist_free_all(slist);

    curl_global_cleanup();
    free_curl_err_handling();
    tcpbw_report_done(report);

    return rc;
}

