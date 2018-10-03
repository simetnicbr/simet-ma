#include "simet-inetuptime_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <limits.h>
#include <string.h>
#include <getopt.h>
#include <assert.h>

#include <sys/poll.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>

#include <time.h>
#include <sys/sysinfo.h>

#include "simet-inetuptime.h"
#include "logger.h"

#ifdef HAVE_JSON_JSON_H
#include <json/json.h>
#elif HAVE_JSON_C_JSON_H
#include <json-c/json.h>
#else
#include <json.h>
#endif

static struct simet_inetup_server **servers = NULL;
static const char *agent_id = NULL;
static const char *agent_token = NULL;
static const char *boot_id = NULL;
static const char *agent_mac = NULL;
static const char *task_name = NULL;

static int simet_uptime2_keepalive_interval = 30; /* seconds */
static int simet_uptime2_tcp_timeout = 60; /* seconds, for data to be ACKed as well as connect() */

#define BACKOFF_LEVEL_MAX 8
static const unsigned int backoff_times[BACKOFF_LEVEL_MAX] =
    { 1, 10, 10, 30, 30, 60, 60, 300 };


/*
 * helpers
 */

static const char *str_ip46(int ai_family)
{
    switch (ai_family) {
        case AF_INET:
            return "ip4";
        case AF_INET6:
            return "ip6";
    }
    return "ip";
}

#define TRACE_LOG(s, ...) \
    do { LOG_MESSAGE(stderr, "TRACE"); \
         fprintf(stderr,  "%s(%u): ", str_ip46(s->ai_family), s->connection_id); \
         fprintf(stderr, __VA_ARGS__); \
         fprintf(stderr, "\n"); \
    } while(0)

#if 0
static struct json_object * xx_json_object_new_in64_as_str(const int64_t v)
{
    char buf[32];
    snprintf(buf, sizeof(buf), "%" PRIi64, v);
    return json_object_new_string(buf);
}
#endif

/*
 * TCP async queueing
 *
 * 1. reserve space in the local queue, if not available, try again later (so that
 *    we can be message-atomic at the higher level)
 * 2. commit message to the local queue, we can now return success no matter what.
 * 3. attempt to send() to kernel buffer immediately and return even if nothing or
 *    partial send.  Whatever is left will get sent async by the main loop.
 */

static void tcpaq_close(struct simet_inetup_server * const s)
{
    assert(s);
    if (s->socket != -1) {
        shutdown(s->socket, SHUT_RDWR);
        close(s->socket);
        s->socket = -1;
    }
    s->queue.rd_pos = 0;
    s->queue.wr_pos = 0;
    s->queue.wr_pos_reserved = 0;
}

static int tcpaq_reserve(struct simet_inetup_server * const s, size_t size)
{
    assert(s);

    /* paranoia */
    if (s->queue.wr_pos >= s->queue.wr_pos_reserved)
        s->queue.wr_pos_reserved = s->queue.wr_pos;

    if (s->queue.wr_pos_reserved + size >= s->queue.buffer_size)
        return -ENOSPC;

    s->queue.wr_pos_reserved += size;
    return 0;
}

static void tcpaq_unreserve(struct simet_inetup_server * const s, size_t size)
{
    assert(s);
    if (s->queue.wr_pos_reserved > s->queue.wr_pos + size)
        s->queue.wr_pos_reserved -= size;
}

/**
 * tcpaq_queue: queue a message for transmisson, does *not* flush
 *
 * @reserved: true if tcpaq_reserve() already done for this message
 *
 * returns: 0, -ENOSPC...
 */
static int tcpaq_queue(struct simet_inetup_server * const s, void *data, size_t size, int reserved)
{
    assert(s && s->queue.buffer);

    if (!size)
        return 0;
    if (!reserved && tcpaq_reserve(s, size))
        return -ENOSPC;
    if (s->queue.wr_pos + size >= s->queue.buffer_size)
        return -ENOSPC; /* defang the bug */

    memcpy(&s->queue.buffer[s->queue.wr_pos], data, size);
    s->queue.wr_pos += size;

    if (s->queue.wr_pos > s->queue.wr_pos_reserved) {
        WARNING_LOG("internal error: stream %u went past reservation, coping with it", s->connection_id);
        s->queue.wr_pos_reserved = s->queue.wr_pos;
    }

    return 0;
}

static void xx_tcpaq_compact(struct simet_inetup_server * const s)
{
    /* FIXME: also compact partially transmitted using a watermark */
    if (s->queue.rd_pos >= s->queue.wr_pos) {
        if (s->queue.wr_pos_reserved > s->queue.rd_pos) {
            s->queue.wr_pos_reserved -= s->queue.rd_pos;
        } else {
            s->queue.wr_pos_reserved = 0;
        }
        s->queue.wr_pos = 0;
        s->queue.rd_pos = 0;
    }
}

static int tcpaq_send_nowait(struct simet_inetup_server * const s)
{
    size_t  send_sz;
    ssize_t sent;

    assert(s && s->queue.buffer);

    if (s->socket == -1)
        return -ENOTCONN;
    if (s->queue.wr_pos == 0)
        return 0;
    if (s->queue.rd_pos >= s->queue.wr_pos || s->queue.rd_pos >= s->queue.buffer_size) {
        xx_tcpaq_compact(s);
        return 0;
    }

    send_sz = s->queue.wr_pos - s->queue.rd_pos;
    sent = send(s->socket, &s->queue.buffer[s->queue.rd_pos], send_sz, MSG_DONTWAIT | MSG_NOSIGNAL);
    if (sent < 0) {
        int err = errno;
        if (err == EAGAIN || err == EWOULDBLOCK || err == EINTR)
            return 0;
        TRACE_LOG(s, "send() error: %s", strerror(err));
        return -err;
    }
    s->queue.rd_pos += sent;

#if 0
    /* commented out - we can tolerate 200ms extra delay from Naggle just fine,
     * and we already asked for TCP_NODELAY after connect() */

    const int zero = 0;
    const int one = 1;
    /* Ask kernel to flush buffer every time our local queue is empty */
    if (s->queue.wr_pos <= s->queue.rd_pos) {
        setsockopt(s->socket, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        setsockopt(s->socket, IPPROTO_TCP, TCP_NODELAY, &zero, sizeof(zero));
    }
#endif
    /* TRACE_LOG(s, "send() %zd out of %zu bytes", sent, send_sz); */

    xx_tcpaq_compact(s);
    return 0;
}


/*
 * SIMET2 Uptime2 protocol helpers
 */
static int xx_simet_uptime2_sndmsg(struct simet_inetup_server * const s,
                               const uint16_t msgtype, const uint32_t msgsize,
                               const char * const msgdata)
{
    struct simet_inetup_msghdr hdr;
    size_t reserve_sz = msgsize + sizeof(hdr);

    if (tcpaq_reserve(s, reserve_sz))
        return -EAGAIN; /* can't send right now */

    hdr.message_type = htons(msgtype);
    hdr.message_size = htonl(msgsize);

    if (tcpaq_queue(s, &hdr, sizeof(hdr), 1) || tcpaq_queue(s, (void *)msgdata, msgsize, 1)) {
        tcpaq_unreserve(s, reserve_sz);
        return -EAGAIN;
    }

    return tcpaq_send_nowait(s);
}

static int uptimeserver_flush(struct simet_inetup_server * const s)
{
    if (s && s->queue.buffer && s->socket != -1 && s->state != SIMET_INETUP_P_C_SHUTDOWN)
        return tcpaq_send_nowait(s);

    return 0;
}

static void xx_clocknow(time_t *now_seconds)
{
    struct timespec now;

    if (!clock_gettime(CLOCK_MONOTONIC, &now)) {
        *now_seconds = now.tv_sec;
    } else {
        *now_seconds = 0; /* clock broken */
    }
}

/* update keepalive timer every time we send a message of any time */
static void simet_uptime2_keepalive_update(struct simet_inetup_server * const s)
{
    xx_clocknow(&s->keepalive_clock);
}

/*
 * SIMET2 Uptime2 general messages
 *
 * Returns: 0 or -errno
 */

static int simet_uptime2_msg_keepalive(struct simet_inetup_server * const s)
{
    TRACE_LOG(s, "sending ma_keepalive event");
    return xx_simet_uptime2_sndmsg(s, SIMET_INETUP_P_MSGTYPE_KEEPALIVE, 0, NULL);
}

static int simet_uptime2_msg_maconnect(struct simet_inetup_server * const s)
{
    json_object *jo;
    struct sysinfo si;
    long uptime = 0;
    int rc = -ENOMEM;

    assert(s);

    TRACE_LOG(s, "sending ma_connect event");

    if (sysinfo(&si) == 0)
        uptime = si.uptime;

    jo = json_object_new_object();
    if (!jo)
        return -ENOMEM;

    if (agent_id)
        json_object_object_add(jo, "agent-id", json_object_new_string(agent_id));
    if (agent_token)
        json_object_object_add(jo, "agent-token", json_object_new_string(agent_token));
    if (boot_id)
        json_object_object_add(jo, "boot-id", json_object_new_string(boot_id));

    if (s->local_family != AF_UNSPEC || s->peer_family != AF_UNSPEC) {
        json_object *jconn = json_object_new_object();
        if (!jconn)
            goto err_exit;

        if (s->local_family != AF_UNSPEC) {
            json_object_object_add(jconn, "local-address-family", json_object_new_string(str_ip46(s->local_family)));
            json_object_object_add(jconn, "local-address", json_object_new_string(s->local_name));
            json_object_object_add(jconn, "local-port", json_object_new_string(s->local_port));
        }
        if (s->peer_family != AF_UNSPEC) {
            json_object_object_add(jconn, "remote-address-family", json_object_new_string(str_ip46(s->peer_family)));
            json_object_object_add(jconn, "remote-address", json_object_new_string(s->peer_name));
            json_object_object_add(jconn, "remote-port", json_object_new_string(s->peer_port));
        }
        json_object_object_add(jo, "connection", jconn);
        jconn = NULL;
    }
    if (agent_mac)
        json_object_object_add(jo, "mac", json_object_new_string(agent_mac));
    if (task_name)
        json_object_object_add(jo, "task-name", json_object_new_string(task_name));
    json_object_object_add(jo, "task-version", json_object_new_string(PACKAGE_VERSION));
    json_object_object_add(jo, "uptime-seconds", json_object_new_int64(uptime));

    const char *jsonstr = json_object_to_json_string(jo);
    if (jsonstr) {
        TRACE_LOG(s, "ma_connect message: %s", jsonstr);
        rc = xx_simet_uptime2_sndmsg(s, SIMET_INETUP_P_MSGTYPE_MACONNECT, strlen(jsonstr), jsonstr);
    } else {
        rc = -EFAULT;
    }

err_exit:
    /* free(jsonstr); -- not! it is managed by json-c */
    json_object_put(jo);

    return rc;
}

/*
 * SIMET2 Uptime2 connection lifetime messages and handling
 */

static void xx_server_backoff_reset(struct simet_inetup_server * const s)
{
    xx_clocknow(&s->backoff_clock);
}

/* jump to the reconnect state, used by state machine workers */
static void simet_uptime2_reconnect(struct simet_inetup_server * const s)
{
    s->state = SIMET_INETUP_P_C_RECONNECT;
    s->backoff_level = 0;
    xx_server_backoff_reset(s);
}

/*
 * protocol state machine: state workers
 *
 * returns: N < 0 : errors (-errno)
 *          N = 0 : OK, run next state ASAP
 *          N > 0 : OK, no need to run again for N seconds
 */
static int uptimeserver_refresh(struct simet_inetup_server * const s)
{
    assert(s);
    assert(s->state == SIMET_INETUP_P_C_REFRESH);

    if (simet_uptime2_msg_maconnect(s)) {
        simet_uptime2_reconnect(s);
    } else {
        simet_uptime2_keepalive_update(s);
        s->state = SIMET_INETUP_P_C_MAINLOOP;
    }

    return 0;
}

static int uptimeserver_keepalive(struct simet_inetup_server * const s)
{
    assert(s);

    if (s->keepalive_clock != 0) {
        struct timespec now;
        int ds;

        if (!clock_gettime(CLOCK_MONOTONIC, &now)) {
            ds = (now.tv_sec >= s->keepalive_clock)? now.tv_sec - s->keepalive_clock : INT_MAX;
            if (ds < simet_uptime2_keepalive_interval)
                return simet_uptime2_keepalive_interval - ds;
        }
    }

    if (simet_uptime2_msg_keepalive(s)) {
        simet_uptime2_reconnect(s);
        return 0;
    }

    simet_uptime2_keepalive_update(s);
    return simet_uptime2_keepalive_interval;
}

static int xx_nameinfo(struct sockaddr_storage *sa, socklen_t sl,
                        sa_family_t *family, const char **hostname, const char **hostport)
{
    char namebuf[256], portbuf[32];

    if (sa->ss_family == AF_UNSPEC || getnameinfo((struct sockaddr *)sa, sl,
                                                   namebuf, sizeof(namebuf), portbuf, sizeof(portbuf),
                                                   NI_NUMERICHOST | NI_NUMERICSERV)) {
        *family = AF_UNSPEC;
        *hostname = strdup("unknown");
        *hostport = strdup("error");

        return 1;
    }

    *hostname = strdup(namebuf);
    *hostport = strdup(portbuf);
    *family = sa->ss_family;

    return 0;
}

static int uptimeserver_connect(struct simet_inetup_server * const s,
                       const char * const server_name, const char * const server_port)
{
    struct addrinfo *air, *airp;
    struct addrinfo ai;
    int backoff;
    int r;

    const int int_one = 1;

    assert(s && server_name && server_port);
    assert(s->state == SIMET_INETUP_P_C_INIT || s->state == SIMET_INETUP_P_C_RECONNECT);

    if (s->state == SIMET_INETUP_P_C_RECONNECT && s->socket != -1)
        tcpaq_close(s);

    /* Backoff timer */
    if (s->backoff_clock != 0) {
        struct timespec now;
        unsigned int ds;

        if (!clock_gettime(CLOCK_MONOTONIC, &now)) {
            ds = (now.tv_sec >= s->backoff_clock)? now.tv_sec - s->backoff_clock : UINT_MAX;
            if (ds < backoff_times[s->backoff_level])
                return (int)(backoff_times[s->backoff_level] - ds);
        }
    }

    xx_server_backoff_reset(s);
    if (s->backoff_level < BACKOFF_LEVEL_MAX-1)
        s->backoff_level++;
    backoff = (int) backoff_times[s->backoff_level];

    TRACE_LOG(s, "attempting connection to %s, port %s", server_name, server_port);

    memset(&ai, 0, sizeof(ai));
    ai.ai_flags = AI_ADDRCONFIG;
    ai.ai_socktype = SOCK_STREAM;
    ai.ai_family = s->ai_family;
    ai.ai_protocol = IPPROTO_TCP;

    r = getaddrinfo(server_name, server_port, &ai, &air);
    if (r != 0) {
        TRACE_LOG(s, "getaddrinfo returned %s", gai_strerror(r));
        return backoff;
    }
    for (airp = air; airp != NULL; airp = airp->ai_next) {
        s->socket = socket(airp->ai_family, airp->ai_socktype | SOCK_CLOEXEC, airp->ai_protocol);
        if (s->socket == -1)
            continue;

        /* FIXME: do this using select()/poll(), but we have to make it
         * indepondent and async so that we can return to caller to process
         * other concurrent connect()s to other server streams in the
         * meantime.  And that must happen in the middle of the
         * getaddrinfo() loop */

        /* The use of SO_SNDTIMEO for blocking connect() timeout is not
         * mandated by POSIX and it is implemented only in [non-ancient]
         * Linux */
        const struct timeval so_timeout = {
            .tv_sec = simet_uptime2_tcp_timeout,
            .tv_usec = 0,
        };
        if (setsockopt(s->socket, SOL_SOCKET, SO_SNDTIMEO, &so_timeout, sizeof(so_timeout)) ||
            setsockopt(s->socket, SOL_SOCKET, SO_RCVTIMEO, &so_timeout, sizeof(so_timeout))) {
            TRACE_LOG(s, "failed to set socket timeouts using SO_*TIMEO");
        }

        /* RFC-0793/RFC-5482 user timeout.
         *
         * WARNING: Linux seems to be using twice the value set, but trying to
         * compensate for this (by giving it half the value we want) is dangerous
         * unless we do track it down to be sure it has been enshrined as ABI
         */
        const unsigned int ui = (unsigned int)simet_uptime2_tcp_timeout * 1000U;
        if (setsockopt(s->socket, IPPROTO_TCP, TCP_USER_TIMEOUT, &ui, sizeof(unsigned int))) {
            WARNING_LOG("failed to enable TCP timeouts, measurement error will increase");
        }

#if 0
        /* RFC-1122 TCP keep-alives as a fallback for timeouts.
         *
         * Cheap bug defense against application-layer keepalive messages not being sent, but otherwise
         * useless as the kernel resets the TCP Keep-Alive timers on socket send().
         *
         * Linux seems to do the expected with this one, and timeout at
         * KEEPIDLE + KEEPINTVL * KEEPCNT.
         *
         * Note: we don't account for KEEPIDLE in the code below
         */
        const int tcp_keepcnt = 3;
        int tcp_keepintvl = simet_uptime2_tcp_timeout / tcp_keepcnt;
        if (tcp_keepintvl < 5)
            tcp_keepintvl = 5;
        int tcp_keepidle = simet_uptime2_tcp_timeout / tcp_keepcnt;
        if (tcp_keepidle < 5)
            tcp_keepidle = 5;
        if (setsockopt(s->socket, IPPROTO_TCP, TCP_KEEPCNT, &tcp_keepcnt, sizeof(int)) ||
            setsockopt(s->socket, IPPROTO_TCP, TCP_KEEPIDLE, &tcp_keepidle, sizeof(int)) ||
            setsockopt(s->socket, IPPROTO_TCP, TCP_KEEPINTVL, &tcp_keepintvl, sizeof(int)) ||
            setsockopt(s->socket, SOL_SOCKET, SO_KEEPALIVE, &int_one, sizeof(int_one))) {
            WARNING_LOG("failed to enable TCP Keep-Alives, measurement error might increase");
        } else {
            DEBUG_LOG("RFC-1122 TCP Keep-Alives enabled, idle=%ds, intvl=%ds, count=%d", tcp_keepidle, tcp_keepintvl, tcp_keepcnt);
        }
#endif

        if (connect(s->socket, airp->ai_addr, airp->ai_addrlen) != -1)
            break;
        close(s->socket);
        s->socket = -1;
    }
    if (!airp) {
        TRACE_LOG(s, "could not connect, will retry later");
        return backoff;
    }

    freeaddrinfo(air);

    s->state = SIMET_INETUP_P_C_RECONNECT; /* if we abort, ensure we will cleanup */

    /* Disable Naggle, we don't need it (but we can tolerate it) */
    setsockopt(s->socket, IPPROTO_TCP, TCP_NODELAY, &int_one, sizeof(int_one));

    /* Get metadata of the connected socket */
    struct sockaddr_storage sa;
    socklen_t sa_len;

    sa_len = sizeof(struct sockaddr_storage);
    sa.ss_family = AF_UNSPEC;
    if (getpeername(s->socket, (struct sockaddr *)&sa, &sa_len) || 
        xx_nameinfo(&sa, sa_len, &s->peer_family, &s->peer_name, &s->peer_port))
        WARNING_LOG("failed to get peer metadata, coping with it");

    sa_len = sizeof(struct sockaddr_storage);
    sa.ss_family = AF_UNSPEC;
    if (getsockname(s->socket, (struct sockaddr *)&sa, &sa_len) ||
        xx_nameinfo(&sa, sa_len, &s->local_family, &s->local_name, &s->local_port))
        WARNING_LOG("failed to get local metadata, coping with it");

    /* done... */
    TRACE_LOG(s, "connected: local %s:[%s]:%s, remote %s:[%s]:%s",
            str_ip46(s->local_family), s->local_name, s->local_port,
            str_ip46(s->peer_family), s->peer_name, s->peer_port);

    s->state = SIMET_INETUP_P_C_REFRESH;
    return 0;
}

static int uptimeserver_create(struct simet_inetup_server **sp, int ai_family)
{
    static unsigned int next_connection_id = 1;

    struct simet_inetup_server *s;

    assert(sp);
    assert(ai_family == AF_INET || ai_family == AF_INET6);

    s = calloc(1, sizeof(struct simet_inetup_server));
    if (!s)
        return -ENOMEM;

    s->socket = -1;
    s->state = SIMET_INETUP_P_C_INIT;
    s->ai_family = ai_family;
    s->connection_id = next_connection_id;
    s->queue.buffer = calloc(1, SIMET_INETUP_QUEUESIZE);
    if (!s->queue.buffer) {
        free(s);
        return -ENOMEM;
    }
    s->queue.buffer_size = SIMET_INETUP_QUEUESIZE;

    next_connection_id++;

    *sp = s;

    return 0;
}

/*
 * Command line and main executable
 */

static const char program_copyright[]=
    "Copyright (c) 2018 NIC.br\n\n"
    "This is free software; see the source for copying conditions.\n"
    "There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR\n"
    "A PARTICULAR PURPOSE.\n";

static void print_version(void)
{
    fprintf(stdout, "%s %s\n%s\n", PACKAGE_NAME, PACKAGE_VERSION, program_copyright);
    exit(EXIT_SUCCESS);
}

/* FIXME:
 * implement both "standalone daemon" modes and foreground modes?
 *
 * daemon:     -p <pidfile>, and does setsid() and fork().
 * foreground: [-f], works better for systemd and procd
 *
 * currently, implements only foreground mode.
 */

static void print_usage(const char * const p, int mode)
{
    fprintf(stderr, "Usage: %s [-h] [-V] [-t <timeout>] "
        "[-d <agent-id>] [-m <string>] [-b <boot id>] [-j <token> ] [-M <string>] "
        "<server name> [<server port>]\n", p);
    if (mode) {
    fprintf(stderr, "\n"
        "\t-h\tprint usage help and exit\n"
        "\t-V\tprint program version and copyright, and exit\n"
        "\t-t\tprotocol timeout in seconds\n"
        "\t-d\tmeasurement agent id\n"
        "\t-m\tmeasurement agent hardcoded id\n"
        "\t-M\tmeasurement task name\n"
        "\t-b\tboot id (e.g. from /proc/sys/kernel/random/boot_id)\n"
        "\t-j\taccess credentials\n"
        "\n"
        "server name: DNS name of server\n"
        "server port: TCP port on server\n"
        "\nNote: client will attempt to open one IPv4 and one IPv6 connection to the server");
    }
    exit((mode)? EXIT_SUCCESS : EXIT_FAILURE);
}

int main(int argc, char **argv) {
    const char *server_name = NULL;
    const char *server_port = "22000";
    int intarg;

    int option;
    /* FIXME: parameter range checking, proper error messages, strtoul instead of atoi */
    while ((option = getopt (argc, argv, "46hVc:l:t:d:m:M:b:j:")) != -1) {
        switch (option) {
        case 't':
            intarg = atoi(optarg);
            if (intarg >= 15)
                simet_uptime2_tcp_timeout = intarg;

            if (simet_uptime2_keepalive_interval >= simet_uptime2_tcp_timeout)
                simet_uptime2_keepalive_interval = simet_uptime2_tcp_timeout / 2;
            if (simet_uptime2_keepalive_interval > 30)
                simet_uptime2_keepalive_interval = 30;
            break;
        case 'd':
            agent_id = optarg;
            break;
        case 'm':
            agent_mac = optarg;
            break;
        case 'M':
            task_name = optarg;
            break;
        case 'b':
            boot_id = optarg;
            break;
        case 'j':
            agent_token = optarg;
            break;
        case 'h':
            print_usage(argv[0], 1);
            /* fall-through */
        case 'V':
            print_version();
            /* fall-through */
        default:
            print_usage(argv[0], 0);
        }
    };

    if (optind >= argc || argc - optind > 2)
        print_usage(argv[0], 0);

    server_name = argv[optind++];
    if (optind < argc)
        server_port = argv[optind];

    DEBUG_LOG("timeout=%d, keepalive=%d, server=\"%s\", port=%s",
              simet_uptime2_tcp_timeout, simet_uptime2_keepalive_interval,
              server_name, server_port);

    /* init */
    /* this can be easily converted to use up-to-# servers per ai_family, etc */
    const unsigned int servers_count = 2;
    struct pollfd *servers_pollfds = calloc(servers_count, sizeof(struct pollfd));
    servers = calloc(servers_count, sizeof(struct simet_inetup_server *));
    if (!servers_pollfds || !servers ||
            uptimeserver_create(&servers[0], AF_INET) || uptimeserver_create(&servers[1], AF_INET6)) {
        ERROR_LOG("out of memory");
        return EXIT_FAILURE;
    }

    /* state machine loop */
    do {
        time_t minwait = 300;
        unsigned int j;

        for (j = 0; j < servers_count; j++) {
            struct simet_inetup_server *s = servers[j];
            int wait = 0;

            /* DEBUG_LOG("%s(%u): main loop, currently at state %u", str_ip46(s->ai_family), s->connection_id, s->state); */

            switch (s->state) {
            case SIMET_INETUP_P_C_INIT:
                /* FIXME: add POLLIN if a backchannel is added, etc */
                servers_pollfds[j].events = POLLRDHUP;
                /* fall-through */
            case SIMET_INETUP_P_C_RECONNECT:
                wait = uptimeserver_connect(s, server_name, server_port);
                servers_pollfds[j].fd = s->socket;
                break;
            case SIMET_INETUP_P_C_REFRESH:
                wait = uptimeserver_refresh(s);
                break;
            case SIMET_INETUP_P_C_MAINLOOP:
                wait = uptimeserver_keepalive(s);
                /* state change messages go here */
                break;
#if 0
            case SIMET_INETUP_P_C_DISCONNECT:
                /* not implemented, unreachable */
                servers_pollfds[s].fd = -1;
            case SIMET_INETUP_P_C_SHUTDOWN:
                /* not implemented, unreachable */
#endif
            default:
                ERROR_LOG("internal error or memory corruption");
                return EXIT_FAILURE;
            }

            if (wait >= 0 && wait < minwait)
                minwait = wait;

            if (uptimeserver_flush(s)) {
                simet_uptime2_reconnect(s);
                minwait = 0;
            }
        }
        /* DEBUG_LOG("------ (minwait: %ld) ------", minwait); */

        if (minwait > 0) {
            /* optimized for a small number of servers */
            int poll_res = poll(servers_pollfds, servers_count, minwait * 1000U);
            if (poll_res > 0) {
                for (j = 0; j < servers_count; j++) {
                    if (servers_pollfds[j].revents & (POLLRDHUP | POLLHUP | POLLERR))
                        simet_uptime2_reconnect(servers[j]); /* fast close/shutdown detection */
                    else if (servers_pollfds[j].revents) {
                        TRACE_LOG(servers[j], "unhandled: pollfd[%u].fd = %d, pollfd[%u].events = 0x%04x, pollfd[%u].revents = 0x%04x",
                            j, servers_pollfds[j].fd,
                            j, (unsigned int)servers_pollfds[j].events,
                            j, (unsigned int)servers_pollfds[j].revents);
                    }
                }
            } else if (poll_res == -1 && (errno != EINTR && errno != EAGAIN)) {
                ERROR_LOG("internal error, memory corruption or out of memory");
                return EXIT_FAILURE;
            }
        }
    } while (1);

    return EXIT_SUCCESS;
}

/* vim: set et ts=4 sw=4 : */
