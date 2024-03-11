/*
 * SIMET2 MA SIMET Spoofer client (sspooferc) - measurement packet
 * Copyright (c) 2024 NIC.br <medicoes@simet.nic.br>
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

#include "sspooferc_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>

#include <limits.h>
#include <string.h>
#include <errno.h>

#include <assert.h>
#if !defined(static_assert) && defined(__STDC_VERSION__) && (__STDC_VERSION__ < 202301L)
#  define static_assert _Static_assert
#endif

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include "sspooferc.h"
#include "simet_err.h"
#include "logger.h"
#include "timespec.h"

#ifdef HAVE_JSON_JSON_H
#include <json/json.h>
#elif HAVE_JSON_C_JSON_H
#include <json-c/json.h>
#else
#include <json.h>
#endif

#define packet_msg(aloglevel, sctx, format, arg...) \
    do { \
       print_msg(aloglevel, "measurement: %u (%s): " format, sctx->connection_id, str_ipv46(sctx->conn.ai_family), ## arg); \
    } while (0)

#define packet_trace(sctx, format, arg...) \
    protocol_msg(MSG_TRACE, sctx, format, ## arg)


/* Pseudo headers used for UDP over IPv4/IPv6 checksum calculation */
struct udp4_ph {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint8_t  z1;
    uint8_t  proto;
    uint16_t ip_len;
    /* udp header */
    /* udp payload */
} __attribute__((__packed__));

struct udp6_ph {
    uint32_t src_addr[4];
    uint32_t dst_addr[4];
    uint32_t ip_len;
    uint16_t z1;
    uint8_t  z2;
    uint8_t  proto;
    /* udp header */
    /* udp payload */
} __attribute__((__packed__));

union udp_ph {
    struct udp4_ph udp4_ph;
    struct udp6_ph udp6_ph;
};

static uint16_t nbo_inet_csum(const void *buf, size_t len, uint16_t nbo_old_csum)
{
    const uint16_t *u16_buf;
    uint32_t sum;

    if (!buf)
        return 0;
    u16_buf = buf;

    /* RFC 1701 */
    sum = 0;
    while (len > 1) {
        sum += *u16_buf++;
        len -= sizeof(*u16_buf);
    }
    if (len) {
        /* odd length... */
        sum += ntohs(*(const uint8_t *)u16_buf);
    }

    /* Sum in previous partial result, inverted because we
     * previously inverted it on return.
     *
     * Note: 0xffff == 0x0000 due to one's-complement math */
    sum += (uint16_t)(~nbo_old_csum);

    /* fold in the carries: converts two's-complement sum into
     * to one's-complement  */
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);

    /* result is already in network byte order, because we did not
     * htons() while summing, and one's-complement sums of 16-bit words
     * are symmetric re. byte-ordering */

    return (uint16_t)(~sum);
}

/* payload is not touched, returns: -ERRNO, or packet size */
static ssize_t fill_udp46_hdr(uint8_t * const datagram, const uint16_t buffer_length,
                              const uint16_t udp_payload_len,
                              uint8_t ip_ttl, uint8_t ip_traffic_class,
                              const sockaddr_any_t_ * const src,
                              const sockaddr_any_t_ * const dst,
                              struct udphdr ** const pudp,
                              uint8_t ** const ppayload)
{
    uint16_t datagram_len = 0;
    uint16_t udp_offset = 0;
    uint16_t udp_ph_len = 0;
    union udp_ph udp_ph;

    /* note: network byte order */
    in_port_t nbo_src_port = 0;
    in_port_t nbo_dst_port;

    if (!datagram || !dst || (src && src->ss.ss_family != dst->ss.ss_family))
        return -EINVAL;

    memset(&udp_ph, 0, sizeof(udp_ph));

    /* IPv4/IPv6 header */

    if (dst->ss.ss_family == AF_INET) {
        /* IPv4 UDP datagram */

        udp_offset = sizeof(struct ip);
        datagram_len = sizeof(struct ip) + sizeof(struct udphdr) + udp_payload_len;
        if (datagram_len > buffer_length)
            return -ENOSPC;

        memset(datagram, 0, sizeof(struct ip));
        struct ip *iph = (void *)datagram;
        iph->ip_hl = 5;      /* No IPv4 options */
        iph->ip_v = 4;       /* IPv4 */
        iph->ip_tos = ip_traffic_class;
        iph->ip_len = htons(datagram_len);
        iph->ip_id = 0;      /* kernel fills it in */
        iph->ip_off = 0;
        iph->ip_ttl = ip_ttl;
        iph->ip_p = IPPROTO_UDP;
        iph->ip_sum = 0;     /* kernel fills it in */

        if (src) {
            memcpy(&iph->ip_src, &src->sin.sin_addr, sizeof(iph->ip_src));
            nbo_src_port = src->sin.sin_port;
        }
        memcpy(&iph->ip_dst, &dst->sin.sin_addr, sizeof(iph->ip_dst));
        nbo_dst_port = dst->sin.sin_port;

#if 0
        /* this is actually not needed in Linux, but might be more portable */
        /* however, if we do this, we must also set the ip_id field */
        iph->ip_sum = nbo_inet_csum(datagram, udp_offset, 0);
#endif

        /* prepare UDP pseudo header */
        udp_ph_len = sizeof(udp_ph.udp4_ph);
        memcpy(&udp_ph.udp4_ph.src_addr, &iph->ip_src, sizeof(udp_ph.udp4_ph.src_addr));
        memcpy(&udp_ph.udp4_ph.dst_addr, &iph->ip_dst, sizeof(udp_ph.udp4_ph.dst_addr));
        udp_ph.udp4_ph.proto  = iph->ip_p;
        udp_ph.udp4_ph.ip_len = htons(sizeof(struct udphdr) + udp_payload_len);
    } else if (dst->ss.ss_family == AF_INET6) {
        /* IPv6 UDP datagram */

        udp_offset = sizeof(struct ip6_hdr);
        datagram_len = sizeof(struct ip6_hdr) + sizeof(struct udphdr) + udp_payload_len;
        if (datagram_len > buffer_length)
            return -ENOSPC;

        memset(datagram, 0, sizeof(struct ip6_hdr));
        struct ip6_hdr *ip6h = (void *)datagram;
        /* ip6h->ip6_flow = 0;   kernel fills it in, warning: writing to ip6_flow overwrites ipv6_vfc */
        ip6h->ip6_vfc = 0x60;    /* IPv6, tclass = 0 */
        ip6h->ip6_plen = htons(sizeof(struct udphdr) + udp_payload_len); /* payload len + UDP EH */
        ip6h->ip6_nxt  = IPPROTO_UDP; /* next header: UDP */
        ip6h->ip6_hlim = ip_ttl;

        if (src) {
            memcpy(&ip6h->ip6_src, &src->sin6.sin6_addr, sizeof(ip6h->ip6_src));
            nbo_src_port = src->sin6.sin6_port;
        }
        memcpy(&ip6h->ip6_dst, &dst->sin6.sin6_addr, sizeof(ip6h->ip6_dst));
        nbo_dst_port = dst->sin6.sin6_port;

        /* prepare UDP pseudo header */
        udp_ph_len = sizeof(udp_ph.udp6_ph);
        memcpy(&udp_ph.udp6_ph.src_addr, &ip6h->ip6_src, sizeof(udp_ph.udp6_ph.src_addr));
        memcpy(&udp_ph.udp6_ph.dst_addr, &ip6h->ip6_dst, sizeof(udp_ph.udp6_ph.dst_addr));
        udp_ph.udp6_ph.ip_len = htons(sizeof(struct udphdr) + udp_payload_len);
        udp_ph.udp6_ph.proto  = ip6h->ip6_nxt;
    } else {
        return -EAFNOSUPPORT;
    }

    /* UDP header */

    if (udp_offset <= 0)
        return -EINVAL;

    struct udphdr *udp_hdr = (void *) (datagram + udp_offset);
    memset(udp_hdr, 0, sizeof(struct udphdr));
    udp_hdr->source = nbo_src_port;
    udp_hdr->dest   = nbo_dst_port;
    udp_hdr->len    = htons(udp_payload_len + sizeof(struct udphdr));
    udp_hdr->check  = 0;

    /* partial checksum, RFC1624 */
    uint16_t ph_csum = nbo_inet_csum(&udp_ph, udp_ph_len, 0);
    udp_hdr->check = nbo_inet_csum(udp_hdr, sizeof(udp_hdr), ph_csum);

    /* RFC 768: all zeros means not-calculated cksum, so a real csum of
     * all-zeroes should be transmitted as all-ones
     * Note: one's complement math, so 0xffff (-0) == 0x0000 (+0) */
    if (!udp_hdr->check)
        udp_hdr->check = 0xffff;

    if (pudp)
        *pudp = udp_hdr;
    if (ppayload)
        *ppayload = (udp_payload_len > 0)? datagram + udp_offset + sizeof(struct udphdr) : NULL;

    return (ssize_t) datagram_len;
}

static void sspoof_pkt_payload(uint8_t *payload, size_t payload_len,
                               const struct sspoof_sid * const sid,
                               const uint8_t flags,
                               const sockaddr_any_t_ * const saddr,
                               const struct sspoof_msmt_req * const mreq)
{
    struct sspoof_pkt_payload data = {};

    if (!payload)
        return;
    memset(payload, 0, payload_len);

    if (!mreq)
        return;

    /* we don't want to truncante the important data... */
    static_assert(sizeof(struct sspoof_pkt_payload) <= SSPOOF_MSMT_MIN_PAYLOADSZ);

    strncpy((char *)data.magic, SSPOOF_PKT_MAGIC, sizeof(data.magic)); /* 16 bytes */
    data.version = 1;
    data.flags = flags;
    data.grp_number = htonl((unsigned int)mreq->grp_sent);
    data.pkt_number = htonl((unsigned int)mreq->pkt_sent);

    data.ma_src_port = sockaddr_any_get_port_nbo(saddr);
    if (saddr->sa.sa_family == AF_INET) {
        memcpy(&data.ma_src_addr, &saddr->sin.sin_addr, sizeof(saddr->sin.sin_addr));
    } else {
        memcpy(&data.ma_src_addr, &saddr->sin6.sin6_addr, sizeof(saddr->sin6.sin6_addr));
    }

    data.sid_len = (sid->len <= sizeof(data.sid)) ? sid->len : sizeof(data.sid);
    memcpy(&data.sid, &sid->sid, data.sid_len);

    memcpy(payload, &data, (payload_len < sizeof(data))? payload_len : sizeof(data));
}

long sspoof_msmt_txpkt(struct sspoof_server * const sctx,
                       struct sspoof_msmt_ctx * const mctx,
                       struct sspoof_msmt_req * const mreq)
{
    uint8_t *payload = NULL;
    uint8_t pkt[SSPOOF_MSMT_MAX_PAYLOADSZ];

    sockaddr_any_t_ saddr, daddr;
    sockaddr_any_t_ spoofaddr;
    socklen_t daddr_len;
    ssize_t res;
    int rc;

    if (!sctx || !mctx || !mreq)
        return -EINVAL;

    if (mreq->payload_size < SSPOOF_MSMT_MIN_PAYLOADSZ
            || mreq->payload_size > SSPOOF_MSMT_MAX_PAYLOADSZ
            || mreq->payload_size > sizeof(pkt)) {
        return -EINVAL;
    }

    if (mreq->grp_sent >= mreq->pkt_group_count || mreq->pkt_group_count <= 0 || mreq->grp_sent < 0) {
        return LONG_MAX;
    }


    /* needs to send one packet, according to mreq->type plus whatever state
     * kept in mreq for bursts of mixed types, etc */

    /* FIXME: right now we just send either probe or spoof, one packet (burst 1),
     * and the time to next packet is the group time */

    memcpy(&saddr, &mctx->udp_sa_local, sizeof(saddr));
    memcpy(&daddr, &sctx->sa_peer, sizeof(daddr));

    switch (daddr.sa.sa_family) {
    case AF_INET:
        if (mreq->dst_port) {
            daddr.sin.sin_port = htons(mreq->dst_port);
        }
        daddr_len = sizeof(daddr.sin);
        break;
    case AF_INET6:
        if (mreq->dst_port) {
            daddr.sin6.sin6_port = htons(mreq->dst_port);
        }
        daddr_len = sizeof(daddr.sin6);
        break;
    default:
        return -EOPNOTSUPP;
    }

    switch (mreq->type) {
    case SSPOOF_MSMT_T_PROBE:
        sspoof_pkt_payload(pkt, mreq->payload_size, &sctx->sid, 0, &saddr, mreq);
        do {
            res = sendto(mctx->udpsocket, pkt, mreq->payload_size, MSG_DONTWAIT | MSG_NOSIGNAL, &daddr.sa, daddr_len);
        } while (res == -1 && errno == EINTR);
        if (res < 0) {
            print_warn("UDP probe packet: send failed: %s", strerror(errno));
        } else {
            packet_msg(MSG_DEBUG, sctx, "send: UDP probe packet %d", mreq->grp_sent);
        }

        /* probe does 1 packet per group, only */
        mreq->grp_sent++;
        rc = (mreq->grp_interval_us <= INT_MAX)? (int)mreq->grp_interval_us : INT_MAX;
        break;

    case SSPOOF_MSMT_T_SPOOFV1:
        /* packet pair: sentinel/probe ; spoof */

        /* even packets: sentinel/probe; odd packets: spoof v1 packet */
        const bool is_spoof = !!(mreq->pkt_sent & 1);

        memcpy(&spoofaddr, &saddr, sizeof(spoofaddr));

        if (is_spoof) {
            if (daddr.ss.ss_family == AF_INET6) {
                memcpy(&spoofaddr.sin6.sin6_addr, &mreq->prefix, sizeof(uint64_t));

                /* FIXME: apply mask, random host */
                spoofaddr.sin6.sin6_addr.s6_addr32[2] = 0;
                spoofaddr.sin6.sin6_addr.s6_addr32[3] = htonl(0x13);
            } else {
                memcpy(&spoofaddr.sin.sin_addr.s_addr, &mreq->prefix, sizeof(uint32_t));
                /* FIXME: apply mask, random host */
            }
        }

        struct udphdr *udp_hdr = NULL;
        ssize_t pkt_size = fill_udp46_hdr(pkt, 256, mreq->payload_size,
                                          mreq->ip_ttl, mreq->ip_traffic_class,
                                          &spoofaddr, &daddr, &udp_hdr, &payload);
        if (pkt_size <= 0) {
            rc = (int)pkt_size;
            print_err("unexpected failure: could not create RAW packet: %s", strerror(rc));
            goto close_exit;
        }

        sspoof_pkt_payload(payload, mreq->payload_size, &sctx->sid,
                SSPOOF_PKT_F_RAW | ((is_spoof)? SSPOOF_PKT_F_SRCSPOOF : 0),
                &spoofaddr, mreq);
        if (udp_hdr)
            udp_hdr->check = nbo_inet_csum(payload, mreq->payload_size, udp_hdr->check);

        /* Recommended for Linux IPPROTO_RAW: destination sockaddr's source port was to be
         * used as protocol (no longer works like that since Linux 2.2), and must be zero */
        if (daddr.sa.sa_family == AF_INET) {
            daddr.sin.sin_port = 0;
        } else {
            daddr.sin6.sin6_port = 0;
        }

        do {
            res = sendto(sctx->rawsock, pkt, (size_t)pkt_size, 0, &daddr.sa, daddr_len);
        } while (res == -1 && errno == EINTR);
        if (res < 0) {
            print_warn("UDP spoofed packet (RAW socket): send failed: %s", strerror(errno));
        } else {
            packet_msg(MSG_DEBUG, sctx, "send: UDP %s packet %d, %d",
                    is_spoof ? "spoofed" : "sentinel",
                    mreq->grp_sent, mreq->pkt_sent);
        }

        /* sent a packet... */
        mreq->pkt_sent++;

        if (mreq->pkt_sent >= 2) {
            /* start new group, note: assumes group of 2 packets in rc calculation */
            mreq->grp_sent++;
            mreq->pkt_sent = 0;
            rc = (mreq->grp_interval_us <= INT_MAX)? (int)(mreq->grp_interval_us - mreq->pkt_interval_us) : INT_MAX;
        } else {
            rc = (mreq->pkt_interval_us <= INT_MAX)? (int)mreq->pkt_interval_us : INT_MAX;
        }
        break;
    default:
        return -EOPNOTSUPP;
    }

close_exit:
    return rc;
}

/* vim: set et ts=8 sw=4 : */
