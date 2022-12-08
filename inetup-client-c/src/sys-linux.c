/*
 * Copyright (c) 2020 NIC.br <medicoes@simet.nic.br>
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

#ifdef __linux__

#include "simet-inetuptime_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <assert.h>
#include <errno.h>

#include <string.h>
#include <ctype.h>
#include <limits.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifdef HAVE_SYS_SYSINFO_H
#include <sys/sysinfo.h>
#endif

#include "simet-inetuptime.h"
#include "simet_err.h"
#include "logger.h"

#include "sys-linux.h"

#define LINUX_NETDEVSTAT_FMT "/sys/class/net/%s/statistics/%s"
#define LINUX_NETDEVSTAT_TX  "tx_bytes"
#define LINUX_NETDEVSTAT_RX  "rx_bytes"
#define LINUX_NETDEVSTAT_MAX 1024

struct netdev_ctx {
    const char *devname;
    const char *tx_fname;
    const char *rx_fname;
    uint64_t last_rx;
    uint64_t last_tx;
    int rollover_32bits;
};

/*
 * SYSFS
 */

#define SYSFS_BUF_SZ 1024

static int sysfs_read_uint64(const char * const path, uint64_t * const value)
{
    int fd;
    int e;
    char *c;
    ssize_t s;
    uint64_t result;
    char buf[SYSFS_BUF_SZ];

    if (!value)
        return 0;
    if (!path)
        return -EINVAL;

    fd = open(path, O_CLOEXEC | O_RDONLY);
    if (fd == -1)
        return -errno;

    do {
        s = read(fd, buf, SYSFS_BUF_SZ);
    e = errno;
    } while (s == -1 && e == EINTR);

    close(fd);

    if (s < 0)
        return -e;
    if (s >= SYSFS_BUF_SZ)
    return -ENOTSUP;
    buf[s] = 0;

    errno = 0;
    result = strtoull(buf, &c, 10);
    if (errno != 0)
    return -errno;
    if ((c == buf) || (c && *c && !isspace(*c)))
    return -ENOTSUP;

    *value = (uint64_t) result;
    return 0;
}

/* os_netdev */

/* avoid bypassing the type system without hard-to-understand tricks */
static inline void free_constchar(const char *p) { free ((void *)p); }

static int xx_os_read_netdev_counters(uint64_t *tx_bytes, uint64_t *rx_bytes,
        const char * const tx_fn, const char * const rx_fn)
{
    uint64_t tx, rx;
    int rc;

    if (!tx_bytes || !rx_bytes || !tx_fn || !rx_fn)
        return -EINVAL;

    rc = sysfs_read_uint64(rx_fn, &rx);
    if (rc)
        return rc;
    rc = sysfs_read_uint64(tx_fn, &tx);
    if (rc)
        return rc;

    *tx_bytes = tx;
    *rx_bytes = rx;
    return 0;
}

int os_get_netdev_counters(uint64_t *tx_bytes, uint64_t *rx_bytes, void * const netdev_ctx)
{
    struct netdev_ctx * const ctx = netdev_ctx;
    if (!ctx)
        return -EINVAL;
    return xx_os_read_netdev_counters(tx_bytes, rx_bytes, ctx->tx_fname, ctx->rx_fname);
}

int os_netdev_change(const char * const netdev_name, void *netdev_ctx)
{
    struct netdev_ctx *ctx = netdev_ctx;
    char *tx_fn = NULL;
    char *rx_fn = NULL;
    char *n_dev = NULL;
    uint64_t tx, rx;
    int rc;
    char s[LINUX_NETDEVSTAT_MAX];

    if (!ctx || !netdev_name)
        return -EINVAL;

    if (ctx->devname && !strcmp(ctx->devname, netdev_name))
        return 1; /* same device, do nothing */

    snprintf(s, sizeof(s), LINUX_NETDEVSTAT_FMT, netdev_name, LINUX_NETDEVSTAT_TX);
    tx_fn = strndup(s, sizeof(s));
    snprintf(s, sizeof(s), LINUX_NETDEVSTAT_FMT, netdev_name, LINUX_NETDEVSTAT_RX);
    rx_fn = strndup(s, sizeof(s));
    n_dev = strdup(netdev_name);

    if (tx_fn && rx_fn && n_dev) {
        rc = xx_os_read_netdev_counters(&tx, &rx, tx_fn, rx_fn);
    } else {
        rc = -ENOMEM;
    }

    if (!rc) {
        free_constchar(ctx->devname);
        free_constchar(ctx->tx_fname);
        free_constchar(ctx->rx_fname);
        ctx->devname = n_dev;
        ctx->tx_fname = tx_fn;
        ctx->rx_fname = rx_fn;
    } else {
        free(tx_fn);
        free(rx_fn);
        free(n_dev);
    }
    return rc;
}

int os_netdev_init(const char * const netdev_name, void **netdev_ctx)
{
    struct netdev_ctx *ctx;
    int rc;

    if (!netdev_ctx || !netdev_name)
        return -EINVAL;

    ctx = malloc(sizeof(struct netdev_ctx));
    *netdev_ctx = ctx;
    if (!ctx)
        return -ENOMEM;
    memset(ctx, 0, sizeof(struct netdev_ctx));

    rc = os_netdev_change(netdev_name, ctx);
    if (rc < 0) {
        os_netdev_done(ctx);
        *netdev_ctx = NULL;
    }
    return (rc >= 0) ? 0 : rc;
}

void os_netdev_done(void *netdev_ctx)
{
    struct netdev_ctx * const ctx = netdev_ctx;

    if (ctx) {
        free_constchar(ctx->devname);
        free_constchar(ctx->tx_fname);
        free_constchar(ctx->rx_fname);
        free(ctx);
    }
}

#ifdef HAVE_SYS_SYSINFO_H
/* May wrap around INT32_MAX on 32-bit platforms! */
int os_seconds_since_boot(int64_t * const uptime)
{
    struct sysinfo si;

    if (!uptime || sysinfo(&si) != 0)
        return -EINVAL;

    *uptime = (si.uptime >= 0)? si.uptime : LONG_MAX;

    errno = 0;
    return 0;
}

#else

int os_seconds_since_boot(int64_t * const uptime)
{
    return (uptime)? -ENOTSUP : -EINVAL ;
}
#endif /* SYS/SYSINFO.H */


#endif /* __linux__ */

/* vim: set et ts=4 sw=4 : */
