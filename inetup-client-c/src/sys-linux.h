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

#ifndef SIMET_SYSLINUX_H
#define SIMET_SYSLINUX_H

#include <stdint.h>
#include <stdbool.h>
#include <errno.h>

#ifdef __linux__

/*
 * Because gcc has been sitting on this since 2016.
 */
static bool is_EAGAIN_WOULDBLOCK(const int e) __attribute__((__unused__,__const__));
static bool is_EAGAIN_WOULDBLOCK(const int e)
{
#if defined(EAGAIN) && defined (EWOULDBLOCK) && (EAGAIN == EWOULDBLOCK)
    return (e == EAGAIN);
#else
    return (e == EAGAIN || e == EWOULDBLOCK);
#endif
}

/*
 * Notes:
 *
 * the contextes of this module are not not MT-safe, they will
 * require external locking if the same context is going to be used
 * concurrently.
 */

/* returns 1 if os_get_netdev_counters() is supported */
static int os_netdev_bytecount_supported(void) __attribute__((__unused__));
static int os_netdev_bytecount_supported(void) { return 1; }

/* allocates a context, returns 0 ok, -EINVAL/-ENOMEM otherwise */
int os_netdev_init(const char * const netdev_name, void **netdev_ctx);

/* changes the netdev to use, returns 0 ok, 1 no-change-needed, -errno otherwise */
int os_netdev_change(const char * const netdev_name, void *netdev_ctx);

/* frees a context, netdev_ctx can be NULL */
void os_netdev_done(void *netdev_ctx);

/* reads interface counters, returns 0 (ok) or -ERRNO */
int os_get_netdev_counters(uint64_t *tx_bytes, uint64_t *rx_bytes, void * const netdev_ctx);

/* Get the number of seconds since boot in *val, limited to LONG_MAX.
 * returns 0 if sucessful, -EINVAL or -ENOTSUP otherwise */
int os_seconds_since_boot(int64_t * const uptime);

#else

static int os_netdev_bytecount_supported(void) { return 0; }
static int os_netdev_init(const char * const netdev_name, void **netdev_ctx) { return -ENOTSUP; }
static int os_netdev_change(const char * const netdev_name, void *netdev_ctx) { return -ENOTSUP; }
static void os_netdev_done(void *netdev_ctx) { return };
static int os_get_netdev_counters(uint64_t *tx_bytes, uint64_t *rx_bytes, void * const netdev_ctx) { return -ENOTSUP; }
static int os_seconds_since_boot(int64_t * const uptime) { return (uptime)? -ENOTSUP : -EINVAL; }

#endif /* __linux__ */

#endif /* SIMET_INETUPTIME_H */
