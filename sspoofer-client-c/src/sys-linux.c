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

#include "sspooferc_config.h"

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

#include "sys-linux.h"

/*
 * SYSFS
 */

#define SYSFS_BUF_SZ 1024

static int sysfs_read_uint64(const char * const path, uint64_t * const value) __attribute__((__unused__));
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

/* vim: set et ts=8 sw=4 : */
