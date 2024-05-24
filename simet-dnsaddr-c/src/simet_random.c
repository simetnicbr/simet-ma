/*
 * SIMET2 MA - urandom access
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

#include "simet-dnsaddr_config.h"

#include <stdio.h>
#include <unistd.h>
#include <inttypes.h>

#include <fcntl.h>
#include <errno.h>

#ifdef HAVE_GETRANDOM
#include <sys/random.h>
#endif

#include "simet_random.h"

int simet_getrandom(void * const buf, size_t buf_len)
{
    uint8_t *ubuf = buf;
    ssize_t res = 0;

    if (!buf_len)
        return 0;

    if (!ubuf) {
        errno = EINVAL;
        return -1;
    }

#ifdef HAVE_GETRANDOM
    while (buf_len > 0) {
        res = getrandom(ubuf, buf_len, 0);
        if (res > 0) {
            buf_len -= (size_t)res; /* valid, res > 0 */
            ubuf += res;
        } else if (!res || (res == -1 && errno != EINTR)) {
            break;
        }
    }

    if (!buf_len) {
        return 0;
    } else if (res == -1 && errno != ENOSYS) {
        return -1; /* errno set */
    }
#endif

    const char * const randompath = SIMET_RANDOM_SOURCE;
    int rfd = open(randompath, O_RDONLY);
    if (rfd < 0) {
        return rfd; /* errno set */
    } else {
        errno = EAGAIN;
        while (buf_len > 0 && (errno == EINTR || errno == EAGAIN)) {
            res = read(rfd, ubuf, buf_len);
            if (res <= 0 || (size_t) res > buf_len) {
                /* should never happen, unless reading from a short file */
                break;
            }
            if (res > 0) {
                ubuf += (size_t) res;
                buf_len -= (size_t) res; /* res <= buf_len ensured above */
            }
        }
        close(rfd);
    }

    if (!buf_len) {
        return 0;
    }

    if (!errno) {
        errno = EIO;
    }
    return -1;
}

/* vim: set et ts=8 sw=4 : */
