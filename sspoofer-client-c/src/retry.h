/*
 * Retry macros for EINTR, EAGAIN, EWOULDBLOCK
 * Copyright (c) 2024 NIC.br <medicoes@simet.nic.br>
 *
 * SPDX-License-Identifier: BSD-3-CLAUSE
 */

#ifndef SRETRY_H_
#define SRETRY_H_

#include <errno.h>

#define MAXIMUM_SYSCALL_RETRIES 50
#define MAXIMUM_GAI_RETRIES 5

#define RETRY_EINTR(x) ({ \
    typeof(x) _r; \
    char _tries = MAXIMUM_SYSCALL_RETRIES; \
    do { \
        _r = (x); \
        } while (_r == -1 && errno == EINTR && (--_tries) > 0); \
    _r; \
})

#define RETRY_GAI(x) ({ \
    char _tries = MAXIMUM_GAI_RETRIES; \
    int _r; \
    do { \
        _r = (x); \
        } while (( (_r == EAI_SYSTEM && errno == EINTR) || (_r == EAI_AGAIN)) \
                 && (--_tries) > 0); \
    _r; \
})

#endif /* SRETRY_H_ */
/* vim: set et ts=8 sw=4 : */
