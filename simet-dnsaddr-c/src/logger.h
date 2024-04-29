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

#ifndef LOGGER_H_
#define LOGGER_H_

#include <stdio.h>

extern int log_level; /* 0: errors; 1: quiet; 2: normal; 3: debug/verbose ; 4: trace */
extern const char *progname;

#define MSG_ALWAYS    0
#define MSG_IMPORTANT 1
#define MSG_NORMAL    2
#define MSG_DEBUG     3
#define MSG_TRACE     4

#define print_msg_u(format, arg...) \
    do { fflush(stdout); fprintf(stderr, "%s: " format "\n", progname, ## arg); } while (0)

#define print_msg(level, format, arg...) \
    do { \
        if (log_level >= (level)) { \
            fflush(stdout); \
            fprintf(stderr, "%s: " format "\n", progname, ## arg); \
        } \
    } while (0)

#define print_err(format, arg...) \
    do { fflush(stdout); fprintf(stderr, "%s: error: " format "\n", progname, ## arg); } while (0)

#define print_warn(format, arg...) \
    do { fflush(stdout); fprintf(stderr, "%s: warning: " format "\n", progname, ## arg); } while (0)

#endif /* LOGGER_H_ */
