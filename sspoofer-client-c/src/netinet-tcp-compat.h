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

#ifndef NETINET_TCP_COMPAT_H
#define NETINET_TCP_COMPAT_H

#include <netinet/tcp.h>

#ifdef __linux__
/*
 * Missing socket options in OpenWRT CC uClibc
 * (OpenWRT CC uses Linux kernel 3.18.109)
 */

/* tcp-thin supported since Linux 2.6.34 */
#ifndef TCP_THIN_LINEAR_TIMEOUTS
#define TCP_THIN_LINEAR_TIMEOUTS 16
#endif
#ifndef TCP_THIN_DUPACK
#define TCP_THIN_DUPACK  17
#endif

/* TCP user timeouts supported since Linux 2.6.37 */
#ifndef TCP_USER_TIMEOUT
#define TCP_USER_TIMEOUT 18
#endif

#endif /* __linux__ */
#endif /* NETINET_TCP_COMPAT_H */
