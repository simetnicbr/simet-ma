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
