/*
 * Common SIMET error codes for POSIX executables
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

#ifndef SIMET_ERR_H
#define SIMET_ERR_H

/* Succesful (measurement taken, output valid, and so on) */
#define SEXIT_SUCCESS  0

/*
 * Generic errors
 */

/* Generic failure, measurement not taken/invalid */
#define SEXIT_FAILURE       1

/* Command line error, invalid command line parameter */
#define SEXIT_BADCMDLINE    2

/* Generic internal error, such as illegal code flow or corruption detected */
#define SEXIT_INTERNALERR   3

/* Out of memory or other system resource (file handles, sockets...) */
#define SEXIT_OUTOFRESOURCE 4


/*
 * Network errors
 */

/* Address family not available for testing */
#define SEXIT_NOADDRFAMILY    10

/* No uplink/route/gateway available, generic connection error */
#define SEXIT_NETUNAVAILABLE  11

/* DNS error - includes DNSSEC-related */
#define SEXIT_DNSERR          12

/* Auth failure for fixed credential such as keys or certificates */
#define SEXIT_AUTHERR         13

/* Measurement Agent unregistered, or missing registration information */
#define SEXIT_MA_UNREGISTERED  20

/* Agent registration refused (generic reason) */
#define SEXIT_MA_REFUSED       21

/* SIMET essential services: connection refused or timed out */
#define SEXIT_SIMET_UNAVAIL    22

/* SIMET essential services: server returned an error code */
#define SEXIT_SIMET_SRVERR     23

/* Measurement peer refused connection */
#define SEXIT_MP_REFUSED       24

/* Measurement peer timed out */
#define SEXIT_MP_TIMEOUT       25

/* Measurement request denied (no measurement token, no servers) */
#define SEXIT_SIMET_NOMEASURE  26

/* Measurement control protocol error (generic),
 * e.g. *WAMP control, SIMET TCPBW control, etc */
#define SEXIT_CTRLPROT_ERR     30

/* Environment unstable (clock, network, temperture, cpu load, etc) */
#define SEXIT_ENVUNSTABLE      31

#endif /* SIMET_ERR_H */
