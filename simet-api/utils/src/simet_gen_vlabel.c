/*
 * SIMET2 MA Internet Availability Measurement vlabel generator
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

#include "simet-api-utils_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>

#include <limits.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>

#include <assert.h>
#if !defined(static_assert) && defined(__STDC_VERSION__) && (__STDC_VERSION__ < 202301L)
#  define static_assert _Static_assert
#endif

#include <fcntl.h>

#include "sha256.h"
#include "crc16.h"
#include "base64.h"

const char *progname = PACKAGE_NAME;

#define print_msg_u(format, arg...) \
    do { fflush(stdout); fprintf(stderr, "%s: " format "\n", progname, ## arg); } while (0)

#define print_err(format, arg...) \
    do { fflush(stdout); fprintf(stderr, "%s: error: " format "\n", progname, ## arg); } while (0)

#define print_warn(format, arg...) \
    do { fflush(stdout); fprintf(stderr, "%s: warning: " format "\n", progname, ## arg); } while (0)

#define print_errno(format, arg...) \
    do { int e = errno; fflush(stdout); fprintf(stderr, "%s: error: " format ": %s\n", progname, ## arg, strerror(e)); } while (0)

#define SEXIT_SUCCESS (0)
#define SEXIT_FAILURE (1)
#define SEXIT_TMP_FAILURE (2)
#define SEXIT_BADCMDLINE SEXIT_FAILURE

/*
 * Vlabel N0 format
 */

static int hmac_sha256_selftest(void)
{
    uint8_t t1[20];
    uint8_t d1[50];
    SHA256_DIGEST digest = { 0 };

    /* RFC4867 test case PRF-3 */
    memset(t1, 0xaa, 20);
    memset(d1, 0xdd, 50);
    HMAC_SHA256(digest, t1, 20, d1, 50);
    if (memcmp(digest, (uint8_t[SHA256_DIGEST_LENGTH]){ 0x77,0x3e,0xa9,0x1e,0x36,0x80,0x0e,0x46,0x85,0x4d,0xb8,0xeb,0xd0,0x91,0x81,0xa7, 0x29,0x59,0x09,0x8b,0x3e,0xf8,0xc1,0x22,0xd9,0x63,0x55,0x14,0xce,0xd5,0x65,0xfe }, SHA256_DIGEST_LENGTH))
        return 1;

    memcpy(t1, "Jefe", 4);
    memcpy(d1, "what do ya want for nothing?", 28);
    HMAC_SHA256(digest, t1, 4, d1, 28);
    if (memcmp(digest, (uint8_t[SHA256_DIGEST_LENGTH]){ 0x5b,0xdc,0xc1,0x46,0xbf,0x60,0x75,0x4e,0x6a,0x04,0x24,0x26,0x08,0x95,0x75,0xc7, 0x5a,0x00,0x3f,0x08,0x9d,0x27,0x39,0x83,0x9d,0xec,0x58,0xb9,0x64,0xec,0x38,0x43 }, SHA256_DIGEST_LENGTH))
        return 1;
    return 0;
}

static int simet_do_vlN0(const char *seed)
{
    if (!seed) {
        print_err("N0: missing salt paremeter");
        return SEXIT_FAILURE;
    }
    if (strlen(seed) < 4) {
        print_err("N0: seed is too short");
        return SEXIT_FAILURE;
    }

    /* fast self tests */
    if (crc_16("123456789", 9) != 0xbb3dU) {
        print_err("N0: CRC-16 self-test failed");
        return SEXIT_FAILURE;
    }
    if (hmac_sha256_selftest()) {
        print_err("N0: HMAC-SHA-256 self-test failed");
        return SEXIT_FAILURE;
    }

    SHA256_DIGEST digest;
    if (HMAC_SHA256_from_fd(digest, (void*)seed, strlen(seed), STDIN_FILENO)) {
            print_errno("N0: failed to read data from stdin");
            return SEXIT_TMP_FAILURE;
    }

    /* N0 format:
     * "N0" BASE64_URL(<key> .. CRC16(<key>)), where key has 16 bytes
     * CRC16 is stored in network byte order.
     */
    unsigned int crc = crc_16((void *)&digest, 16);
    digest[16] = (crc >> 8) & 0xffU;
    digest[17] = crc & 0xffU;

    char outbuf[32];
    ssize_t outsz = base64safe_encode((void *)&digest, 18, (void *)outbuf, sizeof(outbuf));
    if (outsz < 24 || outsz > INT_MAX) {
        print_err("N0: internal error, failed to encode to base64-safe");
        return SEXIT_FAILURE;
    }
    fprintf(stdout, "N0%.*s\n", (int) outsz, outbuf);

    return SEXIT_SUCCESS;
}

/*
 * Command line and main executable
 */

static const char program_copyright[]=
    "Copyright (c) 2024 NIC.br\n\n"
    "This is free software; see the source for copying conditions.\n"
    "There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR\n"
    "A PARTICULAR PURPOSE.\n";

static void print_version(void)
{
    fprintf(stdout, "%s %s\n%s\n", PACKAGE_NAME, PACKAGE_VERSION, program_copyright);
    exit(SEXIT_SUCCESS);
}

static void print_usage(const char * const p, int mode) __attribute__((__noreturn__));
static void print_usage(const char * const p, int mode)
{
    fprintf(stderr, "Usage: %s [-q][-v][-h][-V] <format> <parameters...>\n", p);

    if (mode) {
        fprintf(stderr, "\n"
            "\t-h\tprint usage help and exit\n"
            "\t-V\tprint program version and copyright, and exit\n"
            "\t-v\tverbose mode (does nothing)\n"
            "\t-q\tquiet mode (does nothing)\n"
            "\n"
            "Formats:\n"
            "\tN0\tstdin: secret (16 bytes+), parameter: salt (string)"
            "\n");
    }

    exit((mode)? SEXIT_SUCCESS : SEXIT_BADCMDLINE);
}

static int is_valid_fd(const int fd)
{
    return fcntl(fd, F_GETFD) != -1 || errno != EBADF;
}

static void fix_fds(const int fd, const int fl)
{
    int nfd;

    if (is_valid_fd(fd))
            return;

    nfd = open("/dev/null", fl);
    if (nfd == -1 || dup2(nfd, fd) == -1) {
            print_err("could not attach /dev/null to file descriptor %d: %s",
                      fd, strerror(errno));
            /* if (nfd != -1) close(nfd); - disabled as we're going to exit() now */
            exit(SEXIT_FAILURE);
    }
    if (nfd != fd)
            close(nfd);
}

static void sanitize_std_fds(void)
{
   /* do it in file descriptor numerical order! */
   fix_fds(STDIN_FILENO,  O_RDONLY);
   fix_fds(STDOUT_FILENO, O_WRONLY);
   fix_fds(STDERR_FILENO, O_RDWR);
}

int main(int argc, char **argv) {
    progname = argv[0];
    sanitize_std_fds();

    int option;
    while ((option = getopt (argc, argv, "vqhV")) != -1) {
        switch (option) {
        case 'v':
            break;
        case 'q':
            break;
        case 'h':
            print_usage(progname, 1);
            /* fall-through */
        case 'V':
            print_version();
            /* fall-through */
        default:
            print_usage(progname, 0);
        }
    };

    if (optind >= argc || !argv[optind])
        print_usage(progname, 0);

    if (!strcmp("N0", argv[optind])) {
        optind++;
        return simet_do_vlN0((optind < argc)? argv[optind] : NULL);
    }

    print_err("Unsupported format: %s", argv[optind]);
    return SEXIT_FAILURE;
}

/* vim: set et ts=4 sw=4 : */
