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
 * globals
 */

unsigned int  opt_keylen = 0; /* key length, 0 = default */
long int      opt_par_n = 0;  /* -n <value>, 0 = default */

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

static int pbkdf2_selftest(void)
{
    uint8_t k[SHA256_BLKSIZE];
    if (pbkdf2_hmac_sha256((void *)"passwd", 6, (void *)"salt", 4, 1, k, sizeof(k)))
        return -1;
    if (memcmp(k, (uint8_t[SHA256_BLKSIZE]){
                0x55, 0xac, 0x04, 0x6e, 0x56, 0xe3, 0x08, 0x9f, 0xec, 0x16, 0x91, 0xc2, 0x25, 0x44, 0xb6, 0x05,
                0xf9, 0x41, 0x85, 0x21, 0x6d, 0xde, 0x04, 0x65, 0xe6, 0x8b, 0x9d, 0x57, 0xc2, 0x0d, 0xac, 0xbc,
                0x49, 0xca, 0x9c, 0xcc, 0xf1, 0x79, 0xb6, 0x45, 0x99, 0x16, 0x64, 0xb3, 0x9d, 0x77, 0xef, 0x31,
                0x7c, 0x71, 0xb8, 0x45, 0xb1, 0xe3, 0x0b, 0xd5, 0x09, 0x11, 0x20, 0x41, 0xd3, 0xa1, 0x97, 0x83
            }, SHA256_BLKSIZE))
        return -1;
    if (pbkdf2_hmac_sha256((void *)"passwd", 6, (void *)"salt", 4, 2, k, sizeof(k)))
        return -1;
    if (memcmp(k, (uint8_t[SHA256_BLKSIZE]){
                0x2d, 0x41, 0x2f, 0x89, 0x6e, 0x76, 0x68, 0x5e, 0x30, 0xdf, 0x56, 0x9f, 0x0a, 0x74, 0x06, 0x34,
                0xe3, 0x1f, 0x03, 0x1f, 0x74, 0x9d, 0x60, 0x7d, 0x9e, 0x44, 0x21, 0x0b, 0xff, 0xb9, 0x1a, 0x6a,
                0xb6, 0x70, 0xf5, 0x00, 0xc7, 0x88, 0x62, 0x00, 0x19, 0x59, 0xf7, 0xd7, 0xb9, 0xf9, 0x6a, 0xfb,
                0x36, 0x05, 0x70, 0x02, 0x98, 0xac, 0xb1, 0x44, 0x27, 0xe0, 0x23, 0x94, 0x63, 0xc6, 0x6f, 0x20
            }, SHA256_BLKSIZE))
        return -1;
#if 0 /* too slow */
    if (pbkdf2_hmac_sha256((void *)"Password", 8, (void *)"NaCl", 4, 80000, k, sizeof(k)))
        return -1;
    if (memcmp(k, (uint8_t[SHA256_BLKSIZE]){
                0x4d, 0xdc, 0xd8, 0xf6, 0x0b, 0x98, 0xbe, 0x21, 0x83, 0x0c, 0xee, 0x5e, 0xf2, 0x27, 0x01, 0xf9,
                0x64, 0x1a, 0x44, 0x18, 0xd0, 0x4c, 0x04, 0x14, 0xae, 0xff, 0x08, 0x87, 0x6b, 0x34, 0xab, 0x56,
                0xa1, 0xd4, 0x25, 0xa1, 0x22, 0x58, 0x33, 0x54, 0x9a, 0xdb, 0x84, 0x1b, 0x51, 0xc9, 0xb3, 0x17,
                0x6a, 0x27, 0x2b, 0xde, 0xbb, 0xa1, 0xd0, 0x78, 0x47, 0x8f, 0x62, 0xb3, 0x97, 0xf3, 0x3c, 0x8d
            }, SHA256_BLKSIZE))
        return -1;
#endif
    return 0;
}

#define MAX_N0_KEYLEN SHA256_DIGEST_LENGTH

static int simet_do_vlN0(const char *seed, unsigned int keylen, uint32_t iteractions)
{
    if (!seed) {
        print_err("N0: missing salt paremeter");
        return SEXIT_FAILURE;
    }
    if (strlen(seed) < 4) {
        print_err("N0: seed is too short");
        return SEXIT_FAILURE;
    }
    if (keylen < 16 || keylen > MAX_N0_KEYLEN) {
        print_err("N0: unsupported key length");
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
    if (pbkdf2_selftest()) {
        print_err("N0: PBKDF2-HMAC-SHA-256 self-test failed");
        return SEXIT_FAILURE;
    }

    SHA256_DIGEST digest;
    if (HMAC_SHA256_from_fd(digest, (void*)seed, strlen(seed), STDIN_FILENO)) {
        print_errno("N0: failed to read data from stdin");
        return SEXIT_TMP_FAILURE;
    }

    uint8_t keyout[MAX_N0_KEYLEN + 2]; /* hash[0..keylen] + CRC16 */
    if (pbkdf2_hmac_sha256(digest, sizeof(digest), (void *)seed, strlen(seed), iteractions, keyout, sizeof(keyout))) {
        print_err("N0: internal error calling pbkdf2_hmac_sha256");
        return SEXIT_TMP_FAILURE;
    }

    /* N0 format:
     * "N0" BASE64_URL(<key> .. CRC16(<key>)), where key has 16 bytes
     * CRC16 is stored in network byte order.
     * Base64 padding removed.
     */
    unsigned int crc = crc_16((void *)&keyout, keylen);
    keyout[keylen]     = (crc >> 8) & 0xffU;
    keyout[keylen + 1] = crc & 0xffU;

    char outbuf[50]; /* Enough for base64 of 256-bit value, plus 16-bit CRC */
    ssize_t outsz = base64safe_encode((void *)&keyout, keylen + 2, (void *)outbuf, sizeof(outbuf), 1);
    if (outsz < 24 || outsz >= 50) {
        print_err("N0: internal error during base64 encoding");
        exit(SEXIT_TMP_FAILURE);
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
            "\t-l\tkey length (bits), 0 = default, 128 minimum\n"
            "\t-n\t(depends on format)\n"
            "\n"
            "Formats:\n"
            "\tN0\tstdin: secret (length >= 16)\n"
            "\t\tparameter: salt (string)\n"
            "\t\t-n: number of iterations (PBKDF2)\n"
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
    while ((option = getopt (argc, argv, "vqhVn:l:")) != -1) {
        switch (option) {
        case 'v':
            break;
        case 'q':
            break;
        case 'l':
            if (optarg) {
                opt_keylen = (unsigned int)atoi(optarg);
                if (opt_keylen < 128 || opt_keylen > 256) {
                    print_err("Unsupported key length");
                    exit(SEXIT_TMP_FAILURE);
                }
            }
            break;
        case 'n':
            if (optarg) {
                opt_par_n = atol(optarg);
            }
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

    const char *mode = argv[optind];
    optind++;

    if (!strcmp("N0", mode)) {
        uint32_t iterations = 10000;
        unsigned int keylen = 16;

        if (opt_keylen != 0) {
            if (opt_keylen < 128 || opt_keylen > 256) {
                print_err("N0: key length must be between 128 and 256 bits");
                exit(SEXIT_TMP_FAILURE);
            }
            keylen = (opt_keylen + 7) / 8;
        }

        if (opt_par_n != 0) {
            if (opt_par_n < 1000 || opt_par_n > UINT32_MAX) {
                print_err("N0: number of iterations bust be between 1000 and %u", UINT32_MAX);
                exit(SEXIT_TMP_FAILURE);
            }
            iterations = (uint32_t)opt_par_n; /* safe, [1000..UINT32_MAX] */
        }
        return simet_do_vlN0((optind < argc)? argv[optind] : NULL, keylen, iterations);
    }

    print_err("Unsupported format: %s", argv[optind]);
    return SEXIT_FAILURE;
}

/* vim: set et ts=4 sw=4 : */
