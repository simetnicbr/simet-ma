/*
 * SIMET-MA hashing helpers
 * Copyright (c) 2026 NIC.br <medicoes@simet.nic.br>
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
#define SEXIT_NODATA SEXIT_FAILURE

#define MAX_INPUT_STR_LEN (65536)

static int output_sha(const SHA256_DIGEST * const digest)
{
    char outbuf[64]; /* Enough for base64 of 256-bit value */

    memset(outbuf, 0, sizeof(outbuf)); /* not really needed */
    ssize_t outsz = base64safe_encode((void *)digest, SHA256_DIGEST_LENGTH, (void *)outbuf, sizeof(outbuf), 0);
    if (outsz != 43) { /* base64 encoding of 32 bytes, no padding */
        print_err("internal error during base64 encoding");
        exit(SEXIT_TMP_FAILURE);
    }
    int res = fprintf(stdout, "%.*s\n", (int)outsz, outbuf);
    return (res != (outsz + 1)) ? -1 : 0;
}

static int simet_do_hash(const char * const s)
{
    SHA256_DIGEST digest;
    SHA256_CTX shactx;

    if (!s || !(*s)) {
        print_err("input string empty");
        return SEXIT_FAILURE;
    }

    size_t len = strnlen(s, MAX_INPUT_STR_LEN);
    if (len >= MAX_INPUT_STR_LEN) {
        print_err("input string too long");
        return SEXIT_FAILURE;
    }

    SHA256_Init(&shactx);
    SHA256_Update(&shactx, s, len);
    SHA256_Final(digest, &shactx);

    if (output_sha(&digest)) {
        return SEXIT_FAILURE;
    }
    return SEXIT_SUCCESS;
}

static int simet_do_hash_fd(int fd, const char * const fn)
{
    SHA256_DIGEST digest;
    SHA256_CTX shactx;
	uint8_t io_buf[SHA256_BLKSIZE];
	ssize_t res = 0;
    size_t  size = 0;

    if (fd < 0) {
        print_err("internal error: invalid fd");
        return SEXIT_FAILURE;
    }

    SHA256_Init(&shactx);
	memset(io_buf, 0, SHA256_BLKSIZE);
	do {
	    res = read(fd, &io_buf, sizeof(io_buf));
	    if (res > 0) {
	        SHA256_Update(&shactx, &io_buf, (size_t)res);
            size += (size_t)res; /* verified res>0 */
	    }
	} while (res > 0 || (res == -1 && (errno == EINTR || errno == EAGAIN)));
	if (res < 0) {
        res = errno;
        print_err("sha256: %s read failed: %s", fn, strerror(res));
	    return SEXIT_FAILURE;
	} else if (size <= 0) {
        print_err("sha256: %s: no data to hash", fn);
        return SEXIT_FAILURE;
    }
	SHA256_Final(digest, &shactx);

    if (output_sha(&digest)) {
        return SEXIT_FAILURE;
    }
    return SEXIT_SUCCESS;
}

static int simet_do_hash_stdin(void)
{
    return simet_do_hash_fd(STDIN_FILENO, "stdin");
}

static int simet_do_hash_file(const char * const fn)
{
    if (!fn || !(*fn)) {
        print_err("missing file name");
        return SEXIT_FAILURE;
    }

    if (fn[0] == '-' && fn[1] == '\0') {
        return simet_do_hash_stdin();
    }

    int fd = open(fn, O_RDONLY);
    if (fd < 0) {
        print_err("open failed: %s", strerror(errno));
        return SEXIT_FAILURE;
    }
    int res = simet_do_hash_fd(fd, fn);
    close(fd);
    return res;
}


/*
 * Command line and main executable
 */

static const char program_copyright[]=
    "Copyright (c) 2026 NIC.br\n\n"
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
    fprintf(stderr, "Usage: %s [-q][-v][-h][-V] [[-s <string to hash>] | <path>]\n", p);

    if (mode) {
        fprintf(stderr, "\n"
            "\t-h\tprint usage help and exit\n"
            "\t-V\tprint program version and copyright, and exit\n"
            "\t-v\tverbose mode (does nothing)\n"
            "\t-q\tquiet mode (does nothing)\n"
            "\n"
            "\t-s\thash <string>, max %zu bytes\n"
            "\n"
            "Reads input data from stdin if neither -s or <path> are specified,\n"
            "or from file at <path> otherwise.  '-' as <path> means stdin as well.\n"
            "Empty string/file/stdin will be rejected with an error\n",
            (size_t)MAX_INPUT_STR_LEN - 1);
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

    if (is_valid_fd(fd)) {
            return;
    }

    nfd = open("/dev/null", fl);
    if (nfd == -1 || dup2(nfd, fd) == -1) {
            print_err("could not attach /dev/null to file descriptor %d: %s",
                      fd, strerror(errno));
            /* if (nfd != -1) close(nfd); - disabled as we're going to exit() now */
            exit(SEXIT_FAILURE);
    }
    if (nfd != fd) {
            close(nfd);
    }
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
    const char *input_string = NULL;

    sanitize_std_fds();

    int option;
    while ((option = getopt (argc, argv, "vqhVs:")) != -1) {
        switch (option) {
        case 'v':
            break;
        case 'q':
            break;
        case 's':
            if (input_string) {
                print_err("-s can be used only once");
                print_usage(progname, 0);
                /* not reached */
            } else {
                if (optarg) {
                    input_string = strdup(optarg);
                }
            }
            break;
        case 'h':
            print_usage(progname, 1);
            /* not reached */
            /* fall-through */
        case 'V':
            print_version();
            /* fall-through */
        default:
            print_usage(progname, 0);
        }
    };

    const int nargs = argc - optind;
    int res = SEXIT_NODATA;

    if (input_string) {
        if (nargs > 0) {
            print_err("cannot combine -s and FILEs");
            return SEXIT_FAILURE;
        }
        res = simet_do_hash(input_string);
    } else if (nargs <= 0) {
        /* no FILE arguments */
        res = simet_do_hash_stdin();
    } else if (nargs == 1) {
        /* single FILE argument */
        res = simet_do_hash_file(argv[optind]);
    } else {
        /* too many arguments */
        print_usage(progname, 0);
        /* not-reached */
    }

    return res;
}

/* vim: set et ts=4 sw=4 : */
