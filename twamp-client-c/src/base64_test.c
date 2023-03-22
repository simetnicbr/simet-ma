/*
 * Base64 encoding/decoding (RFC4648) - quick-and-dirty unit test
 * Copyright (c) 2023 NIC.br
 *
 * This software may be distributed under the terms of the BSD license.
 */

#include "base64.h"

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

static void b64_test_vector(const char* raw, const char* b64enc, ssize_t expected_res)
{
    char buf[32];

    if (!raw)
	raw = "";
    if (!b64enc)
	b64enc = "";

    /* decode test */
    size_t out_len = raw ? strlen(raw) : 0;
    if (out_len + 1 > sizeof(buf)) {
	fprintf(stderr, "internal error: raw test vector too large for buffer\n");
	exit(EXIT_FAILURE);
    }

    if (expected_res >= 0) {
	fprintf(stdout, "testing base64_decode(input='%s', input_len='%zu', desired_output='%s', max_output_len='%zu', desired_result='%zu')...\n",
		b64enc, strlen(b64enc), raw, out_len, expected_res);
    } else {
	fprintf(stdout, "testing base64_decode(input='%s', input_len='%zu', desired_output='%s', max_output_len='%zu', desired_error='%s')...\n",
		b64enc, strlen(b64enc), raw, out_len, strerror(-expected_res));
    }

    ssize_t res = base64_decode(b64enc, strlen(b64enc), (void *)buf, out_len);
    if (expected_res != res) {
	if (res < 0) {
	    fprintf(stderr, "base64_decode: failed with an unexpected error: %s\n", strerror(-res));
	    exit(EXIT_FAILURE);
	} else if (expected_res < 0) {
	    buf[out_len] = '\0';
	    fprintf(stderr, "base64_decode: expected an error, but got output='%s', len=%zu\n",
		    buf, res);
	    exit(EXIT_FAILURE);
	} else {
	    buf[out_len] = '\0';
	    fprintf(stderr, "base64_decode: incorrect output length: output='%s', len=%zu\n",
		    buf, res);
	    exit(EXIT_FAILURE);
	}
    }
    if (res > 0 && strncmp(raw, buf, res)) {
	fprintf(stderr, "base64_decode: result mismatch, expected '%s', got '%s'\n",
	    raw, buf);
	exit(EXIT_FAILURE);
    }
}

int main(void)
{
    /* RFC-4648 test vectors */
    b64_test_vector("",		"",		0);
    b64_test_vector("f",	"Zg==",		1);
    b64_test_vector("fo",	"Zm8=",		2);
    b64_test_vector("foo",	"Zm9v",		3);
    b64_test_vector("foob",	"Zm9vYg==",	4);
    b64_test_vector("fooba",    "Zm9vYmE=",	5);
    b64_test_vector("foobar",	"Zm9vYmFy",	6);

    /* Output size calculation versus padding */
    b64_test_vector("",		"Zg==",		-ENOSPC);
    b64_test_vector("",		"Zm8=",		-ENOSPC);
    b64_test_vector("f",	"Zm8=",		-ENOSPC);
    b64_test_vector("",		"Zm9v",		-ENOSPC);
    b64_test_vector("f",	"Zm9v",		-ENOSPC);
    b64_test_vector("fo",	"Zm9v",		-ENOSPC);
    b64_test_vector("fo",	"Zm9vYg==",	-ENOSPC);
    b64_test_vector("foo",	"Zm9vYg==",	-ENOSPC);
    b64_test_vector("foo",      "Zm9vYmE=",	-ENOSPC);
    b64_test_vector("foob",     "Zm9vYmE=",	-ENOSPC);

    /* Incorrect padding */
    b64_test_vector("foobar00", "Zm9vYmFy=",	-EINVAL);
    b64_test_vector("foobar00",	"Zm9vYmFy==",	-EINVAL);
    b64_test_vector("foobar00", "Zm9vYmFy=Z=",	-EINVAL);
    b64_test_vector("foobar00", "Zm9vYmFy====",	-EINVAL);

    /* Incorrect alphabet in normal cluster */
    b64_test_vector("foobar",	"!m9vYmFy",	-EINVAL);
    b64_test_vector("foobar",	"Z!9vYmFy",	-EINVAL);
    b64_test_vector("foobar",	"Zm!vYmFy",	-EINVAL);
    b64_test_vector("foobar",	"Zm9!YmFy",	-EINVAL);

    /* Incorrect alphabet in padding cluster */
    b64_test_vector("fooba",    "Zm9v!mE=",	-EINVAL);
    b64_test_vector("fooba",    "Zm9vY!E=",	-EINVAL);
    b64_test_vector("fooba",    "Zm9vYm!=",	-EINVAL);
    b64_test_vector("fooba",    "Zm9vY!==",	-EINVAL);
    b64_test_vector("fooba",    "Zm9v!m==",	-EINVAL);

    /* Misuse of padding character */
    b64_test_vector("012",	"Z",		-EINVAL);
    b64_test_vector("012",	"ZZ",		-EINVAL);
    b64_test_vector("012",	"ZZZ",		-EINVAL);
    b64_test_vector("012",	"=ZZ=",		-EINVAL);
    b64_test_vector("012",	"Z=Z=",		-EINVAL);

    /* FIXME: full alphabet, base64-safe x base64 */
}
