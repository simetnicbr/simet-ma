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

#include <stdbool.h>

#define TEST_BUF_LEN 32

static void xx_b64_decode_test(const char * raw, const char * b64enc, size_t b64enc_len, ssize_t expected_res_decode, size_t outbuf_len)
{
    char buf[TEST_BUF_LEN] = { 0xff };

    if (!b64enc || (!raw && expected_res_decode > 0) || outbuf_len > sizeof(buf)) {
	fprintf(stderr, "internal error: inconsistent input parameter for b64_decode_test()");
	exit(EXIT_FAILURE);
    }

    /* decode test */
    size_t raw_len = (raw)? strlen(raw) : 0;
    if (raw_len + 1 > sizeof(buf)) {
	fprintf(stderr, "internal error: raw test vector too large for buffer\n");
	exit(EXIT_FAILURE);
    }

    if (expected_res_decode >= 0) {
	fprintf(stdout, "testing base64_decode(input='%.*s', input_len='%zu', desired_output='%s', max_output_len='%zu', desired_result='%zu')...\n",
		(int) b64enc_len, b64enc, b64enc_len, raw, outbuf_len, expected_res_decode);
    } else {
	fprintf(stdout, "testing base64_decode(input='%.*s', input_len='%zu', desired_output='%s', max_output_len='%zu', desired_error='%s')...\n",
		(int) b64enc_len, b64enc, b64enc_len, raw, outbuf_len, strerror(-expected_res_decode));
    }

    ssize_t res = base64_decode(b64enc, b64enc_len, (void *)buf, outbuf_len);
    if (expected_res_decode != res) {
	if (res < 0) {
	    fprintf(stderr, "base64_decode: failed with an unexpected error: %s\n", strerror(-res));
	    exit(EXIT_FAILURE);
	} else if (expected_res_decode < 0) {
	    buf[raw_len] = '\0';
	    fprintf(stderr, "base64_decode: expected an error, but got output='%s', len=%zu\n",
		    buf, res);
	    exit(EXIT_FAILURE);
	} else {
	    buf[raw_len] = '\0';
	    fprintf(stderr, "base64_decode: incorrect output length: output='%s', len=%zu\n",
		    buf, res);
	    exit(EXIT_FAILURE);
	}
    }
    if (res > 0 && raw && strncmp(raw, buf, res)) {
	fprintf(stderr, "base64_decode: result mismatch, expected '%s', got '%s'\n",
	    raw, buf);
	exit(EXIT_FAILURE);
    }
}

static void b64_decode_test(const char * raw, const char * b64enc, ssize_t expected_res_decode, size_t outbuf_len)
{
    size_t b64enc_len = (b64enc)? strlen(b64enc) : 0;

    xx_b64_decode_test(raw, b64enc, b64enc_len, expected_res_decode, outbuf_len);

    /* if the test vector had correct padding, redo without */
    /* remove at most two padding characters at end */
    if (b64enc_len >= 4 && b64enc_len % 4 == 0 && b64enc[b64enc_len-1] == '=') {
	b64enc_len--;
	if (b64enc[b64enc_len-1] == '=')
	    b64enc_len--;
	xx_b64_decode_test(raw, b64enc, b64enc_len, expected_res_decode, outbuf_len);
    }
}

static void xx_b64_encode_test(const char * raw, const char * b64enc, size_t b64enc_len, ssize_t expected_res_encode, size_t outbuf_len)
{
    char buf[TEST_BUF_LEN] = { 0xff };

    if (!raw || (!b64enc && expected_res_encode > 0) || outbuf_len > sizeof(buf)) {
	fprintf(stderr, "internal error: inconsistent input parameter for b64_decode_test()");
	exit(EXIT_FAILURE);
    }

    /* encode test */
    size_t raw_len = raw ? strlen(raw) : 0;
    if (raw_len + 1 > sizeof(buf)) {
	fprintf(stderr, "internal error: raw test vector too large for buffer\n");
	exit(EXIT_FAILURE);
    }

    bool pad_mode = (b64enc_len % 4 == 0);

    if (expected_res_encode >= 0) {
	fprintf(stdout, "testing base64_encode(input='%.*s', input_len='%zu', desired_output='%s', max_output_len='%zu', desired_result='%zu')...\n",
		(int) raw_len, raw, raw_len, b64enc, outbuf_len, expected_res_encode);
    } else {
	fprintf(stdout, "testing base64_encode(input='%.*s', input_len='%zu', desired_output='%s', max_output_len='%zu', desired_error='%s')...\n",
		(int) raw_len, raw, raw_len, b64enc, outbuf_len, strerror(-expected_res_encode));
    }
    ssize_t res = base64_encode(raw, raw_len, buf, outbuf_len, pad_mode);
    if (expected_res_encode != res) {
	if (res < 0) {
	    fprintf(stderr, "base64_encode: failed with an unexpected error: %s\n", strerror(-res));
	    exit(EXIT_FAILURE);
	} else if (expected_res_encode < 0) {
	    buf[raw_len] = '\0';
	    fprintf(stderr, "base64_encode: expected an error, but got output='%s', len=%zu\n",
		    buf, res);
	    exit(EXIT_FAILURE);
	} else {
	    buf[raw_len] = '\0';
	    fprintf(stderr, "base64_encode: incorrect output length: output='%s', len=%zu\n",
		    buf, res);
	    exit(EXIT_FAILURE);
	}
    }
    if (res > 0 && (res != b64enc_len || res >= sizeof(buf) || strncmp(buf, b64enc, res))) {
	fprintf(stderr, "base64_encode: expected result='%s', result_len=%zd, but got '%s', len=%zd\n",
		b64enc, b64enc_len, buf, res);
	exit(EXIT_FAILURE);
    }

}
static void b64_encode_test(const char * raw, const char * b64enc, ssize_t expected_res_encode, size_t outbuf_len)
{
    size_t b64enc_len = (b64enc)? strlen(b64enc) : 0;

    xx_b64_encode_test(raw, b64enc, b64enc_len, expected_res_encode, outbuf_len);

    /* if the test vector had correct padding, redo without */
    /* remove at most two padding characters at end */
    if (expected_res_encode > 0 && b64enc_len >= 4 && b64enc_len % 4 == 0 && b64enc[b64enc_len-1] == '=') {
	b64enc_len--;
	expected_res_encode--;
	if (b64enc[b64enc_len-1] == '=') {
	    b64enc_len--;
	    expected_res_encode--;
	}
	xx_b64_encode_test(raw, b64enc, b64enc_len, expected_res_encode, outbuf_len);
    }
}

static void b64_symmetric_test(const char* raw, const char* b64enc)
{
    char buf[TEST_BUF_LEN] = { 0xff };
    char buf2[TEST_BUF_LEN] = { 0xff };

    if (!raw || !b64enc) {
	fprintf(stderr, "internal error: inconsistent input parameter for b64_decode_test()");
	exit(EXIT_FAILURE);
    }

    const size_t raw_len = strlen(raw);
    const size_t b64_len = strlen(b64enc);

    /* Remark: dst for b64_encode needs space for NUL at end */
    b64_decode_test(raw, b64enc, raw_len, raw_len);   /* just enough buffer */
    b64_encode_test(raw, b64enc, b64_len, b64_len+1); /* just enough buffer */

    if (raw_len > 0)
	b64_decode_test(raw, b64enc, -ENOSPC, raw_len - 1);  /* nearly enough buffer */
    if (strlen(b64enc) > 0)
	b64_encode_test(raw, b64enc, -ENOSPC, b64_len);      /* nearly enough buffer */
}

int main(void)
{
    /* RFC-4648 test vectors */
    b64_symmetric_test("",		"");
    b64_symmetric_test("f",		"Zg==");
    b64_symmetric_test("fo",		"Zm8=");
    b64_symmetric_test("foo",		"Zm9v");
    b64_symmetric_test("foob",		"Zm9vYg==");
    b64_symmetric_test("fooba", 	"Zm9vYmE=");
    b64_symmetric_test("foobar",	"Zm9vYmFy");

    /* Output size calculation versus padding */
    b64_decode_test("",		"Zg==",		-ENOSPC, 0);
    b64_decode_test("fo",	"Zm8=",		-ENOSPC, 0);
    b64_decode_test("fo",	"Zm8=",		-ENOSPC, 1);
    b64_decode_test("foo",	"Zm9v",		-ENOSPC, 0);
    b64_decode_test("foo",	"Zm9v",		-ENOSPC, 1);
    b64_decode_test("foo",	"Zm9v",		-ENOSPC, 2);
    b64_decode_test("fo",	"Zm9vYg==",	-ENOSPC, 2);
    b64_decode_test("foo",	"Zm9vYg==",	-ENOSPC, 3);
    b64_decode_test("foo",	"Zm9vYmE=",	-ENOSPC, 3);
    b64_decode_test("foob",	"Zm9vYmE=",	-ENOSPC, 4);

    b64_encode_test("fo",	"Zm8=",		-ENOSPC, 0);
    b64_encode_test("fo",	"Zm8=",		-ENOSPC, 1);
    b64_encode_test("foo",	"Zm9v",		-ENOSPC, 0);
    b64_encode_test("foo",	"Zm9v",		-ENOSPC, 1);
    b64_encode_test("foo",	"Zm9v",		-ENOSPC, 2);
    b64_encode_test("fo",	"Zm9vYg==",	-ENOSPC, 2);
    b64_encode_test("foo",	"Zm9vYg==",	-ENOSPC, 3);
    b64_encode_test("foo",	"Zm9vYmE=",	-ENOSPC, 3);
    b64_encode_test("foob",	"Zm9vYmE=",	-ENOSPC, 4);

    /* Incorrect padding */
    b64_decode_test("foobar00", "Zm9vYmFy=",	-EINVAL, TEST_BUF_LEN);
    b64_decode_test("foobar00",	"Zm9vYmFy==",	-EINVAL, TEST_BUF_LEN);
    b64_decode_test("foobar00", "Zm9vYmFy=Z=",	-EINVAL, TEST_BUF_LEN);
    b64_decode_test("foobar00", "Zm9vYmFy====",	-EINVAL, TEST_BUF_LEN);

    /* Incorrect alphabet in normal cluster */
    b64_decode_test("foobar", "!m9vYmFy",	-EINVAL, TEST_BUF_LEN);
    b64_decode_test("foobar", "Z!9vYmFy",	-EINVAL, TEST_BUF_LEN);
    b64_decode_test("foobar", "Zm!vYmFy",	-EINVAL, TEST_BUF_LEN);
    b64_decode_test("foobar", "Zm9!YmFy",	-EINVAL, TEST_BUF_LEN);

    /* Incorrect alphabet in padding cluster */
    b64_decode_test("fooba", "Zm9v!mE=",	-EINVAL, TEST_BUF_LEN);
    b64_decode_test("fooba", "Zm9vY!E=",	-EINVAL, TEST_BUF_LEN);
    b64_decode_test("fooba", "Zm9vYm!=",	-EINVAL, TEST_BUF_LEN);
    b64_decode_test("fooba", "Zm9vY!==",	-EINVAL, TEST_BUF_LEN);
    b64_decode_test("fooba", "Zm9v!m==",	-EINVAL, TEST_BUF_LEN);

    /* Misuse of padding character */
    b64_decode_test("012",	"=ZZ=",		-EINVAL, TEST_BUF_LEN);
    b64_decode_test("012",	"Z=Z=",		-EINVAL, TEST_BUF_LEN);
    b64_decode_test("f",	"Z===",		-EINVAL, TEST_BUF_LEN);

    /* Extra patterns related to padding being optional for decode */
    b64_decode_test("f", "Z",    -EINVAL, TEST_BUF_LEN); /* bits missing */
    b64_decode_test("f", "Z=",   -EINVAL, TEST_BUF_LEN); /* bits missing */
    b64_decode_test("f", "Z==",  -EINVAL, TEST_BUF_LEN); /* bits missing */
    b64_decode_test("f", "Zg=",  -EINVAL, TEST_BUF_LEN); /* incomplete padding */

    /* FIXME: full alphabet, base64-safe x base64 */
}
