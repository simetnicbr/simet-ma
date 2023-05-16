/*
 * Base64 encoding/decoding (RFC4648)
 * Copyright (c) 2023 NIC.br
 *
 * This software may be distributed under the terms of the BSD license.
 */

/* Based on source code from Polfosol:
   https://stackoverflow.com/questions/180947/base64-decode-snippet-in-c/13935718
*/

#include "twampc_config.h"
#include "base64.h"

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

#include <errno.h>

/* base64_decode - RFC 4648
 *
 * Strict-mode base64 / base64-safe decoder.
 *
 * Accepts both base64 and base64-safe as the input enconding (in fact,
 * accepts an illegal mix of both).
 *
 * Rejects missing or excessive input padding and left-over characters
 * as an error.  Rejects illegal characters in encoding as an error.
 *
 * Output buffer contents are *undefined* upon error return, it might or
 * might not have been partially modified.
 *
 * Returns number of decoded bytes in the output buffer, or a negative
 * error code.
 *
 * -EINVAL:  invalid base64 input data
 * -ENOSPC:  output buffer too small, nothing done
 */

ssize_t base64_decode(const char* const src, const size_t src_len, uint8_t *dst, const size_t max_dst_len) {
    const uint8_t b64dec[256] = {
        0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U,
        0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U,
        0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x3eU, 0x80U, 0x3eU, 0x80U, 0x3fU,
        0x34U, 0x35U, 0x36U, 0x37U, 0x38U, 0x39U, 0x3aU, 0x3bU, 0x3cU, 0x3dU, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U,
        0x80U, 0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U, 0x08U, 0x09U, 0x0aU, 0x0bU, 0x0cU, 0x0dU, 0x0eU,
        0x0fU, 0x10U, 0x11U, 0x12U, 0x13U, 0x14U, 0x15U, 0x16U, 0x17U, 0x18U, 0x19U, 0x80U, 0x80U, 0x80U, 0x80U, 0x3fU,
        0x80U, 0x1aU, 0x1bU, 0x1cU, 0x1dU, 0x1eU, 0x1fU, 0x20U, 0x21U, 0x22U, 0x23U, 0x24U, 0x25U, 0x26U, 0x27U, 0x28U,
        0x29U, 0x2aU, 0x2bU, 0x2cU, 0x2dU, 0x2eU, 0x2fU, 0x30U, 0x31U, 0x32U, 0x33U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U,
        0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U,
        0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U,
        0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U,
        0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U,
        0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U,
        0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U,
        0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U,
        0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U
    }; /* Remarks: decodes '-' and '+' to 0x3e and '_' and '/' to 0x3f */

#if 0
    /* Code to create the above decoding table: */

    #include <unistd.h>
    #include <stdint.h>
    #include <stddef.h>
    #include <stdio.h>
    #include <string.h>

    const char encoding_table[] = {
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
        'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
        'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
        'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/' };

    unsigned char decoding_table[256];

    int main() {
	memset(decoding_table, 0x80, sizeof(decoding_table));

        for (int i = 0; i < 64; i++)
            decoding_table[(unsigned char)encoding_table[i]] = i;

        /* Extra alphabet: base64safe */
        decoding_table['-'] = 62;
        decoding_table['_'] = 63;

        for (int i = 0; i < 256; i++) {
            printf("0x%02xU, ", decoding_table[i]);
            if (i % 16 == 15) {
                printf("\n");
            }
        }
    }
#endif

    if (!src || !src_len)
        return 0; /* no input data to process */

    if (src_len % 4 != 0)
	return -EINVAL; /* required input padding missing */

    /* code from this point on assumes src_len >= 4 and multiple of 4 */

    const uint8_t *inbuf = (const uint8_t *)src;
    const bool pad1 = (char)inbuf[src_len - 1] == '=';
    const bool pad2 = pad1 && (char)inbuf[src_len - 2] == '=';

    const size_t in_len = src_len - pad1 - pad2;
    const size_t out_len = ((src_len / 4U) * 3U) - pad1 - pad2;

    if (out_len > max_dst_len)
	return -ENOSPC;

    /* we should ensure to never read or write out-of-bounds from this
     * point on as safety in depth, but we might not detect it as an
     * error explicitly */

    size_t i = 0, o = 0;
    while (i < in_len && ((o + 3) <= out_len)) {
	union {
	    uint32_t u32;
	    uint8_t  b[4];
	} u;

	u.b[0] = b64dec[inbuf[i++]];
	u.b[1] = b64dec[inbuf[i++]];
	u.b[2] = b64dec[inbuf[i++]];
	u.b[3] = b64dec[inbuf[i++]];
	if ((u.u32 & 0x80808080U) != 0)
	    return -EINVAL; /* illegal char, including out-of-place padding */

	uint32_t n = ((uint32_t)u.b[0] << 18) | ((uint32_t)u.b[1] << 12) | ((uint32_t)u.b[2] << 6) | ((uint32_t)u.b[3]);
	dst[o++] = (n >> 16U) & 0xffU;
	dst[o++] = (n >> 8U) & 0xffU;
	dst[o++] = n & 0xffU;
    }
    if (pad1 && o <= out_len) {
	union {
	    uint16_t u16[2];
	    uint8_t  b[4];
	} u;

	u.b[0] = b64dec[inbuf[i++]];
	u.b[1] = b64dec[inbuf[i++]];
	u.b[2] = b64dec[inbuf[i++]];
	u.b[3] = 0; /* known to be '=' */
	if ((u.u16[0] & 0x8080U) != 0 || (!pad2 && ((u.b[2] & 0x80U) != 0)))
	    return -EINVAL;

	uint32_t n = ((uint32_t)u.b[0] << 18U) | ((uint32_t)u.b[1] << 12U) | ((uint32_t)u.b[2] << 6U);
	dst[o++] = (n >> 16U) & 0xffU;

	if (!pad2 && o <= out_len) {
	    dst[o++] = (n >> 8U) & 0xffU;
	}
    }

    return (ssize_t)o;
}
