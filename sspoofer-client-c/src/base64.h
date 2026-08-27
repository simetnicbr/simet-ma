/*
 * Base64 encoding/decoding (RFC4648) rev 2.2
 * Copyright (c) 2023, 2024 NIC.br
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef SIMET_BASE64_H_
#define SIMET_BASE64_H_

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/* base64_decode - RFC 4648
 * Strict-mode base64 / base64-safe decoder.
 *
 * Accepts both base64 and base64-safe as the input enconding (in fact,
 * accepts an illegal mix of both).
 *
 * Padding is optional, but incorrect or excessive input padding and
 * left-over characters will be rejected as an error.  Rejects illegal
 * characters in encoding as an error.
 *
 * Output buffer contents are *undefined* upon error return, it might or
 * might not have been partially modified.
 *
 * @src is a byte buffer with length @src_len, with the encoded data
 * @dst is a byte buffer with length @max_dst_len, for the decoded data
 *
 * Returns number of decoded bytes in the output buffer, or a negative
 * error code.
 *
 * -EINVAL:  invalid base64 input data
 * -ENOSPC:  output buffer too small, nothing done
 */
ssize_t base64_decode(const char* const restrict src, const size_t src_len,
                      uint8_t * restrict dst, const size_t max_dst_len);

/* base64_encode - RFC 4648
 *
 * Encodes a buffer in base64, using the standard dictionary, with '=' padding.
 * ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
 *
 * @src is a byte buffer with length @src_len
 * @dst is a C-string with maximum length @max_dst_len.
 * @pad includes '=' padding if non-zero, excludes it if zero
 *
 * Returns the length of dst, or a negative error (-EOVERFLOW, -ENOSPC)
 * -EOVERFLOW: size too large to fit ssize_t when decoded.
 * -ENOSPC: destination buffer too small. *
 */
ssize_t base64_encode(const uint8_t * const restrict src, const size_t src_len,
                      char * restrict dst, const size_t max_dst_len, int pad);

/* base64safe_encode - RFC 4648
 *
 * same as base64_encode, but uses a dictionary that is more friendly
 * to URLs and filenames.
 * ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_
 *
 * @src is a byte buffer with length @src_len
 * @dst is a C-string with maximum length @max_dst_len.
 * @pad includes '=' padding if non-zero, excludes it if zero
 *
 * Returns the length of dst, or a negative error (-EOVERFLOW, -ENOSPC)
 */
ssize_t base64safe_encode(const uint8_t * const restrict src, const size_t src_len,
                          char * restrict dst, const size_t max_dst_len, int pad);

#endif /* SIMET_BASE64_H_ */
