/*
 * Base64 encoding/decoding (RFC4648)
 * Copyright (c) 2023 NIC.br
 *
 * This software may be distributed under the terms of the BSD license.
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
ssize_t base64_decode(const char* const src, const size_t src_len, uint8_t *dst, const size_t max_dst_len);

#endif /* SIMET_BASE64_H_ */
