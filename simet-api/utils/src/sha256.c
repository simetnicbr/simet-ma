#include "simet-api-utils_config.h"

#include "./sha256.h"

#include <stdint.h>
#include <stddef.h>
#include <unistd.h>

#include <string.h>
#include <errno.h>
#include <arpa/inet.h> /* htonl() */

/* not side-effect safe! */
#define MIN(a, b) ((a) > (b)) ? (b) : (a)

/*
 * Let the compiler optimize these, it does a better job.
 */
static inline uint32_t load_be32(const void *ptr)
{
	const uint8_t *p = ptr;
	return  (uint32_t)p[0] << 24 |
		(uint32_t)p[1] << 16 |
		(uint32_t)p[2] <<  8 |
		(uint32_t)p[3];
}
static inline void store_be32(void *ptr, uint32_t value)
{
	uint8_t *p = ptr;
	p[0] = (value >> 24) & 0xffU;
	p[1] = (value >> 16) & 0xffU;
	p[2] = (value >>  8) & 0xffU;
	p[3] = value & 0xffU;
}

void SHA256_Init(SHA256_CTX *ctx)
{
	ctx->offset = 0;
	ctx->size = 0;
	ctx->state[0] = 0x6a09e667ul;
	ctx->state[1] = 0xbb67ae85ul;
	ctx->state[2] = 0x3c6ef372ul;
	ctx->state[3] = 0xa54ff53aul;
	ctx->state[4] = 0x510e527ful;
	ctx->state[5] = 0x9b05688cul;
	ctx->state[6] = 0x1f83d9abul;
	ctx->state[7] = 0x5be0cd19ul;
	memset(ctx->buf, 0, sizeof(ctx->buf));
}

static inline uint32_t ror(uint32_t x, unsigned int n)
{
	return (x >> n) | (x << (32 - n));
}

static inline uint32_t ch(uint32_t x, uint32_t y, uint32_t z)
{
	return z ^ (x & (y ^ z));
}

static inline uint32_t maj(uint32_t x, uint32_t y, uint32_t z)
{
	return ((x | y) & z) | (x & y);
}

static inline uint32_t sigma0(uint32_t x)
{
	return ror(x, 2) ^ ror(x, 13) ^ ror(x, 22);
}

static inline uint32_t sigma1(uint32_t x)
{
	return ror(x, 6) ^ ror(x, 11) ^ ror(x, 25);
}

static inline uint32_t gamma0(uint32_t x)
{
	return ror(x, 7) ^ ror(x, 18) ^ (x >> 3);
}

static inline uint32_t gamma1(uint32_t x)
{
	return ror(x, 17) ^ ror(x, 19) ^ (x >> 10);
}

static void SHA256_Transform(SHA256_CTX *ctx, const uint8_t *buf)
{

	uint32_t S[8], W[64], t0, t1;
	int i;

	/* copy state into S */
	for (i = 0; i < 8; i++)
		S[i] = ctx->state[i];

	/* copy the state into 512-bits into W[0..15] */
	for (i = 0; i < 16; i++, buf += sizeof(uint32_t))
		W[i] = load_be32(buf);

	/* fill W[16..63] */
	for (i = 16; i < 64; i++)
		W[i] = gamma1(W[i - 2]) + W[i - 7] + gamma0(W[i - 15]) + W[i - 16];

#undef  SHA2ROUND
#define SHA2ROUND(a,b,c,d,e,f,g,h,i,ki)                 \
	t0 = h + sigma1(e) + ch(e, f, g) + ki + W[i];   \
	t1 = sigma0(a) + maj(a, b, c);                  \
	d += t0;                                        \
	h  = t0 + t1;

	SHA2ROUND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],0,0x428a2f98);
	SHA2ROUND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],1,0x71374491);
	SHA2ROUND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],2,0xb5c0fbcf);
	SHA2ROUND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],3,0xe9b5dba5);
	SHA2ROUND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],4,0x3956c25b);
	SHA2ROUND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],5,0x59f111f1);
	SHA2ROUND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],6,0x923f82a4);
	SHA2ROUND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],7,0xab1c5ed5);
	SHA2ROUND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],8,0xd807aa98);
	SHA2ROUND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],9,0x12835b01);
	SHA2ROUND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],10,0x243185be);
	SHA2ROUND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],11,0x550c7dc3);
	SHA2ROUND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],12,0x72be5d74);
	SHA2ROUND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],13,0x80deb1fe);
	SHA2ROUND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],14,0x9bdc06a7);
	SHA2ROUND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],15,0xc19bf174);
	SHA2ROUND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],16,0xe49b69c1);
	SHA2ROUND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],17,0xefbe4786);
	SHA2ROUND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],18,0x0fc19dc6);
	SHA2ROUND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],19,0x240ca1cc);
	SHA2ROUND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],20,0x2de92c6f);
	SHA2ROUND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],21,0x4a7484aa);
	SHA2ROUND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],22,0x5cb0a9dc);
	SHA2ROUND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],23,0x76f988da);
	SHA2ROUND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],24,0x983e5152);
	SHA2ROUND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],25,0xa831c66d);
	SHA2ROUND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],26,0xb00327c8);
	SHA2ROUND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],27,0xbf597fc7);
	SHA2ROUND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],28,0xc6e00bf3);
	SHA2ROUND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],29,0xd5a79147);
	SHA2ROUND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],30,0x06ca6351);
	SHA2ROUND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],31,0x14292967);
	SHA2ROUND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],32,0x27b70a85);
	SHA2ROUND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],33,0x2e1b2138);
	SHA2ROUND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],34,0x4d2c6dfc);
	SHA2ROUND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],35,0x53380d13);
	SHA2ROUND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],36,0x650a7354);
	SHA2ROUND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],37,0x766a0abb);
	SHA2ROUND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],38,0x81c2c92e);
	SHA2ROUND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],39,0x92722c85);
	SHA2ROUND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],40,0xa2bfe8a1);
	SHA2ROUND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],41,0xa81a664b);
	SHA2ROUND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],42,0xc24b8b70);
	SHA2ROUND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],43,0xc76c51a3);
	SHA2ROUND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],44,0xd192e819);
	SHA2ROUND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],45,0xd6990624);
	SHA2ROUND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],46,0xf40e3585);
	SHA2ROUND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],47,0x106aa070);
	SHA2ROUND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],48,0x19a4c116);
	SHA2ROUND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],49,0x1e376c08);
	SHA2ROUND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],50,0x2748774c);
	SHA2ROUND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],51,0x34b0bcb5);
	SHA2ROUND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],52,0x391c0cb3);
	SHA2ROUND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],53,0x4ed8aa4a);
	SHA2ROUND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],54,0x5b9cca4f);
	SHA2ROUND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],55,0x682e6ff3);
	SHA2ROUND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],56,0x748f82ee);
	SHA2ROUND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],57,0x78a5636f);
	SHA2ROUND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],58,0x84c87814);
	SHA2ROUND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],59,0x8cc70208);
	SHA2ROUND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],60,0x90befffa);
	SHA2ROUND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],61,0xa4506ceb);
	SHA2ROUND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],62,0xbef9a3f7);
	SHA2ROUND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],63,0xc67178f2);

	for (i = 0; i < 8; i++)
		ctx->state[i] += S[i];
}

void SHA256_Update(SHA256_CTX *ctx, const void *data, size_t len)
{
	unsigned int len_buf = ctx->size & 63;

	ctx->size += len;

	/* Read the data into buf and process blocks as they get full */
	if (len_buf) {
		unsigned int left = 64 - len_buf;
		if (len < left)
			left = (unsigned int)len;
		memcpy(len_buf + ctx->buf, data, left);
		len_buf = (len_buf + left) & 63;
		len -= left;
		data = ((const char *)data + left);
		if (len_buf)
			return;
		SHA256_Transform(ctx, ctx->buf);
	}
	while (len >= 64) {
		SHA256_Transform(ctx, data);
		data = ((const char *)data + 64);
		len -= 64;
	}
	if (len)
		memcpy(ctx->buf, data, len);
}

void SHA256_Final(uint8_t digest[SHA256_DIGEST_LENGTH], SHA256_CTX *ctx)
{
	static const unsigned char pad[64] = { 0x80 };
	unsigned int padlen[2];
	int i;

	/* Pad with a binary 1 (ie 0x80), then zeroes, then length */
	padlen[0] = htonl((uint32_t)(ctx->size >> 29));
	padlen[1] = htonl((uint32_t)(ctx->size << 3));

	i = ctx->size & 63;
	SHA256_Update(ctx, pad, 1 + (63 & (55 - i)));
	SHA256_Update(ctx, padlen, 8);

	/* copy output */
	for (i = 0; i < 8; i++, digest += sizeof(uint32_t))
		store_be32(digest, ctx->state[i]);
}

/* HMAC-SHA256 */

typedef struct HMAC_SHA256_CTX {
	SHA256_CTX hctx_inner;
	SHA256_CTX hctx_outer;
} HMAC_SHA256_CTX;

static inline void HMAC_SHA256_Init(HMAC_SHA256_CTX *hmctx,
		 const void * const key_in, const size_t key_len)
{
	uint8_t key[SHA256_BLKSIZE];
	uint8_t k_ipad[SHA256_BLKSIZE];
	uint8_t k_opad[SHA256_BLKSIZE];
	int i;

	/* RFC 2104 2. (1) */
	memset(key, 0, SHA256_BLKSIZE);
	if (SHA256_BLKSIZE < key_len) {
	        SHA256_Init(&hmctx->hctx_inner);
		SHA256_Update(&hmctx->hctx_inner, key_in, key_len);
		SHA256_Final(key, &hmctx->hctx_inner);
	} else {
		memcpy(key, key_in, key_len);
	}

	/* RFC 2104 2. (2) & (5) */
	for (i = 0; i < SHA256_BLKSIZE; i++) {
		k_ipad[i] = key[i] ^ 0x36;
		k_opad[i] = key[i] ^ 0x5c;
	}

	/* RFC 2104 2. (3) & (4), first part */
	SHA256_Init(&hmctx->hctx_inner);
	SHA256_Update(&hmctx->hctx_inner, k_ipad, sizeof(k_ipad));

	/* RFC 2104 2. (6) & (7), first part */
	SHA256_Init(&hmctx->hctx_outer);
	SHA256_Update(&hmctx->hctx_outer, k_opad, sizeof(k_opad));
}

static inline void HMAC_SHA256_Update(HMAC_SHA256_CTX *hmctx,
		 const void * const data, const size_t data_len)
{
	/* RFC 2104 2. (3) & (4), second part */
	SHA256_Update(&hmctx->hctx_inner, data, data_len);
}

static inline void HMAC_SHA256_Final(HMAC_SHA256_CTX *hmctx, uint8_t digest[SHA256_DIGEST_LENGTH])
{
	/* RFC 2104 2. (3) & (4), third part */
	SHA256_Final(digest, &hmctx->hctx_inner);

	/* RFC 2104 2. (6) & (7), second part */
	SHA256_Update(&hmctx->hctx_outer, digest, SHA256_DIGEST_LENGTH);
	SHA256_Final(digest, &hmctx->hctx_outer);
}

void HMAC_SHA256(uint8_t digest[SHA256_DIGEST_LENGTH],
		 const void * const key_in, const size_t key_len,
		 const void * const data, const size_t data_len)
{
	HMAC_SHA256_CTX hmctx;

	HMAC_SHA256_Init(&hmctx, key_in, key_len);
	HMAC_SHA256_Update(&hmctx, data, data_len);
	HMAC_SHA256_Final(&hmctx, digest);
}

int HMAC_SHA256_from_fd(uint8_t digest[SHA256_DIGEST_LENGTH],
		 const void * const key_in, size_t key_len,
		 const int fd)
{
	HMAC_SHA256_CTX hmctx;
	uint8_t io_buf[SHA256_BLKSIZE];
	ssize_t res;

	HMAC_SHA256_Init(&hmctx, key_in, key_len);

	/* RFC 2104 2. (3) & (4), second part */
	memset(io_buf, 0, SHA256_BLKSIZE);
	do {
	    res = read(fd, &io_buf, sizeof(io_buf));
	    if (res > 0) {
	        HMAC_SHA256_Update(&hmctx, &io_buf, (size_t)res);
	    }
	} while (res > 0 || (res == -1 && (errno == EINTR || errno == EAGAIN)));
	if (res) {
	    /* errno set */
	    return -1;
	}

	HMAC_SHA256_Final(&hmctx, digest);
	return 0;
}

/* PBKDF2-HMAC-SHA256 */

/* this auto-vectorizes, memcpy() might not */
static inline void SHA256_scpy(SHA256_CTX * restrict out,
			const SHA256_CTX * restrict in)
{
	out->state[0] = in->state[0];
	out->state[1] = in->state[1];
	out->state[2] = in->state[2];
	out->state[3] = in->state[3];
	out->state[4] = in->state[4];
	out->state[5] = in->state[5];
	out->state[6] = in->state[6];
	out->state[7] = in->state[7];
}
static inline void SHA256_sxor(SHA256_CTX * restrict out,
			const SHA256_CTX * restrict in)
{
	out->state[0] ^= in->state[0];
	out->state[1] ^= in->state[1];
	out->state[2] ^= in->state[2];
	out->state[3] ^= in->state[3];
	out->state[4] ^= in->state[4];
	out->state[5] ^= in->state[5];
	out->state[6] ^= in->state[6];
	out->state[7] ^= in->state[7];
}
static inline void SHA256_extract(const SHA256_CTX * restrict ctx,
			 uint8_t * restrict out)
{
	store_be32(out     , ctx->state[0]);
	store_be32(out +  4, ctx->state[1]);
	store_be32(out +  8, ctx->state[2]);
	store_be32(out + 12, ctx->state[3]);
	store_be32(out + 16, ctx->state[4]);
	store_be32(out + 20, ctx->state[5]);
	store_be32(out + 24, ctx->state[6]);
	store_be32(out + 28, ctx->state[7]);
}

/* FastPBKDF2 optimization by Joseph Birr-Pixton <jpixton@gmail.com> */
static inline void pbkdf2_hmac_sha256_f(HMAC_SHA256_CTX *hmctx,
			uint32_t counter,
			const uint8_t *salt, size_t salt_len,
			uint32_t iterations,
			uint8_t *block)
{

	uint8_t  padded[SHA256_BLKSIZE];
	uint32_t count_be;
	uint32_t i;

	store_be32(&count_be, counter);

	/* Invariant padding */
	memset(&padded[SHA256_DIGEST_LENGTH], 0, SHA256_BLKSIZE - SHA256_DIGEST_LENGTH - 4);
	padded[SHA256_DIGEST_LENGTH] = 0x80;
	store_be32(&padded[SHA256_BLKSIZE - sizeof(uint32_t)], (SHA256_BLKSIZE + SHA256_DIGEST_LENGTH) * 8);

	/* First iteraction, U_1 = PRF(P, S || count_be) */
	HMAC_SHA256_CTX uctx = *hmctx;
	HMAC_SHA256_Update(&uctx, salt, salt_len);
	HMAC_SHA256_Update(&uctx, &count_be, sizeof(count_be));
	HMAC_SHA256_Final(&uctx, padded);

	SHA256_CTX hctx_result = uctx.hctx_outer;

	/* Subsequent iteractions, U_c = PRF(P, U_{c-1}) */
	for (i = 1; i < iterations; ++i) {
	    /* Complete inner hash with previous iteraction */
	    SHA256_scpy(&uctx.hctx_inner, &hmctx->hctx_inner);
	    SHA256_Transform(&uctx.hctx_inner, padded);
	    SHA256_extract(&uctx.hctx_inner, padded);
	    /* Complete outer hash with inner output */
	    SHA256_scpy(&uctx.hctx_outer, &hmctx->hctx_outer);
	    SHA256_Transform(&uctx.hctx_outer, padded);
	    SHA256_extract(&uctx.hctx_outer, padded);

	    SHA256_sxor(&hctx_result, &uctx.hctx_outer);
	}

	SHA256_extract(&hctx_result, block);
}

int pbkdf2_hmac_sha256(const uint8_t *pw, size_t pw_len,
			const uint8_t *salt, size_t salt_len,
			uint32_t iterations,
			uint8_t *key_out, size_t key_out_len)
{
	HMAC_SHA256_CTX hmctx;
	uint32_t blocks_needed;
	uint32_t counter;

	if (!pw || !pw_len || !salt || !salt_len || !key_out || !key_out_len || !iterations) {
		errno = EINVAL;
		return -1;
	}

	HMAC_SHA256_Init(&hmctx, pw, pw_len);

	blocks_needed = (uint32_t)(key_out_len + SHA256_DIGEST_LENGTH - 1) / SHA256_DIGEST_LENGTH;
	for (counter = 1; counter <= blocks_needed; ++counter) {
		uint8_t block[SHA256_DIGEST_LENGTH];
		pbkdf2_hmac_sha256_f(&hmctx, counter, salt, salt_len, iterations, block);

		size_t offset = (counter - 1) * SHA256_DIGEST_LENGTH;
		size_t taken = MIN(key_out_len - offset, SHA256_DIGEST_LENGTH);
		memcpy(key_out + offset, block, taken);
	}

	return 0;
}

