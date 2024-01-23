#ifndef SHA256_H
#define SHA256_H

#define SHA256_BLKSIZE   64
#define SHA256_DIGESTSZ  32

#include <stdint.h>
#include <stddef.h>

struct SHA256_CTX {
	uint32_t state[8];
	uint64_t size;
	uint32_t offset;
	uint8_t buf[SHA256_BLKSIZE];
};

typedef struct SHA256_CTX SHA256_CTX;
typedef uint8_t SHA256_DIGEST[SHA256_DIGESTSZ];

void SHA256_init(SHA256_CTX *ctx);
void SHA256_update(SHA256_CTX *ctx, const void *data, size_t len);
void SHA256_final(SHA256_DIGEST digest, SHA256_CTX *ctx);

/* HMAC-SHA256 */
void HMAC_SHA256(SHA256_DIGEST digest,
		 const void * key_in, size_t key_len,
		 const void * data,   size_t data_len);

/* drains fd, returns 0 (ok) or -1 (error), errno set */
int HMAC_SHA256_from_fd(SHA256_DIGEST digest,
		 const void * key_in, size_t key_len,
		 int fd);

#endif
