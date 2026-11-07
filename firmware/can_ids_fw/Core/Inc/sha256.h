/* SHA-256 (FIPS 180-4) and HMAC-SHA256 (RFC 2104), small portable C.
   Used to sign the Nucleo's JSON lines; the secure bootloader reuses it for the image hash. */
#ifndef SHA256_H
#define SHA256_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
  uint32_t h[8];
  uint64_t len;          /* bytes hashed so far */
  uint8_t buf[64];
  uint32_t n;            /* bytes waiting in buf */
} sha256_ctx;

void sha256_init(sha256_ctx *c);
void sha256_update(sha256_ctx *c, const void *data, size_t len);
void sha256_final(sha256_ctx *c, uint8_t out[32]);
void sha256(const void *data, size_t len, uint8_t out[32]);
void hmac_sha256(const uint8_t *key, size_t key_len, const void *msg, size_t len, uint8_t out[32]);

#endif
