/* AES-128 (FIPS 197, encryption only) and AES-CMAC (RFC 4493 / NIST SP 800-38B).
   Used for SecOC-style CAN authentication (ids_secoc.c). The F446 has no AES hardware. */
#ifndef AES_CMAC_H
#define AES_CMAC_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
  uint8_t rk[176];       /* expanded round keys */
  uint8_t k1[16], k2[16];/* CMAC subkeys */
} aes_cmac_ctx;

void aes128_encrypt(const uint8_t rk[176], const uint8_t in[16], uint8_t out[16]);
void aes_cmac_init(aes_cmac_ctx *c, const uint8_t key[16]);
void aes_cmac(const aes_cmac_ctx *c, const uint8_t *msg, size_t len, uint8_t mac[16]);

#endif
