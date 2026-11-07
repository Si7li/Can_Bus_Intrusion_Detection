/* PC check of Core/Src/aes_cmac.c: FIPS 197 / RFC 4493 vectors, then random inputs vs Python.
     cd firmware && gcc -O2 -Ican_ids_fw/Core/Inc host_test/cmac_test.c can_ids_fw/Core/Src/aes_cmac.c -o build/cmac_test
   --stdin: reads "key_hex msg_hex" lines ("-" = empty message) and prints the CMAC. */
#include <stdio.h>
#include <string.h>
#include "aes_cmac.h"

static void hex(const uint8_t *d, size_t n, char *o) { for (size_t i = 0; i < n; i++) sprintf(o + 2 * i, "%02x", d[i]); }
static size_t unhex(const char *s, uint8_t *o) { size_t n = strlen(s) / 2; for (size_t i = 0; i < n; i++) sscanf(s + 2 * i, "%2hhx", &o[i]); return n; }

int main(int argc, char **argv)
{
  aes_cmac_ctx c; uint8_t key[16], m[64], out[16]; char oh[33]; int bad = 0;
  if (argc > 1 && !strcmp(argv[1], "--stdin")) {
    static char k[64], ms[20000]; static uint8_t mb[10000];
    while (scanf("%63s %19999s", k, ms) == 2) {
      unhex(k, key); aes_cmac_init(&c, key);
      size_t n = strcmp(ms, "-") ? unhex(ms, mb) : 0;
      aes_cmac(&c, mb, n, out); hex(out, 16, oh); puts(oh);
    }
    return 0;
  }
  /* FIPS 197 appendix B */
  unhex("2b7e151628aed2a6abf7158809cf4f3c", key); aes_cmac_init(&c, key);
  unhex("3243f6a8885a308d313198a2e0370734", m); aes128_encrypt(c.rk, m, out); hex(out, 16, oh);
  bad += strcmp(oh, "3925841d02dc09fbdc118597196a0b32") != 0;
  /* RFC 4493 examples 1-4 (same key) */
  const char *msg = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";
  const size_t lens[4] = {0, 16, 40, 64};
  const char *want[4] = {"bb1d6929e95937287fa37d129b756746", "070a16b46b4d4144f79bdd9dd04a287c",
                         "dfa66747de9ae63030ca32611497c827", "51f0bebf7e3b9d92fc49741779363cfe"};
  unhex(msg, m);
  for (int i = 0; i < 4; i++) { aes_cmac(&c, m, lens[i], out); hex(out, 16, oh); bad += strcmp(oh, want[i]) != 0; }
  printf("standard vectors: %s\n", bad ? "FAILED" : "5/5 OK (FIPS 197 AES, RFC 4493 CMAC x4)");
  return bad;
}
