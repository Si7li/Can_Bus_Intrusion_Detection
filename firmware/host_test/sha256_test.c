/* PC check of Core/Src/sha256.c: FIPS 180-4 / RFC 4231 vectors, then random inputs vs Python.
     cd firmware && gcc -O2 -Ican_ids_fw/Core/Inc host_test/sha256_test.c can_ids_fw/Core/Src/sha256.c -o build/sha256_test
   --stdin: reads "key_hex msg_hex" lines (hex, "-" = empty) and prints the HMAC;
   with key "-" it prints the plain SHA-256 (used for the random check against Python). */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "sha256.h"

static void hex(const uint8_t *d, size_t n, char *out) { for (size_t i = 0; i < n; i++) sprintf(out + 2 * i, "%02x", d[i]); }
static size_t unhex(const char *s, uint8_t *out) { size_t n = strlen(s) / 2; for (size_t i = 0; i < n; i++) sscanf(s + 2 * i, "%2hhx", &out[i]); return n; }

int main(int argc, char **argv)
{
  if (argc > 1 && !strcmp(argv[1], "--stdin")) {
    static char k[4096], m[200000]; static uint8_t kb[2048], mb[100000]; uint8_t o[32]; char oh[65];
    while (scanf("%4095s %199999s", k, m) == 2) {
      size_t mn = strcmp(m, "-") ? unhex(m, mb) : 0;
      if (!strcmp(k, "-")) sha256(mb, mn, o); else hmac_sha256(kb, unhex(k, kb), mb, mn, o);
      hex(o, 32, oh); puts(oh);
    }
    return 0;
  }
  uint8_t o[32]; char oh[65]; int bad = 0;
  struct { const char *msg; const char *want; } v[] = {
    {"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
    {"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
    {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"}};
  for (int i = 0; i < 3; i++) { sha256(v[i].msg, strlen(v[i].msg), o); hex(o, 32, oh); bad += strcmp(oh, v[i].want) != 0; }
  /* RFC 4231 test case 2 */
  hmac_sha256((const uint8_t *)"Jefe", 4, "what do ya want for nothing?", 28, o); hex(o, 32, oh);
  bad += strcmp(oh, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843") != 0;
  printf("standard vectors: %s\n", bad ? "FAILED" : "4/4 OK");
  return bad;
}
