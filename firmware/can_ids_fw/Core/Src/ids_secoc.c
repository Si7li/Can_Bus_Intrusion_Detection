/* SecOC-style verification of chosen CAN IDs, see ids_secoc.h. Receiver side only.

   Each protected frame carries an authenticator in a companion CAN frame with a HIGH-priority
   ID (0x004 / 0x005), so the bus never delays it far from its data frame. The data frame and
   its authenticator may still arrive in either order (priority can send the authenticator
   first), so the receiver keeps a small ring of each kind and matches them by recomputing the
   CMAC, whichever arrives first.

   Verdicts, raised as an ALERT on the protected ID:
     auth_mac      an authenticator verifies no buffered data frame -> data replaced in transit
     auth_replay   verifies, but the freshness counter is not newer -> a recorded frame resent
     auth_missing  a protected data frame no authenticator ever verifies -> injected frame
   Smoothing: a single frame lost on the bus makes one isolated check fail, so an ALERT is
   raised only on a burst (SECOC_SMOOTH failures within SECOC_WINDOW) on one ID, the same idea
   as the detector's k-of-n smoothing. A real forgery or replay fails every frame, so the
   burst is immediate. */
#include "ids_secoc.h"
#include <stdio.h>
#include <string.h>
#include "aes_cmac.h"
#include "sha256.h"
#include "stm32f4xx.h"

#define N_PROT 2u
#define RING   96u                       /* recent unmatched frames per kind per ID (the adapter can
                                            delay the low-priority authenticator by up to ~1 s) */
#define AUTH_TIMEOUT_US 400000u          /* a data frame unverified this long = injected/lost */
#define SECOC_RUN 16u                    /* consecutive failures (no valid frame between) to ALERT:
                                            a masquerade forges every frame; bus loss is isolated */

static const struct { uint16_t data_id, auth_id; } PROT[N_PROT] = {{0x386, 0x786}, {0x2B0, 0x7B0}};

typedef struct { uint8_t used, dlc; uint8_t data[8]; uint32_t t_us; } data_t;
typedef struct { uint8_t used, tag[4]; uint32_t fresh, t_us; } auth_t;

static struct {
  uint8_t armed;
  uint32_t last_fresh;
  data_t dring[RING];                    /* data frames awaiting their authenticator */
  auth_t aring[RING];                    /* authenticators awaiting their data frame */
  uint32_t fail_run;                     /* consecutive failed checks (reset by any valid frame) */
  uint8_t last_reason;
} slot[N_PROT];

static aes_cmac_ctx cmac;
static int have_key;
static uint32_t n_ok, n_alert, n_unverified, cmac_cycles;

static int index_of(uint16_t id, int auth)
{
  for (uint32_t k = 0; k < N_PROT; k++)
    if ((auth ? PROT[k].auth_id : PROT[k].data_id) == id) return (int)k;
  return -1;
}

void secoc_set_key(const uint8_t device_secret[16])
{
  if (!device_secret) { have_key = 0; memset(&cmac, 0, sizeof cmac); return; }
  uint8_t h[32];
  sha256_ctx c;
  sha256_init(&c);
  sha256_update(&c, "can-ids secoc v1", 16);
  sha256_update(&c, device_secret, 16);
  sha256_final(&c, h);
  aes_cmac_init(&cmac, h);                /* SecOC key = a separate hash of the device secret */
  memset(h, 0, sizeof h);
  have_key = 1;
}

void secoc_reset(void)
{
  for (uint32_t k = 0; k < N_PROT; k++)
    for (uint32_t r = 0; r < RING; r++) { slot[k].dring[r].used = 0; slot[k].aring[r].used = 0; }
}

/* CMAC over data ID (2 B BE) || DLC || data[0..dlc-1] || freshness (4 B BE); first 4 bytes kept */
static void tag_of(uint16_t data_id, uint8_t dlc, const uint8_t data[8], uint32_t fresh, uint8_t out4[4])
{
  uint8_t msg[15], mac[16];
  uint32_t n = 0, t0 = DWT->CYCCNT;
  if (dlc > 8u) dlc = 8u;
  msg[n++] = (uint8_t)(data_id >> 8); msg[n++] = (uint8_t)data_id; msg[n++] = dlc;
  for (uint32_t i = 0; i < dlc; i++) msg[n++] = data[i];
  msg[n++] = (uint8_t)(fresh >> 24); msg[n++] = (uint8_t)(fresh >> 16);
  msg[n++] = (uint8_t)(fresh >> 8);  msg[n++] = (uint8_t)fresh;
  aes_cmac(&cmac, msg, n, mac);
  memcpy(out4, mac, 4);
  cmac_cycles = DWT->CYCCNT - t0;
}

/* a matched data+authenticator pair: 0 = fresh (accepted), SECOC_R_REPLAY = freshness not newer */
static int verified(int k, uint32_t fresh)
{
  if (slot[k].armed && fresh <= slot[k].last_fresh) return SECOC_R_REPLAY;
  slot[k].last_fresh = fresh;
  slot[k].armed = 1;
  slot[k].fail_run = 0;                   /* a valid frame breaks any run of failures */
  n_ok++;
  return 0;
}

/* Record a failed check on ID k. A real masquerade or replay forges every protected frame,
   so failures come in an unbroken run; a frame lost on the bus fails once between valid frames.
   Raise an ALERT only once the run reaches SECOC_RUN. */
static int note_fail(int k, uint8_t reason, uint32_t t_us, secoc_fail_t *f)
{
  (void)t_us;
  n_unverified++;
  slot[k].last_reason = reason;
  if (slot[k].fail_run < 0xFFFFu) slot[k].fail_run++;
  if (slot[k].fail_run >= SECOC_RUN) {
    n_alert++;
    f->id = PROT[k].data_id;
    f->reason = reason;
    return 1;
  }
  return 0;
}

static data_t *oldest_data(int k)
{
  data_t *o = &slot[k].dring[0];
  for (uint32_t r = 1; r < RING; r++)
    if (!o->used || (slot[k].dring[r].used && (int32_t)(slot[k].dring[r].t_us - o->t_us) < 0)) o = &slot[k].dring[r];
  return o;
}

int secoc_frame(uint16_t id, uint8_t dlc, const uint8_t data[8], uint32_t t_us, secoc_fail_t *f)
{
  f->reason = 0;
  int d = index_of(id, 0), a = index_of(id, 1);

  if (d >= 0) {                          /* a protected data frame */
    if (have_key) {                      /* does a buffered authenticator verify it? */
      for (uint32_t r = 0; r < RING; r++) {
        if (!slot[d].aring[r].used) continue;
        uint8_t want[4];
        tag_of(PROT[d].data_id, dlc, data, slot[d].aring[r].fresh, want);
        if (memcmp(want, slot[d].aring[r].tag, 4) == 0) {
          uint32_t fr = slot[d].aring[r].fresh;
          slot[d].aring[r].used = 0;
          if (verified(d, fr) == SECOC_R_REPLAY) note_fail(d, SECOC_R_REPLAY, t_us, f);
          return 0;
        }
      }
    }
    data_t *dst = NULL;                  /* keep it until an authenticator arrives */
    for (uint32_t r = 0; r < RING; r++) if (!slot[d].dring[r].used) { dst = &slot[d].dring[r]; break; }
    if (!dst) { dst = oldest_data(d); if (slot[d].armed) note_fail(d, SECOC_R_MISSING, t_us, f); }
    dst->used = 1; dst->dlc = dlc > 8u ? 8u : dlc; memcpy(dst->data, data, 8); dst->t_us = t_us;
    return 0;                            /* not consumed: the detector still inspects the data frame */
  }

  if (a < 0) return 0;                   /* ordinary frame */
  if (!have_key) return 1;               /* authenticator, no key: consume silently */

  uint32_t fresh = (uint32_t)data[0] << 24 | (uint32_t)data[1] << 16 | (uint32_t)data[2] << 8 | data[3];
  for (uint32_t r = 0; r < RING; r++) {  /* does a buffered data frame verify under this authenticator? */
    if (!slot[a].dring[r].used) continue;
    uint8_t want[4];
    tag_of(PROT[a].data_id, slot[a].dring[r].dlc, slot[a].dring[r].data, fresh, want);
    if (memcmp(want, data + 4, 4) == 0) {
      slot[a].dring[r].used = 0;
      if (verified(a, fresh) == SECOC_R_REPLAY) note_fail(a, SECOC_R_REPLAY, t_us, f);
      return 1;
    }
  }
  if (slot[a].armed) {                    /* no buffered data matches: the data was replaced (forgery) */
    note_fail(a, SECOC_R_MAC, t_us, f);
    return 1;
  }
  auth_t *dst = NULL;                      /* data frame not here yet: keep the authenticator briefly */
  for (uint32_t r = 0; r < RING; r++) if (!slot[a].aring[r].used) { dst = &slot[a].aring[r]; break; }
  if (!dst) { dst = &slot[a].aring[0]; for (uint32_t r = 1; r < RING; r++) if ((int32_t)(slot[a].aring[r].t_us - dst->t_us) < 0) dst = &slot[a].aring[r]; }
  dst->used = 1; dst->fresh = fresh; memcpy(dst->tag, data + 4, 4); dst->t_us = t_us;
  return 1;
}

int secoc_poll(uint32_t now_us, secoc_fail_t *f)
{
  f->reason = 0;
  for (uint32_t k = 0; k < N_PROT; k++) {
    if (!slot[k].armed) continue;
    for (uint32_t r = 0; r < RING; r++) {
      if (slot[k].dring[r].used && now_us - slot[k].dring[r].t_us > AUTH_TIMEOUT_US) {
        slot[k].dring[r].used = 0;        /* a data frame no authenticator ever verified */
        if (note_fail((int)k, SECOC_R_MISSING, now_us, f)) return 1;
      }
      if (slot[k].aring[r].used && now_us - slot[k].aring[r].t_us > AUTH_TIMEOUT_US)
        slot[k].aring[r].used = 0;         /* an authenticator whose data frame was lost: drop quietly */
    }
  }
  return 0;
}

const char *secoc_json(void)
{
  static char buf[128];
  snprintf(buf, sizeof buf, "\"secoc\":{\"key\":%s,\"ok\":%lu,\"alerts\":%lu,\"unverified\":%lu,\"verify_us\":%lu}",
           have_key ? "true" : "false", (unsigned long)n_ok, (unsigned long)n_alert,
           (unsigned long)n_unverified, (unsigned long)(cmac_cycles / (SystemCoreClock / 1000000u)));
  return buf;
}
