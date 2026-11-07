/* Device protection (step 3): watchdog, reset cause, protection settings report.
   Register-level (RM0390 reference manual), so no extra HAL module is needed. */
#include "ids_security.h"
#include <stdio.h>
#include <string.h>
#include "stm32f4xx_hal.h"
#include "sha256.h"
#include "ids_entropy.h"
#include "uecc/uECC.h"
#include "secure_boot.h"
#include "ids_indicators.h"
#include "ids_secoc.h"

extern UART_HandleTypeDef huart2;

static const char *reset_cause = "unknown";
static void capture_boot_report(void);

/* RCC_CSR keeps the reset flags until RMVF clears them. Several can be set at once:
   every internal reset also pulls the NRST pin (PINRSTF), and a power-on also sets
   BORRSTF, so check the specific causes first. */
void sec_capture_reset_cause(void)
{
  uint32_t csr = RCC->CSR;
  if (csr & RCC_CSR_IWDGRSTF)      reset_cause = "watchdog";       /* IWDG: main loop stopped */
  else if (csr & RCC_CSR_WWDGRSTF) reset_cause = "window_watchdog";
  else if (csr & RCC_CSR_LPWRRSTF) reset_cause = "low_power";
  else if (csr & RCC_CSR_SFTRSTF)  reset_cause = "software";       /* NVIC_SystemReset, debugger */
  else if (csr & RCC_CSR_PORRSTF)  reset_cause = "power_on";
  else if (csr & RCC_CSR_BORRSTF)  reset_cause = "brown_out";      /* supply dipped below the BOR level */
  else if (csr & RCC_CSR_PINRSTF)  reset_cause = "reset_pin";      /* black button, ST-LINK hardware reset */
  RCC->CSR |= RCC_CSR_RMVF;
  capture_boot_report();
}

const char *sec_reset_cause(void) { return reset_cause; }

/* What the secure bootloader verified before starting us (secure_boot.h). */
static sb_bootinfo_t boot_report;
static void capture_boot_report(void)
{
  boot_report.magic = SB_BOOTINFO->magic;
  boot_report.fw_version = SB_BOOTINFO->fw_version;
  boot_report.min_version = SB_BOOTINFO->min_version;
  boot_report.check_ms = SB_BOOTINFO->check_ms;
  SB_BOOTINFO->magic = 0;            /* the next boot must be verified again */
}

/* Option bytes (FLASH_OPTCR), read-only here; they are changed with STM32_Programmer_CLI.
     RDP     [15:8]  0xAA = level 0 (open), 0xCC = level 2 (permanent), anything else = level 1
     BOR_LEV [3:2]   00 = level 3 (2.70 V), 01 = level 2 (2.40 V), 10 = level 1 (2.10 V), 11 = off
     WDG_SW  bit 5   1 = watchdog started by software, 0 = started by hardware at every reset
     nWRP    [23:16] one bit per flash sector 0-7, 0 = write-protected (when SPRMOD = 0) */
void sec_report_boot(void)
{
  uint32_t opt = FLASH->OPTCR;
  uint32_t rdp = (opt >> 8) & 0xFFu;
  const char *rdp_s = rdp == 0xAAu ? "level0" : rdp == 0xCCu ? "level2" : "level1";
  static const char *const bor_s[4] = {"level3_2.70V", "level2_2.40V", "level1_2.10V", "off"};
  uint32_t nwrp = (opt >> 16) & 0xFFu;
  int pcrop = (opt >> 31) & 1u;                 /* SPRMOD = 1: the bits mean PCROP, not WRP */
  char wrp[40], *p = wrp;
  *p++ = '[';
  for (int s = 0; s < 8; s++)
    if (!pcrop && !(nwrp & (1u << s))) p += sprintf(p, p == wrp + 1 ? "%d" : ",%d", s);
  *p++ = ']'; *p = 0;
  char sb[96];
  if (boot_report.magic == SB_BOOTINFO_MAGIC)
    snprintf(sb, sizeof sb, "\"secure_boot\":{\"verified\":true,\"fw_version\":%lu,\"min_version\":%lu,\"check_ms\":%lu}",
             (unsigned long)boot_report.fw_version, (unsigned long)boot_report.min_version, (unsigned long)boot_report.check_ms);
  else
    snprintf(sb, sizeof sb, "\"secure_boot\":{\"verified\":false}");
  printf("{\"type\":\"boot\",\"reset\":\"%s\",\"rdp\":\"%s\",\"bor\":\"%s\",\"wrp_sectors\":%s,"
         "\"watchdog\":\"%s\",\"watchdog_ms\":%lu,\"demo_commands\":%s,%s,%s}\r\n",
         reset_cause, rdp_s, bor_s[(opt >> 2) & 3u], wrp, (opt & FLASH_OPTCR_WDG_SW) ? "software" : "hardware",
         (unsigned long)SEC_WATCHDOG_MS, SEC_DEMO_COMMANDS ? "true" : "false", sec_secret_json(), sb);
}

/* IWDG: LSI (~32 kHz) / 32 = ~1 kHz counter, reload = timeout in ms (max 4095).
   Once started it cannot be stopped by software: only a reset ends it. */
void sec_watchdog_start(uint32_t ms)
{
  if (ms < 1u) ms = 1u;
  if (ms > 4095u) ms = 4095u;
  DBGMCU->APB1FZ |= DBGMCU_APB1_FZ_DBG_IWDG_STOP;   /* paused while a debugger halts the core */
  IWDG->KR = 0xCCCCu;                                /* start (also starts the LSI) */
  IWDG->KR = 0x5555u;                                /* unlock PR and RLR */
  IWDG->PR = 3u;                                     /* divide by 32 */
  IWDG->RLR = ms;
  while (IWDG->SR & (IWDG_SR_PVU | IWDG_SR_RVU)) { } /* wait until the new values are taken */
  IWDG->KR = 0xAAAAu;                                /* reload the counter now */
}

#if SEC_DEMO_COMMANDS
/* "E1" / "E2" / "E4" / "E8": dump 32,768 raw entropy samples (LSI periods per sample = digit)
   for the measurement on the PC (pc/entropy_check.py). 64 samples per line, 4 hex digits each.
   The detector is paused meanwhile (~3 s). */
static void entropy_dump(uint32_t periods)
{
  static const char hx[] = "0123456789abcdef";
  char d[64 * 4 + 1];
  entropy_start(periods);
  for (uint32_t line = 0; line < 512u; line++) {
    (void)entropy_sample();              /* the gap while printing spans several periods: drop it */
    for (uint32_t k = 0; k < 64u; k++) {
      uint32_t v = entropy_sample();
      if (v > 0xFFFFu) v = 0xFFFFu;
      d[4 * k] = hx[(v >> 12) & 15]; d[4 * k + 1] = hx[(v >> 8) & 15];
      d[4 * k + 2] = hx[(v >> 4) & 15]; d[4 * k + 3] = hx[v & 15];
    }
    d[256] = 0;
    sec_watchdog_kick();
    printf("{\"type\":\"entropy_raw\",\"periods\":%lu,\"i\":%lu,\"d\":\"%s\"}\r\n",
           (unsigned long)periods, (unsigned long)line, d);
  }
  entropy_stop();
  printf("{\"type\":\"entropy_done\",\"periods\":%lu,\"samples\":32768}\r\n", (unsigned long)periods);
}
#endif

/* Commands over the serial port (polled, one byte per loop pass at most, so a flood of
   characters cannot block the loop):
     Q<128 hex digits>\n ECDH provisioning with the PC's public key (only when no secret is present)
     H                   demo only: hang the main loop (watchdog demo)                    */
void sec_poll_commands(void)
{
  static char line[140];
  static uint32_t n;
  if (!(USART2->SR & USART_SR_RXNE)) return;
  char c = (char)USART2->DR;
#if SEC_DEMO_COMMANDS
  if (c == 'H' && n == 0) {
    printf("{\"type\":\"info\",\"msg\":\"demo: main loop hung on purpose, the watchdog should reset the chip\"}\r\n");
    __disable_irq();
    for (;;) { }                    /* no refresh: the IWDG resets the chip after ~250 ms */
  }
#endif
  if (c == '\r' || c == '\n') {
    if (n == 129 && line[0] == 'Q') sec_secret_provision_ecdh(line + 1);
#if SEC_DEMO_COMMANDS
    else if (n == 2 && line[0] == 'E' && (line[1] == '1' || line[1] == '2' || line[1] == '4' || line[1] == '8'))
      entropy_dump((uint32_t)(line[1] - '0'));
#endif
    n = 0;
  } else if (n < sizeof line) line[n++] = c;
  else n = sizeof line;             /* too long: ignored until the next newline */
}

/* ------------------------------------------------------------------ tamper + device secret
   The secret is a 128-bit key kept in RTC backup registers BKP1-BKP4 (BKP0 = marker,
   BKP5 = "blank since power-up" marker). It stands in for the keys a real ECU keeps there
   (SecOC / diagnostic keys). The chip creates it itself (ECDH with the provisioning PC,
   from its own entropy source, see sec_secret_provision_ecdh), only into an empty slot, and
   never sends it out: only a 32-bit fingerprint is printed.
   A tamper event erases all backup registers in hardware, immediately, even if the core is
   stuck. With a coin cell on VBAT this also works with the board unpowered; on the Nucleo,
   VBAT is tied to VDD, so unplugging USB also erases them (the next boot reports
   "missing" with power_lost, not "erased"). */
/* SPLIT KEY. The 128-bit secret k is never stored as such: k = A XOR B, with
     share A in the RTC backup registers BKP1-BKP4 (marker BKP0): erased by a TAMPER event
     share B in the 4 KB backup SRAM, words 0-3 (marker word 4):  erased when read protection
             is lowered from level 1 to 0 (the "debug unlock" that also mass-erases the flash)
   Each share alone is uniformly random (B comes from the entropy source), so destroying
   either one destroys the key. Measured on this board: an RDP 1 -> 0 regression erased the
   flash and the backup SRAM but NOT the backup registers (RESULTS.md section 7), which is
   why a key kept only in the backup registers survived a debug unlock. */
#define SECRET_MARK  0x5EC2E7A1u   /* BKP0: share A present */
#define SHARE_B_MARK 0x5EC2B5A3u   /* backup SRAM word 4: share B present */
#define BLANK_MARK   0xB1A4C000u   /* BKP5: power was lost, slot empty, waiting for a key */
/* BKP6: boot counter since provisioning (for signed lines) */
#define UNLOCK_MARK  0xDEB06A1Bu   /* BKP7: the key was destroyed by a debug unlock (kept across resets;
                                      a tamper clears it like every backup register) */
#define BKP(n) (*(&RTC->BKP0R + (n)))
#define BKSRAM ((volatile uint32_t *)BKPSRAM_BASE)

typedef enum { SECRET_PRESENT, SECRET_MISSING, SECRET_ERASED } secret_state_t;
static secret_state_t secret_state;
static const char *erased_by = "";     /* "tamper" or "debug_unlock" */
static int power_lost;

static int key_present(void) { return BKP(0) == SECRET_MARK && BKSRAM[4] == SHARE_B_MARK; }
static uint32_t key_word(int w) { return BKP(1 + w) ^ BKSRAM[w]; }     /* word w of k = A XOR B */
static void key_get(uint8_t k[16])
{
  for (int i = 0; i < 16; i++) k[i] = (uint8_t)(key_word(i / 4) >> (24 - 8 * (i % 4)));
}
static void key_wipe(void)             /* destroy both shares (one is already gone) */
{
  for (int i = 0; i < 5; i++) { BKP(i) = 0; BKSRAM[i] = 0; }
}
/* hand the current key (or its absence) to the SecOC layer; a tamper that wipes the key
   therefore also ends CAN authentication */
static void secoc_refresh_key(void)
{
  if (key_present()) { uint8_t k[16]; key_get(k); secoc_set_key(k); memset(k, 0, sizeof k); }
  else secoc_set_key(NULL);
}
static volatile int tamper_pending;
static int tamper_armed;
static uint32_t release_tick;

static uint32_t secret_id(void)        /* FNV-1a over the 16 key bytes: a fingerprint, not the key */
{
  uint32_t h = 2166136261u;
  for (int w = 0; w < 4; w++)
    for (int b = 0; b < 4; b++) { h ^= (key_word(w) >> (8 * b)) & 0xFFu; h *= 16777619u; }
  return h;
}

/* Level detection with a digital filter, not edge detection: the input must read low on
   4 consecutive samples (TAMPFLT = 10) taken at RTCCLK / 256 (LSI ~32 kHz -> one sample every
   ~8 ms, so a press is confirmed after ~32 ms). The internal pull-up precharges the pin before
   each sample. Edge mode without a filter was tried first: enabling it erased the backup
   registers by itself, with the button up (measured, see RESULTS.md section 7).
   Configuration first, TAMP1E in a second write. */
#define TAMPER_CFG ((2u << RTC_TAFCR_TAMPFLT_Pos)   /* 4 consecutive low samples */ \
                  | (7u << RTC_TAFCR_TAMPFREQ_Pos)  /* RTCCLK / 256 */              \
                  | (1u << RTC_TAFCR_TAMPPRCH_Pos)  /* precharge 2 RTCCLK cycles */  \
                  | RTC_TAFCR_TAMPIE)               /* TAMP1TRG = 0: low level triggers */
static void tamper_arm(void)
{
  RTC->TAFCR = TAMPER_CFG;                   /* TAMP1E off */
  RTC->ISR &= ~RTC_ISR_TAMP1F;
  EXTI->PR = EXTI_PR_PR21;
  RTC->TAFCR = TAMPER_CFG | RTC_TAFCR_TAMP1E;
  tamper_armed = 1;
}

void sec_tamper_init(void)
{
  RCC->APB1ENR |= RCC_APB1ENR_PWREN;
  (void)RCC->APB1ENR;
  PWR->CR |= PWR_CR_DBP;                     /* allow writes to the backup domain */
  if (!(RCC->BDCR & RCC_BDCR_RTCEN)) {        /* backup domain was reset: power was lost */
    power_lost = 1;
    RCC->CSR |= RCC_CSR_LSION;
    while (!(RCC->CSR & RCC_CSR_LSIRDY)) { }
    if (!(RCC->BDCR & RCC_BDCR_RTCSEL)) RCC->BDCR |= 2u << RCC_BDCR_RTCSEL_Pos;   /* RTC clock = LSI */
    RCC->BDCR |= RCC_BDCR_RTCEN;
  }
  /* A tamper erases every backup register, BKP5 included, so "erased" can only mean a tamper
     (since the last power-up), and an empty slot after a power loss stays "missing" across resets. */
  RCC->AHB1ENR |= RCC_AHB1ENR_BKPSRAMEN;      /* share B lives in the backup SRAM */
  (void)RCC->AHB1ENR;
  if (power_lost) BKP(5) = BLANK_MARK;
  int a = BKP(0) == SECRET_MARK, b = BKSRAM[4] == SHARE_B_MARK;
  if (a && b) { secret_state = SECRET_PRESENT; BKP(6) = BKP(6) + 1; }
  else if (!a && BKP(5) == BLANK_MARK) secret_state = SECRET_MISSING;   /* not provisioned since power-up */
  else {
    secret_state = SECRET_ERASED;
    if (a) BKP(7) = UNLOCK_MARK;               /* share A left, share B gone: RDP regression (debug unlock) */
    erased_by = BKP(7) == UNLOCK_MARK ? "debug_unlock" : "tamper";
    key_wipe();
  }

  EXTI->IMR |= EXTI_IMR_MR21;                /* RTC tamper/timestamp = EXTI line 21, rising */
  EXTI->RTSR |= EXTI_RTSR_TR21;
  NVIC_SetPriority(TAMP_STAMP_IRQn, 15);     /* lowest: never delays CAN reception */
  NVIC_EnableIRQ(TAMP_STAMP_IRQn);
  if (GPIOC->IDR & GPIO_IDR_ID13) tamper_arm();   /* only arm with the switch closed (button up) */
  else release_tick = HAL_GetTick();
  secoc_refresh_key();                             /* give the SecOC layer the key (or clear it) */
}

/* The backup registers are already erased by the hardware when this runs. */
void TAMP_STAMP_IRQHandler(void)
{
  if (RTC->ISR & RTC_ISR_TAMP1F) {
    RTC->TAFCR &= ~RTC_TAFCR_TAMP1E;
    RTC->ISR &= ~RTC_ISR_TAMP1F;
    tamper_armed = 0;
    tamper_pending = 1;
  }
  EXTI->PR = EXTI_PR_PR21;
}

void sec_tamper_poll(void)
{
  if (tamper_pending) {
    tamper_pending = 0;
    secret_state = SECRET_ERASED;
    erased_by = "tamper";
    int zero = BKP(0) == 0 && BKP(1) == 0 && BKP(2) == 0 && BKP(3) == 0 && BKP(4) == 0 && BKP(5) == 0;
    key_wipe();                              /* share A is gone (hardware); clear share B too */
    secoc_refresh_key();                     /* key gone: CAN authentication stops too */
    GPIOA->BSRR = GPIO_BSRR_BS5;             /* LD2 on: stays on until the next reset */
    ind_tamper();                            /* 5 fast beeps */
    printf("{\"type\":\"tamper\",\"t_ms\":%lu,\"msg\":\"enclosure opened: device secret erased\","
           "\"backup_registers_zero\":%s}\r\n", HAL_GetTick(), zero ? "true" : "false");
    release_tick = HAL_GetTick();
  }
  /* re-arm once the button has been up for 50 ms (arming while pressed would fire again) */
  if (!tamper_armed) {
    if (!(GPIOC->IDR & GPIO_IDR_ID13)) release_tick = HAL_GetTick();
    else if (HAL_GetTick() - release_tick >= 50u) tamper_arm();
  }
}

int sec_secret_ok(void) { return secret_state == SECRET_PRESENT; }
const char *sec_secret_state(void)
{
  return secret_state == SECRET_PRESENT ? "present" : secret_state == SECRET_ERASED ? "erased" : "missing";
}

const char *sec_secret_json(void)
{
  static char buf[112];
  if (secret_state == SECRET_PRESENT)
    snprintf(buf, sizeof buf, "\"secret\":\"present\",\"secret_id\":\"%08lx\"", (unsigned long)secret_id());
  else if (secret_state == SECRET_MISSING)                /* BKP5 marker = power was lost */
    snprintf(buf, sizeof buf, "\"secret\":\"missing\",\"secret_id\":null,\"power_lost\":true");
  else
    snprintf(buf, sizeof buf, "\"secret\":\"erased\",\"secret_id\":null,\"erased_by\":\"%s\"", erased_by);
  return buf;
}

static int hexval(char c)
{
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

/* ECDH provisioning: "Q" + the PC's P-256 public key (128 hex digits = X || Y) + newline.
   1. the chip checks the PC's key is a valid curve point
   2. 4096 entropy samples (LSI jitter) -> health tests -> SHA-256 -> 256-bit seed
   3. a fresh P-256 key pair from that seed; the private key never leaves the chip
   4. shared = ECDH(chip private key, PC public key); the PC computes the same value with its
      private key and the chip's public key. Only the two public keys cross the cable.
   5. device secret = first 16 bytes of SHA-256("can-ids hmac key v1" || shared || chip pub || PC pub)
   The chip private key, the shared value and the seed are wiped. Refused while a secret is
   present: the slot is written once, then only a tamper (or power loss) clears it.
   Unauthenticated ECDH: it defeats someone *listening* on the cable during provisioning, not
   someone who can replace the PC's key with their own (the station must be trusted). */
static uint8_t drbg_seed[32];
static uint32_t drbg_ctr;

static int drbg_rng(uint8_t *dest, unsigned size)     /* SHA-256(seed || counter) blocks */
{
  while (size) {
    uint8_t blk[36], out[32];
    memcpy(blk, drbg_seed, 32);
    memcpy(blk + 32, &drbg_ctr, 4);
    drbg_ctr++;
    sha256(blk, sizeof blk, out);
    unsigned k = size < 32u ? size : 32u;
    memcpy(dest, out, k);
    dest += k; size -= k;
    memset(out, 0, sizeof out);
  }
  return 1;
}

static void hex_out(const uint8_t *d, uint32_t n, char *out)
{
  static const char hx[] = "0123456789abcdef";
  for (uint32_t i = 0; i < n; i++) { out[2 * i] = hx[d[i] >> 4]; out[2 * i + 1] = hx[d[i] & 15]; }
  out[2 * n] = 0;
}

static void provision_refused(const char *why)
{
  printf("{\"type\":\"provision\",\"ok\":false,\"msg\":\"%s\"}\r\n", why);
}

void sec_secret_provision_ecdh(const char *hex128)
{
  const struct uECC_Curve_t *curve = uECC_secp256r1();
  uint8_t pc_pub[64], dev_pub[64], dev_priv[32], shared[32], k[32];
  for (int i = 0; i < 128; i++) {
    int v = hexval(hex128[i]);
    if (v < 0) { provision_refused("bad key format"); return; }
    pc_pub[i / 2] = (uint8_t)((pc_pub[i / 2] << 4) | v);
  }
  if (secret_state == SECRET_PRESENT) { provision_refused("a secret is already present: refused"); return; }
  if (!uECC_valid_public_key(pc_pub, curve)) { provision_refused("the PC public key is not a valid P-256 point"); return; }

  sec_watchdog_start(2000u);                 /* key generation blocks for a while: longer timeout */
  uint32_t t0 = HAL_GetTick();
  entropy_stats_t st;
  if (!entropy_seed(drbg_seed, &st)) {
    sec_watchdog_start(SEC_WATCHDOG_MS);
    printf("{\"type\":\"provision\",\"ok\":false,\"msg\":\"entropy source failed its health test\","
           "\"max_repeat\":%lu,\"max_same_low_byte\":%lu}\r\n", st.max_repeat, st.max_same_low_byte);
    return;
  }
  uint32_t t_entropy = HAL_GetTick() - t0;
  drbg_ctr = 0;
  uECC_set_rng(drbg_rng);
  int ok = uECC_make_key(dev_pub, dev_priv, curve) && uECC_shared_secret(pc_pub, dev_priv, shared, curve);
  uint32_t t_total = HAL_GetTick() - t0;
  sec_watchdog_start(SEC_WATCHDOG_MS);
  if (ok) {
    sha256_ctx c;
    sha256_init(&c);
    sha256_update(&c, "can-ids hmac key v1", 19);
    sha256_update(&c, shared, 32);
    sha256_update(&c, dev_pub, 64);
    sha256_update(&c, pc_pub, 64);
    sha256_final(&c, k);
    uint8_t share_b[16];
    drbg_rng(share_b, sizeof share_b);       /* fresh random share B, from the same seed */
    for (int w = 0; w < 4; w++) {
      uint32_t kw = (uint32_t)k[4 * w] << 24 | (uint32_t)k[4 * w + 1] << 16 | (uint32_t)k[4 * w + 2] << 8 | k[4 * w + 3];
      uint32_t bw = (uint32_t)share_b[4 * w] << 24 | (uint32_t)share_b[4 * w + 1] << 16 |
                    (uint32_t)share_b[4 * w + 2] << 8 | share_b[4 * w + 3];
      BKSRAM[w] = bw;                         /* share B: backup SRAM */
      BKP(w + 1) = kw ^ bw;                   /* share A: backup registers */
    }
    memset(share_b, 0, sizeof share_b);
    BKSRAM[4] = SHARE_B_MARK;
    BKP(7) = 0;
    BKP(0) = SECRET_MARK;
    BKP(5) = 0;
    BKP(6) = 1;                               /* first boot of this key */
    secret_state = SECRET_PRESENT;
    secoc_refresh_key();                      /* the new key is also the SecOC key */
  }
  memset(dev_priv, 0, sizeof dev_priv); memset(shared, 0, sizeof shared); memset(k, 0, sizeof k);
  memset(drbg_seed, 0, sizeof drbg_seed);
  if (!ok) { provision_refused("key generation failed"); return; }
  char pub_hex[129];
  hex_out(dev_pub, 64, pub_hex);
  printf("{\"type\":\"provision\",\"ok\":true,\"method\":\"ecdh-p256\",\"device_pub\":\"%s\",\"secret_id\":\"%08lx\","
         "\"entropy_samples\":%lu,\"max_repeat\":%lu,\"max_same_low_byte\":%lu,\"entropy_ms\":%lu,\"total_ms\":%lu}\r\n",
         pub_hex, (unsigned long)secret_id(), st.samples, st.max_repeat, st.max_same_low_byte, t_entropy, t_total);
}

/* ------------------------------------------------------------------ signed serial lines
   Every JSON line the Nucleo sends is signed with the device secret, so the PC can tell a
   real alert from one typed into the USB link (or a modified one). printf() output is put
   back together line by line here (some lines come from several printf calls); a complete
   JSON object {...} gets three more fields before it is sent:
       "boot":B   boot counter since provisioning (backup register BKP6)
       "seq":N    line counter since this boot
       "mac":"<32 hex>"  HMAC-SHA256 with the device secret, first 128 bits, computed over the
                  line up to and including "seq":N}  (without the mac field), or null when
                  the secret is missing or erased (the line can then not be trusted).
   (boot, seq) only goes up, so the PC rejects a genuine line replayed later.
   Lines that are not JSON (boot banner, self-test text) are sent unsigned, as before. */
static char line_buf[1100];
static uint32_t line_n, seq_no;
static uint32_t hmac_cycles;

static void uart_send(const char *p, uint32_t n)
{
  HAL_UART_Transmit(&huart2, (uint8_t *)p, (uint16_t)n, HAL_MAX_DELAY);
}

static void send_line(void)
{
  static const char hx[] = "0123456789abcdef";
  char *b = line_buf;
  uint32_t n = line_n;
  line_n = 0;
  if (n >= 3 && b[0] == '{' && b[n - 1] == '\n' && b[n - 2] == '\r' && b[n - 3] == '}'
      && n + 96 < sizeof line_buf) {
    n -= 3;                                                   /* drop "}\r\n" */
    n += (uint32_t)sprintf(b + n, ",\"boot\":%lu,\"seq\":%lu}", (unsigned long)BKP(6), (unsigned long)seq_no++);
    if (key_present()) {                                      /* read the key now: a tamper may have just erased it */
      uint8_t key[16], mac[32];
      key_get(key);
      uint32_t t0 = DWT->CYCCNT;
      hmac_sha256(key, sizeof key, b, n, mac);
      hmac_cycles = DWT->CYCCNT - t0;
      memset(key, 0, sizeof key);
      n -= 1;                                                 /* drop '}' */
      memcpy(b + n, ",\"mac\":\"", 8); n += 8;
      for (int i = 0; i < 16; i++) { b[n++] = hx[mac[i] >> 4]; b[n++] = hx[mac[i] & 15]; }
      memcpy(b + n, "\"}\r\n", 4); n += 4;
    } else {
      n -= 1;
      memcpy(b + n, ",\"mac\":null}\r\n", 14); n += 14;
    }
  }
  uart_send(b, n);
}

/* called by _write() (printf) */
void sec_write(const char *p, int len)
{
  for (int i = 0; i < len; i++) {
    if (line_n >= sizeof line_buf - 100) { uart_send(line_buf, line_n); line_n = 0; }   /* too long: unsigned */
    line_buf[line_n++] = p[i];
    if (p[i] == '\n') send_line();
  }
}

uint32_t sec_last_hmac_cycles(void) { return hmac_cycles; }
