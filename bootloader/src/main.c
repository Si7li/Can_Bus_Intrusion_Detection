/* Secure bootloader for the CAN IDS (STM32F446RE). Runs at every reset, from 0x08000000.
 *
 *  1. read the image header (sector 3, secure_boot.h)
 *  2. ECDSA P-256 signature of the header, checked with the public key compiled in (fw_pubkey.h)
 *  3. SHA-256 of the application == the hash in the header
 *  4. version >= the newest version accepted before (anti-rollback log, sector 2)
 *  5. start the application at 0x08010000
 *
 * Any failure: the application is NOT started. The bootloader prints the reason on the
 * ST-LINK serial port (921600 baud, one JSON line every 2 s) and blinks LD2 fast. Recovery:
 * flash a correctly signed image (SWD keeps working; with RDP level 1 only after a mass erase).
 *
 * Register-level, no HAL: small, and nothing is left configured for the application except
 * what step 5 resets on purpose.
 */
#include <stdint.h>
#include <string.h>
#include "stm32f4xx.h"
#include "secure_boot.h"
#include "sha256.h"
#include "uECC.h"
#include "fw_pubkey.h"

#define CORE_HZ 168000000u

void SystemInit(void) { SCB->CPACR |= (0xFu << 20); }          /* FPU on (called by the startup code) */

/* ------------------------------------------------------------------ clock: HSI -> PLL 168 MHz */
static void clock_168mhz(void)
{
  RCC->APB1ENR |= RCC_APB1ENR_PWREN;
  (void)RCC->APB1ENR;
  PWR->CR |= PWR_CR_VOS;                                         /* voltage scale 1 */
  RCC->PLLCFGR = (16u << RCC_PLLCFGR_PLLM_Pos) | (336u << RCC_PLLCFGR_PLLN_Pos)   /* 16/16*336 = 336 MHz VCO */
               | (0u << RCC_PLLCFGR_PLLP_Pos)                    /* /2 = 168 MHz */
               | (7u << RCC_PLLCFGR_PLLQ_Pos) | (2u << RCC_PLLCFGR_PLLR_Pos);      /* source HSI (bit 22 = 0) */
  RCC->CR |= RCC_CR_PLLON;
  while (!(RCC->CR & RCC_CR_PLLRDY)) { }
  FLASH->ACR = FLASH_ACR_LATENCY_5WS | FLASH_ACR_PRFTEN | FLASH_ACR_ICEN | FLASH_ACR_DCEN;
  RCC->CFGR = RCC_CFGR_PPRE1_DIV4 | RCC_CFGR_PPRE2_DIV2 | RCC_CFGR_SW_PLL;          /* APB1 42 MHz */
  while ((RCC->CFGR & RCC_CFGR_SWS) != RCC_CFGR_SWS_PLL) { }
  CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;               /* cycle counter for timings */
  DWT->CYCCNT = 0;
  DWT->CTRL |= DWT_CTRL_CYCCNTENA_Msk;
}

/* back to the reset state, so the application's own clock setup starts from scratch */
static void clock_reset(void)
{
  RCC->CFGR = 0;                                                 /* SYSCLK = HSI 16 MHz */
  while ((RCC->CFGR & RCC_CFGR_SWS) != RCC_CFGR_SWS_HSI) { }
  RCC->CR &= ~RCC_CR_PLLON;
  while (RCC->CR & RCC_CR_PLLRDY) { }
  RCC->PLLCFGR = 0x24003010u;                                    /* reset value */
  FLASH->ACR = 0;
  RCC->AHB1RSTR = RCC_AHB1RSTR_GPIOARST;  RCC->AHB1RSTR = 0;
  RCC->APB1RSTR = RCC_APB1RSTR_USART2RST; RCC->APB1RSTR = 0;
  RCC->AHB1ENR = 0x00100000u;                                    /* reset values */
  RCC->APB1ENR = 0;
}

static void delay_ms(uint32_t ms)
{
  uint32_t t0 = DWT->CYCCNT;
  while (DWT->CYCCNT - t0 < ms * (CORE_HZ / 1000u)) { }
}

/* ------------------------------------------------------------------ serial port (USART2, PA2) and LD2 (PA5) */
static void io_init(void)
{
  RCC->AHB1ENR |= RCC_AHB1ENR_GPIOAEN;
  RCC->APB1ENR |= RCC_APB1ENR_USART2EN;
  (void)RCC->APB1ENR;
  GPIOA->MODER = (GPIOA->MODER & ~(GPIO_MODER_MODER2 | GPIO_MODER_MODER5))
               | GPIO_MODER_MODER2_1 | GPIO_MODER_MODER5_0;      /* PA2 alternate, PA5 output */
  GPIOA->AFR[0] = (GPIOA->AFR[0] & ~(0xFu << 8)) | (7u << 8);    /* PA2 = AF7 USART2_TX */
  USART2->BRR = 46u;                                             /* BRR = f_APB1 / baud = 42 MHz / 921,600 = 45.6 -> 46: 913,043 baud (-0.9%) */
  USART2->CR1 = USART_CR1_UE | USART_CR1_TE;
}

static void out_c(char c) { while (!(USART2->SR & USART_SR_TXE)) { } USART2->DR = (uint8_t)c; }
static void out_s(const char *s) { while (*s) out_c(*s++); }
static void out_u(uint32_t v)
{
  char b[11];
  int i = 10;
  b[i] = 0;
  do { b[--i] = (char)('0' + v % 10u); v /= 10u; } while (v);
  out_s(b + i);
}
static void out_flush(void) { while (!(USART2->SR & USART_SR_TC)) { } }

/* ------------------------------------------------------------------ anti-rollback log (sector 2) */
#define LOG ((const volatile uint32_t *)SB_STATE_ADDR)
#define LOG_WORDS (SB_STATE_SIZE / 4u)

/* newest accepted version; *next = index of the first free pair (LOG_WORDS if full);
   returns 0 if the log is corrupted (a pair whose second word is not the complement) */
static int log_read(uint32_t *min_version, uint32_t *next)
{
  *min_version = 0;
  for (uint32_t i = 0; i + 1u < LOG_WORDS; i += 2u) {
    uint32_t a = LOG[i], b = LOG[i + 1u];
    if (a == 0xFFFFFFFFu && b == 0xFFFFFFFFu) { *next = i; return 1; }
    if (b != ~a) { *next = i; return 0; }
    *min_version = a;
  }
  *next = LOG_WORDS;
  return 1;
}

static int flash_wait(void)
{
  while (FLASH->SR & FLASH_SR_BSY) { }
  return !(FLASH->SR & (FLASH_SR_WRPERR | FLASH_SR_PGAERR | FLASH_SR_PGPERR | FLASH_SR_PGSERR | FLASH_SR_OPERR));
}

static int log_append(uint32_t version, uint32_t next)
{
  int ok = 1;
  FLASH->KEYR = 0x45670123u;
  FLASH->KEYR = 0xCDEF89ABu;
  FLASH->SR = FLASH_SR_WRPERR | FLASH_SR_PGAERR | FLASH_SR_PGPERR | FLASH_SR_PGSERR | FLASH_SR_OPERR | FLASH_SR_EOP;
  if (next + 1u >= LOG_WORDS) {                                  /* full (after ~2,000 updates): start over */
    FLASH->CR = FLASH_CR_PSIZE_1 | FLASH_CR_SER | (SB_STATE_SECTOR << FLASH_CR_SNB_Pos);
    FLASH->CR |= FLASH_CR_STRT;
    ok = flash_wait();
    next = 0;
  }
  FLASH->CR = FLASH_CR_PSIZE_1 | FLASH_CR_PG;                    /* 32-bit programming */
  ((volatile uint32_t *)SB_STATE_ADDR)[next] = version;
  ok = ok && flash_wait();
  ((volatile uint32_t *)SB_STATE_ADDR)[next + 1u] = ~version;
  ok = ok && flash_wait();
  FLASH->CR = FLASH_CR_LOCK;
  return ok;
}

/* ------------------------------------------------------------------ refuse / start */
static void refuse(const char *reason, const sb_header_t *h, int header_ok, uint32_t min_version)
{
  for (uint32_t n = 0;; n++) {                                   /* never returns */
    if (n % 20u == 0u) {
      out_s("{\"type\":\"secure_boot\",\"ok\":false,\"reason\":\"");
      out_s(reason);
      out_s("\"");
      if (header_ok) { out_s(",\"fw_version\":"); out_u(h->fw_version); }
      out_s(",\"min_version\":"); out_u(min_version);
      out_s(",\"msg\":\"application NOT started\",\"mac\":null}\r\n");
    }
    GPIOA->ODR ^= GPIO_ODR_OD5;                                  /* LD2 blinks fast: refused */
    delay_ms(100);
  }
}

static void start_app(void)
{
  uint32_t sp = ((const uint32_t *)SB_APP_ADDR)[0];
  uint32_t pc = ((const uint32_t *)SB_APP_ADDR)[1];
  out_flush();
  __disable_irq();
  clock_reset();
  SysTick->CTRL = 0;
  for (int i = 0; i < 8; i++) { NVIC->ICER[i] = 0xFFFFFFFFu; NVIC->ICPR[i] = 0xFFFFFFFFu; }
  SCB->VTOR = SB_APP_ADDR;
  __DSB(); __ISB();
  __enable_irq();
  __asm volatile ("msr msp, %0\n\tbx %1" : : "r" (sp), "r" (pc));
  for (;;) { }
}

int main(void)
{
  const sb_header_t *h = (const sb_header_t *)SB_HEADER_ADDR;
  uint8_t digest[32];
  uint32_t min_version, next;

  clock_168mhz();
  io_init();
  SB_BOOTINFO->magic = 0;                                        /* only set once everything passed */
  if (!log_read(&min_version, &next)) refuse("anti-rollback log corrupted", h, 0, min_version);

  /* 1. header */
  if (h->magic != SB_MAGIC || h->header_version != SB_HEADER_VERSION) refuse("no valid image header", h, 0, min_version);
  if (h->image_addr != SB_APP_ADDR || h->image_size < 8u || h->image_size > SB_APP_MAX || (h->image_size & 3u))
    refuse("bad image size or address", h, 1, min_version);

  /* 2. signature over the header (which contains the image hash and the version) */
  uint32_t t0 = DWT->CYCCNT;
  sha256(h, SB_SIGNED_BYTES, digest);
  if (!uECC_verify(FW_PUBKEY, digest, sizeof digest, h->signature, uECC_secp256r1()))
    refuse("bad signature (not signed with the firmware key, or header changed)", h, 1, min_version);
  uint32_t t_sig = DWT->CYCCNT - t0;

  /* 3. the application itself */
  t0 = DWT->CYCCNT;
  sha256((const void *)SB_APP_ADDR, h->image_size, digest);
  if (memcmp(digest, h->image_sha256, 32) != 0) refuse("image hash mismatch (application changed)", h, 1, min_version);
  uint32_t t_hash = DWT->CYCCNT - t0;

  /* 4. anti-rollback */
  if (h->fw_version < min_version) refuse("rollback: version older than one already accepted", h, 1, min_version);
  if (h->fw_version > min_version) {
    if (!log_append(h->fw_version, next)) refuse("could not record the new version", h, 1, min_version);
    min_version = h->fw_version;
  }

  /* 5. sanity of the vector table, then start */
  uint32_t sp = ((const uint32_t *)SB_APP_ADDR)[0], pc = ((const uint32_t *)SB_APP_ADDR)[1];
  if (sp < 0x20000000u || sp > 0x20020000u || !(pc & 1u) || pc < SB_APP_ADDR || pc >= SB_APP_ADDR + h->image_size)
    refuse("bad vector table", h, 1, min_version);

  uint32_t check_ms = (t_sig + t_hash) / (CORE_HZ / 1000u);
  out_s("{\"type\":\"secure_boot\",\"ok\":true,\"fw_version\":"); out_u(h->fw_version);
  out_s(",\"min_version\":"); out_u(min_version);
  out_s(",\"image_size\":"); out_u(h->image_size);
  out_s(",\"signature_ms\":"); out_u(t_sig / (CORE_HZ / 1000u));
  out_s(",\"hash_ms\":"); out_u(t_hash / (CORE_HZ / 1000u));
  out_s(",\"msg\":\"signature and hash valid, starting the application\",\"mac\":null}\r\n");
  SB_BOOTINFO->fw_version = h->fw_version;
  SB_BOOTINFO->min_version = min_version;
  SB_BOOTINFO->check_ms = check_ms;
  SB_BOOTINFO->magic = SB_BOOTINFO_MAGIC;
  start_app();
}
