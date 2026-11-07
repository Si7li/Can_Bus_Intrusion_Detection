/* Device protection (step 3): watchdog, reset cause, protection settings report.
   Register-level (RM0390 reference manual), so no extra HAL module is needed. */
#include "ids_security.h"
#include <stdio.h>

static const char *reset_cause = "unknown";

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
}

const char *sec_reset_cause(void) { return reset_cause; }

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
  printf("{\"type\":\"boot\",\"reset\":\"%s\",\"rdp\":\"%s\",\"bor\":\"%s\",\"wrp_sectors\":%s,"
         "\"watchdog\":\"%s\",\"watchdog_ms\":%lu,\"demo_commands\":%s}\r\n",
         reset_cause, rdp_s, bor_s[(opt >> 2) & 3u], wrp, (opt & FLASH_OPTCR_WDG_SW) ? "software" : "hardware",
         (unsigned long)SEC_WATCHDOG_MS, SEC_DEMO_COMMANDS ? "true" : "false");
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

/* Demo commands over the serial port (polled, so a flood of characters cannot block
   the loop): one byte per loop pass at most. */
void sec_poll_commands(void)
{
#if SEC_DEMO_COMMANDS
  if (!(USART2->SR & USART_SR_RXNE)) return;
  char c = (char)USART2->DR;
  if (c == 'H') {
    printf("{\"type\":\"info\",\"msg\":\"demo: main loop hung on purpose, the watchdog should reset the chip\"}\r\n");
    __disable_irq();
    for (;;) { }                    /* no refresh: the IWDG resets the chip after ~250 ms */
  }
#else
  if (USART2->SR & USART_SR_RXNE) (void)USART2->DR;   /* drop it */
#endif
}
