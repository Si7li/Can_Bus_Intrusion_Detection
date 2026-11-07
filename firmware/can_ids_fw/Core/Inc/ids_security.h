/* Device protection (step 3): watchdog, reset cause, protection settings report.
 *
 *   sec_capture_reset_cause()  first thing in main(): why did the chip (re)start?
 *   sec_report_boot()          one JSON line: reset cause + option bytes (RDP, BOR, WRP, watchdog mode)
 *   sec_watchdog_start(ms)     start the independent watchdog (IWDG); cannot be stopped afterwards
 *   sec_watchdog_kick()        refresh it, once per main-loop pass
 *   sec_poll_commands()        demo commands from the PC over the ST-LINK serial port
 *   sec_tamper_init/poll()     tamper switch on PC13 erases the device secret (backup registers)
 *   sec_write()                printf output; every JSON line is signed with the device secret
 */
#ifndef IDS_SECURITY_H
#define IDS_SECURITY_H

#include <stdint.h>
#include "stm32f4xx.h"

/* 1 = accept the demo command 'H' on the serial port (hang the main loop, to show the
   watchdog reset). Set to 0 for a production build: the port then only accepts ECDH provisioning. */
#ifndef SEC_DEMO_COMMANDS
#define SEC_DEMO_COMMANDS 1
#endif

/* IWDG timeout. The IWDG runs on the internal LSI oscillator, which is only accurate to
   17-47 kHz (datasheet), so 250 ms nominal can be as short as ~170 ms. The longest main-loop
   pass measured is a full 256-frame queue (256 x 63 us = 16 ms) plus a few JSON lines. */
#define SEC_WATCHDOG_MS 250u

/* Tamper (PC13 = RTC_AF1 = the Nucleo's blue USER button, active low): a falling edge makes
   the hardware erase the RTC backup registers, where the device secret lives. */
void sec_capture_reset_cause(void);
void sec_tamper_init(void);          /* after the GPIO init, before sec_report_boot() */
void sec_tamper_poll(void);          /* main loop: report a tamper event, re-arm after release */
int sec_secret_ok(void);
const char *sec_secret_state(void);  /* present | missing | erased */
const char *sec_secret_json(void);   /* "secret":"present|new|erased","secret_id":"..." */
void sec_secret_provision_ecdh(const char *hex128);   /* "Q" + PC public key */
const char *sec_reset_cause(void);
void sec_report_boot(void);
void sec_watchdog_start(uint32_t ms);
void sec_poll_commands(void);
void sec_uart_rx_start(void);       /* serial receive by interrupt (call after HAL_UART_Init) */

void sec_write(const char *p, int len);   /* printf output: signs every JSON line (HMAC-SHA256) */
uint32_t sec_last_hmac_cycles(void);

static inline void sec_watchdog_kick(void) { IWDG->KR = 0xAAAAu; }

#endif
