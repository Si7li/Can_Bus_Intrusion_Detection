/* Device protection (step 3): watchdog, reset cause, protection settings report.
 *
 *   sec_capture_reset_cause()  first thing in main(): why did the chip (re)start?
 *   sec_report_boot()          one JSON line: reset cause + option bytes (RDP, BOR, WRP, watchdog mode)
 *   sec_watchdog_start(ms)     start the independent watchdog (IWDG); cannot be stopped afterwards
 *   sec_watchdog_kick()        refresh it, once per main-loop pass
 *   sec_poll_commands()        demo commands from the PC over the ST-LINK serial port
 */
#ifndef IDS_SECURITY_H
#define IDS_SECURITY_H

#include <stdint.h>
#include "stm32f4xx.h"

/* 1 = accept demo commands on the serial port ('H' = hang the main loop, to show the
   watchdog reset). Set to 0 for a production build: the port then accepts nothing. */
#ifndef SEC_DEMO_COMMANDS
#define SEC_DEMO_COMMANDS 1
#endif

/* IWDG timeout. The IWDG runs on the internal LSI oscillator, which is only accurate to
   17-47 kHz (datasheet), so 250 ms nominal can be as short as ~170 ms. The longest main-loop
   pass measured is a full 256-frame queue (256 x 63 us = 16 ms) plus a few JSON lines. */
#define SEC_WATCHDOG_MS 250u

void sec_capture_reset_cause(void);
const char *sec_reset_cause(void);
void sec_report_boot(void);
void sec_watchdog_start(uint32_t ms);
void sec_poll_commands(void);

static inline void sec_watchdog_kick(void) { IWDG->KR = 0xAAAAu; }

#endif
