/* Status LEDs and buzzer (Nucleo Arduino header). Each LED: pin -> 220 ohm-1 kohm resistor ->
 * LED anode (long leg); LED cathode (short leg, flat side) -> GND. Never without the resistor.
 *
 *   D8  PA9   BLUE    CAN activity: blinks (~12 Hz) while frames arrive, off when the bus is idle
 *   D2  PA10  GREEN   everything normal (no incident open)
 *   D4  PB5   YELLOW  WARNING incident open (unusual values)
 *   D7  PA8   RED     ALERT incident open (attack evidence)
 *   D9  PC7   BUZZER  passive buzzer, 2.7 kHz tone from TIM3 channel 2: 3 beeps when an ALERT
 *                     starts, 5 fast beeps on a tamper. Bare 2-leg buzzer: 100 ohm in series
 *                     (or a transistor); a 3-pin buzzer module connects directly.
 *
 * At boot all four LEDs light for 0.3 s with a short chirp: a wiring check.
 * The incident logic stays in main.c; an incident ends 1 s after its last flagged frame,
 * so yellow / red stay on at least 1 s.
 */
#ifndef IDS_INDICATORS_H
#define IDS_INDICATORS_H

#include <stdint.h>

void ind_init(void);                          /* GPIO + buzzer timer + boot wiring check */
void ind_frame(void);                         /* one CAN frame processed */
void ind_alert(void);                         /* an ALERT incident started (or a WARNING escalated) */
void ind_tamper(void);                        /* tamper event */
void ind_poll(int incident_open, int level);  /* main loop: level 1 = WARNING, 2 = ALERT */

#endif
