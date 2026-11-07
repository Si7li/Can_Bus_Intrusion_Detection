/* SecOC-style authentication of chosen CAN IDs (AUTOSAR Secure Onboard Communication idea).
 *
 * Protected IDs and their authenticator frames:
 *     0x386 speedometer (wheel speeds)  ->  0x786
 *     0x2B0 steering angle sensor       ->  0x7B0
 * Right after each protected frame, the sending ECU sends an 8-byte authenticator frame:
 *     bytes 0-3  freshness counter (32 bits, big endian, +1 per frame)
 *     bytes 4-7  first 32 bits of AES-CMAC(K, data ID (2 bytes BE) || DLC || data || freshness)
 * K = first 16 bytes of SHA-256("can-ids secoc v1" || device secret): no extra provisioning,
 * and a tamper (which destroys the device secret) also ends the authentication.
 *
 * Difference from AUTOSAR SecOC: there, the truncated freshness and MAC go INSIDE the
 * protected frame (in place of data bytes). Here they travel in a companion frame, so the
 * car's original data, and the detector trained on it, stay unchanged.
 *
 * Rejected (reported as an ALERT incident on the protected ID):
 *     auth_mac      MAC wrong: data changed in transit or forged (values may look normal)
 *     auth_replay   MAC right but freshness not newer: a recorded frame sent again
 *     auth_missing  protected frame without its authenticator within 5 ms: injected frame
 * An ID is checked once it has carried one valid authenticator since boot ("armed"): a real
 * ECU would know from its configuration which IDs are secured; arming on first use keeps
 * recordings without authenticators (the offline test replays) working unchanged.
 */
#ifndef IDS_SECOC_H
#define IDS_SECOC_H

#include <stdint.h>

#define SECOC_R_MAC     0x10u    /* same flag space as IDS_R_* (ids_detector.h) */
#define SECOC_R_REPLAY  0x20u
#define SECOC_R_MISSING 0x40u

typedef struct {
  uint16_t id;                   /* protected ID that failed */
  uint8_t reason;                /* SECOC_R_* */
} secoc_fail_t;

void secoc_set_key(const uint8_t device_secret[16]);   /* NULL = no key (missing / tamper) */
/* For every received frame. Returns 1 if the frame was an authenticator (consumed: do not
   give it to the detector). *fail is set when a check failed (fail->reason != 0). */
int secoc_frame(uint16_t id, uint8_t dlc, const uint8_t data[8], uint32_t t_us, secoc_fail_t *fail);
/* Main loop: a protected frame whose authenticator never came. */
int secoc_poll(uint32_t now_us, secoc_fail_t *fail);
void secoc_reset(void);          /* bus idle > 1 s: forget pending frames (keeps armed IDs) */
const char *secoc_json(void);    /* ,"secoc":{...} for the status line */

#endif
