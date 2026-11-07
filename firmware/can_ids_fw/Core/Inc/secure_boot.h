/* Secure boot: flash layout, signed image header, boot report. Shared by the bootloader
 * (bootloader/) and the application (firmware/can_ids_fw).
 *
 *   0x08000000  sectors 0-1  32 KB   bootloader + firmware public key   (write-protected, step 3e)
 *   0x08008000  sector 2     16 KB   bootloader state: anti-rollback log
 *   0x0800C000  sector 3     16 KB   image header (sb_header_t), rewritten with every update
 *   0x08010000  sectors 4-7 448 KB   application
 *
 * The PC signs a build with pc/sign_firmware.py: it writes the header (version, size,
 * SHA-256 of the application) and an ECDSA P-256 signature over the header's first 64 bytes,
 * made with the private key in keys/ (never on the chip). At every reset the bootloader
 * checks the signature with the public key compiled into it, then the image hash, then the
 * version against the newest version it has accepted before (anti-rollback), and only then
 * starts the application.
 */
#ifndef SECURE_BOOT_H
#define SECURE_BOOT_H

#include <stdint.h>

#define SB_BOOT_ADDR      0x08000000u
#define SB_STATE_ADDR     0x08008000u     /* sector 2 */
#define SB_STATE_SIZE     0x4000u
#define SB_STATE_SECTOR   2u
#define SB_HEADER_ADDR    0x0800C000u     /* sector 3 */
#define SB_APP_ADDR       0x08010000u     /* sector 4 */
#define SB_APP_MAX        (448u * 1024u)

#define SB_MAGIC          0x53444943u     /* "CIDS" little endian */
#define SB_HEADER_VERSION 1u
#define SB_SIGNED_BYTES   64u             /* header bytes covered by the signature */

typedef struct {
  uint32_t magic;               /* SB_MAGIC */
  uint32_t header_version;      /* SB_HEADER_VERSION */
  uint32_t fw_version;          /* monotonic firmware version (anti-rollback) */
  uint32_t image_addr;          /* SB_APP_ADDR */
  uint32_t image_size;          /* bytes, multiple of 4 */
  uint32_t reserved[3];         /* 0 */
  uint8_t  image_sha256[32];    /* SHA-256 of image_size bytes at image_addr */
  uint8_t  signature[64];       /* ECDSA P-256 r || s over SHA-256(bytes 0..63 of this header) */
} sb_header_t;                  /* 128 bytes */

/* Anti-rollback log (sector 2): pairs of words (version, ~version), appended when a newer
   version is accepted; the minimum allowed version is the last valid pair. Erased = no
   version accepted yet. Erase sector 2 once when installing the bootloader. */

/* Boot report left by the bootloader in the last 16 bytes of RAM (both linker scripts end
   RAM 16 bytes early, so neither stack nor data overlaps it). */
typedef struct {
  uint32_t magic;               /* SB_BOOTINFO_MAGIC when the bootloader verified the image */
  uint32_t fw_version;
  uint32_t min_version;         /* anti-rollback minimum after this boot */
  uint32_t check_ms;            /* signature + hash time */
} sb_bootinfo_t;
#define SB_BOOTINFO       ((volatile sb_bootinfo_t *)0x2001FFF0u)
#define SB_BOOTINFO_MAGIC 0xB007C0DEu

#endif
