# micro-ecc (third-party)

Elliptic-curve library by Kenneth MacKay, BSD 2-clause licence (`LICENSE.txt`).
Source: https://github.com/kmackay/micro-ecc, commit `541b3a78026420a3e369c4c9281c396b5e531113`
(2024-11-14), files copied unchanged (AVR assembly and tests left out).

Used for: ECDH key agreement at provisioning (secp256r1 / NIST P-256), and the ECDSA
signature check of the secure bootloader. Only P-256 is compiled in
(`-DuECC_SUPPORTS_secp*=0` for the other curves, see `firmware/build.sh`); compiled with
-O2 and its ARM Thumb-2 assembly. It has no random generator on bare metal: the firmware
gives it one (`uECC_set_rng`, fed by the on-chip entropy source, `ids_entropy.c`).
