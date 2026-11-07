"""Secure boot demos (L1): try to get the bootloader to start firmware it must refuse.

    python pc/secure_boot_demo.py           # all tests, ~1 min; leaves a valid image installed

Starts from the build in firmware/can_ids_fw/build/can_ids_fw.bin. Each test writes an image
(header + application at 0x0800C000) over SWD, restarts the chip and reads the bootloader's
verdict on the serial port:

  valid        correctly signed, version N+1                    -> must start
  modified     one byte of the application changed, same header -> "image hash mismatch"
  header       version field raised in the header, not re-signed -> "bad signature"
  wrong_key    signed with another private key (an attacker's)   -> "bad signature"
  unsigned     application without a header                      -> "no valid image header"
  rollback     correctly signed but OLDER version N              -> "rollback"
  restore      the valid image again                             -> must start

N = the bootloader's current minimum version, so every run raises the minimum by one
(the anti-rollback log in flash sector 2 only goes up). Results are appended to
results/security_tests.txt.
"""

import json
import time

import serial
from cryptography.hazmat.primitives.asymmetric import ec

import sign_firmware as sf
from security_demo import log, read_lines


def verdict(s: serial.Serial, image: bytes) -> dict | None:
    """Flash an image, restart, return the bootloader's JSON line."""
    path = sf.BUILD / "test_image.bin"
    path.write_bytes(image)
    s.reset_input_buffer()
    if not sf.flash(path):
        raise SystemExit("flashing failed")
    for _, text in read_lines(s, 3.0):
        if text.startswith("{") and '"type":"secure_boot"' in text:
            return json.loads(text)
    return None


def main():
    app = sf.APP_BIN.read_bytes()
    app += b"\xff" * (-len(app) % 4)
    key = sf.load_key()
    pad = b"\xff" * (sf.APP_ADDR - sf.HEADER_ADDR - 128)
    with serial.Serial("/dev/ttyACM0", 921600, timeout=0.05) as s:
        time.sleep(0.3)
        first = verdict(s, sf.signed_image(app, 1, key)) or {}
        n = first.get("min_version", 0)
        valid = sf.signed_image(app, n + 1, key)
        header, body = valid[:128], valid[len(pad) + 128:]

        modified_app = bytearray(body)
        modified_app[len(body) // 2] ^= 0x01                         # one bit, in the middle of the code
        raised = bytearray(header)
        raised[8:12] = (n + 100).to_bytes(4, "little")               # fw_version, signature unchanged
        attacker = ec.generate_private_key(ec.SECP256R1())

        tests = [
            ("valid", valid, True, None),
            ("modified", header + pad + bytes(modified_app), False, "hash mismatch"),
            ("header", bytes(raised) + pad + body, False, "bad signature"),
            ("wrong_key", sf.signed_image(app, n + 1, attacker), False, "bad signature"),
            ("unsigned", b"\xff" * (128 + len(pad)) + body, False, "no valid image header"),
            ("rollback", sf.signed_image(app, n, key), False, "rollback"),
            ("restore", valid, True, None),
        ]
        results = []
        for name, image, should_start, reason in tests:
            v = verdict(s, image)
            started = bool(v and v["ok"])
            passed = v is not None and started == should_start and (reason is None or reason in v.get("reason", ""))
            what = (f"started (version {v['fw_version']}, check {v['signature_ms']} + {v['hash_ms']} ms)" if started
                    else f"refused: {v['reason']}" if v else "no answer")
            print(f"{name:10s} {'PASS' if passed else 'FAIL'}  {what}")
            results.append((name, passed, what))
    all_ok = all(p for _, p, _ in results)
    log("secureboot", all_ok, "; ".join(f"{n}: {w}" for n, _, w in results))


if __name__ == "__main__":
    main()
