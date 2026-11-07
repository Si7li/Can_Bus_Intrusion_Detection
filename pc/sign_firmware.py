"""Sign the IDS firmware for the secure bootloader (layout: firmware/can_ids_fw/Core/Inc/secure_boot.h).

    python pc/sign_firmware.py keygen                 # once: P-256 key pair -> keys/fw_signing_key.pem
                                                      #       + public key -> bootloader/inc/fw_pubkey.h
    python pc/sign_firmware.py sign --version 3       # build/can_ids_fw.bin -> build/can_ids_fw_signed.bin
    python pc/sign_firmware.py flash                  # write the signed image (header + app) and restart

The signed image starts at 0x0800C000: a 128-byte header (padded with 0xFF to the end of
sector 3), then the application at 0x08010000. Header: magic, header version, firmware
version, image address and size, SHA-256 of the application, then an ECDSA P-256 signature
(raw r || s, 64 bytes) over SHA-256 of the header's first 64 bytes.

The private key (keys/fw_signing_key.pem) never goes to the chip or into git: whoever holds
it can make firmware the bootloader accepts. Keep a backup: without it, no new firmware can
be installed on a board with a write-protected bootloader (step 3e).
"""

import argparse
import hashlib
import struct
import subprocess
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, decode_dss_signature, encode_dss_signature

ROOT = Path(__file__).resolve().parents[1]
KEY = ROOT / "keys" / "fw_signing_key.pem"
PUB_H = ROOT / "bootloader" / "inc" / "fw_pubkey.h"
BUILD = ROOT / "firmware" / "can_ids_fw" / "build"
APP_BIN, SIGNED_BIN = BUILD / "can_ids_fw.bin", BUILD / "can_ids_fw_signed.bin"

MAGIC, HEADER_VERSION = 0x53444943, 1
HEADER_ADDR, APP_ADDR, APP_MAX = 0x0800C000, 0x08010000, 448 * 1024
SIGNED_BYTES = 64


def load_key(path: Path = KEY) -> ec.EllipticCurvePrivateKey:
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def raw_pub(key) -> bytes:
    n = key.public_key().public_numbers()
    return n.x.to_bytes(32, "big") + n.y.to_bytes(32, "big")


def keygen(force: bool):
    if KEY.exists() and not force:
        raise SystemExit(f"{KEY.relative_to(ROOT)} already exists (a new key would make every image signed "
                         "with the old one invalid). Use --force to replace it.")
    key = ec.generate_private_key(ec.SECP256R1())
    KEY.parent.mkdir(exist_ok=True)
    KEY.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))
    KEY.chmod(0o600)
    pub = raw_pub(key)
    rows = ",\n".join("  " + ", ".join(f"0x{b:02x}" for b in pub[i:i + 8]) for i in range(0, 64, 8))
    PUB_H.parent.mkdir(parents=True, exist_ok=True)
    PUB_H.write_text(f"""/* Firmware signing PUBLIC key (ECDSA P-256, X || Y), written by pc/sign_firmware.py keygen.
   The bootloader only starts images signed with the matching private key (keys/fw_signing_key.pem,
   kept on the PC). Fingerprint (SHA-256 of these 64 bytes): {hashlib.sha256(pub).hexdigest()[:16]} */
#ifndef FW_PUBKEY_H
#define FW_PUBKEY_H
#include <stdint.h>
static const uint8_t FW_PUBKEY[64] = {{
{rows}
}};
#endif
""")
    print(f"private key: {KEY.relative_to(ROOT)} (keep it secret, keep a backup)")
    print(f"public key:  {PUB_H.relative_to(ROOT)} (fingerprint {hashlib.sha256(pub).hexdigest()[:16]}): rebuild the bootloader")


def make_header(app: bytes, version: int, key) -> bytes:
    body = struct.pack("<8I", MAGIC, HEADER_VERSION, version, APP_ADDR, len(app), 0, 0, 0) + hashlib.sha256(app).digest()
    assert len(body) == SIGNED_BYTES
    der = key.sign(hashlib.sha256(body).digest(), ec.ECDSA(Prehashed(hashes.SHA256())))
    r, s = decode_dss_signature(der)
    return body + r.to_bytes(32, "big") + s.to_bytes(32, "big")


def check_header(header: bytes, app: bytes, pub: bytes) -> bool:
    """The bootloader's checks, in Python (signature, then hash)."""
    x, y = int.from_bytes(pub[:32], "big"), int.from_bytes(pub[32:], "big")
    pk = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
    sig = encode_dss_signature(int.from_bytes(header[64:96], "big"), int.from_bytes(header[96:128], "big"))
    try:
        pk.verify(sig, hashlib.sha256(header[:SIGNED_BYTES]).digest(), ec.ECDSA(Prehashed(hashes.SHA256())))
    except Exception:
        return False
    return header[32:64] == hashlib.sha256(app).digest()


def signed_image(app: bytes, version: int, key) -> bytes:
    app = app + b"\xff" * (-len(app) % 4)
    if len(app) > APP_MAX:
        raise SystemExit(f"application too large: {len(app)} > {APP_MAX} bytes")
    sp, pc = struct.unpack("<2I", app[:8])
    if not (0x20000000 <= sp <= 0x20020000 and pc & 1 and APP_ADDR <= pc < APP_ADDR + len(app)):
        raise SystemExit(f"{APP_BIN.name} does not start with a vector table at 0x{APP_ADDR:08X} "
                         f"(SP 0x{sp:08X}, reset 0x{pc:08X}): was it linked for the bootloader layout?")
    header = make_header(app, version, key)
    assert check_header(header, app, raw_pub(key))
    return header + b"\xff" * (APP_ADDR - HEADER_ADDR - len(header)) + app


def programmer() -> str:
    import shutil, glob
    found = shutil.which("STM32_Programmer_CLI") or (sorted(glob.glob(str(
        Path.home() / "Downloads/makeself_dir_*/y/plugins/*cubeprogrammer*/tools/bin/STM32_Programmer_CLI"))) or [None])[-1]
    if not found:
        raise SystemExit("STM32_Programmer_CLI not found")
    return found


def flash(image: Path = SIGNED_BIN) -> bool:
    r = subprocess.run([programmer(), "-c", "port=SWD", "mode=UR", "reset=HWrst", "-w", str(image),
                        hex(HEADER_ADDR), "-v", "-rst"], capture_output=True, text=True)
    ok = "Download verified successfully" in r.stdout
    if not ok:
        print(r.stdout[-2000:])
    return ok


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keygen"); k.add_argument("--force", action="store_true")
    s = sub.add_parser("sign"); s.add_argument("--version", type=int, required=True)
    s.add_argument("--input", type=Path, default=APP_BIN); s.add_argument("--output", type=Path, default=SIGNED_BIN)
    f = sub.add_parser("flash"); f.add_argument("--image", type=Path, default=SIGNED_BIN)
    args = ap.parse_args()
    if args.cmd == "keygen":
        keygen(args.force)
    elif args.cmd == "sign":
        img = signed_image(args.input.read_bytes(), args.version, load_key())
        args.output.write_bytes(img)
        size = struct.unpack("<I", img[16:20])[0]
        print(f"signed version {args.version}: {size:,} bytes, SHA-256 {img[32:64].hex()[:16]}..., "
              f"-> {args.output.relative_to(ROOT)} (flash at 0x{HEADER_ADDR:08X})")
    elif args.cmd == "flash":
        print("flashed and verified" if flash(args.image) else "FLASH FAILED")


if __name__ == "__main__":
    main()
