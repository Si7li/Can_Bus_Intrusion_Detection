"""Checks the signature on every JSON line from the Nucleo.

The firmware adds "boot", "seq" and "mac" to each JSON line: an HMAC-SHA256 (first 128 bits)
with the 128-bit device secret, over the line up to and including "seq":N} (without the
mac field). The secret was written into the chip by `security_demo.py provision`, which
keeps the PC's copy in keys/device_secret.key (not in git).

    v = Verifier()                 # loads keys/device_secret.key
    verdict = v.check(text)        # "ok" | "forged" | "replayed" | "unsigned" | "no_key" | "not_json"

  ok        MAC correct and (boot, seq) newer than every line accepted before
  forged    MAC wrong: the line was changed or made up (or signed with another key)
  replayed  MAC correct but (boot, seq) not newer: a genuine old line sent again
  unsigned  the line has no MAC ("mac": null): the device secret is missing or erased (tamper)
"""

import hashlib
import hmac
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KEY_FILE = ROOT / "keys" / "device_secret.key"
MAC_RE = re.compile(r'^(\{.*),"mac":(?:"([0-9a-f]{32})"|null)\}$')
SEQ_RE = re.compile(r'"boot":(\d+),"seq":(\d+)\}$')


def load_key() -> bytes | None:
    try:
        return bytes.fromhex(KEY_FILE.read_text().strip())
    except (FileNotFoundError, ValueError):
        return None


def save_key(key_hex: str):
    KEY_FILE.parent.mkdir(exist_ok=True)
    KEY_FILE.write_text(key_hex + "\n")
    KEY_FILE.chmod(0o600)


def mac_of(key: bytes, signed_text: str) -> str:
    return hmac.new(key, signed_text.encode(), hashlib.sha256).hexdigest()[:32]


class Verifier:
    def __init__(self, key: bytes | None = None):
        self.key = key if key is not None else load_key()
        self.last = (-1, -1)                         # newest (boot, seq) accepted
        self.counts = {"ok": 0, "forged": 0, "replayed": 0, "unsigned": 0, "no_key": 0}

    def check(self, text: str) -> str:
        text = text.strip()
        m = MAC_RE.match(text)
        if not m:
            return "not_json" if not text.startswith("{") else self._count("forged")   # JSON without mac field
        signed, mac = m.group(1) + "}", m.group(2)
        if mac is None:
            return self._count("unsigned")
        if self.key is None:
            return self._count("no_key")
        if not hmac.compare_digest(mac, mac_of(self.key, signed)):
            return self._count("forged")
        s = SEQ_RE.search(signed)
        stamp = (int(s.group(1)), int(s.group(2)))
        if stamp <= self.last:
            return self._count("replayed")
        self.last = stamp
        return self._count("ok")

    def _count(self, verdict: str) -> str:
        self.counts[verdict] += 1
        return verdict
