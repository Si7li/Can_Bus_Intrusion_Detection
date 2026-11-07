"""Device-protection demos (step 3), run against the Nucleo over the ST-LINK.

    python pc/security_demo.py status       # restart the Nucleo, show reset cause + protection settings
    python pc/security_demo.py watchdog     # demo L2: hang the main loop on purpose -> watchdog reset
    python pc/security_demo.py provision    # ECDH: the chip makes its own secret (only if none is present)
    python pc/security_demo.py tamper       # demo P2: press the blue button = enclosure opened -> secret erased
    python pc/security_demo.py signing      # every JSON line is signed: forged / replayed lines are rejected

The ST-LINK serial port (/dev/ttyACM0) carries the Nucleo's JSON lines; the restart
uses STM32_Programmer_CLI (bundled with STM32CubeIDE) over SWD, without erasing anything.
Each run appends its result to results/security_tests.txt.
"""

import argparse
import glob
import json
import secrets
import shutil
import subprocess
import time
from datetime import datetime
from pathlib import Path

import hashlib

import serial
from cryptography.hazmat.primitives.asymmetric import ec

from signed_link import KEY_FILE, Verifier, load_key, mac_of, save_key

ROOT = Path(__file__).resolve().parents[1]
LOG = ROOT / "results" / "security_tests.txt"
NUCLEO_BAUD = 921600


def programmer() -> str:
    found = shutil.which("STM32_Programmer_CLI") or (sorted(glob.glob(str(
        Path.home() / "Downloads/makeself_dir_*/y/plugins/*cubeprogrammer*/tools/bin/STM32_Programmer_CLI"))) or [None])[-1]
    if not found:
        raise SystemExit("STM32_Programmer_CLI not found (put it on PATH)")
    return found


def restart():
    """Hardware-style restart over SWD, flash untouched."""
    subprocess.run([programmer(), "-c", "port=SWD", "mode=HOTPLUG", "-rst"], capture_output=True, check=True)


def read_lines(s: serial.Serial, seconds: float) -> list[tuple[float, str]]:
    out, buf, end = [], b"", time.perf_counter() + seconds
    while time.perf_counter() < end:
        buf += s.read(4096)
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            out.append((time.perf_counter(), line.decode(errors="replace").strip()))
    return out


def boot_event(lines) -> tuple[float, dict] | None:
    for t, text in lines:
        if text.startswith("{") and '"type":"boot"' in text:
            return t, json.loads(text)
    return None


def describe_boot(ev: dict) -> str:
    return (f"reset cause {ev['reset']} | read protection (RDP) {ev['rdp']} | brown-out reset {ev['bor']} | "
            f"write-protected sectors {ev['wrp_sectors'] or 'none'} | watchdog {ev['watchdog_ms']} ms | "
            f"demo commands {'on' if ev['demo_commands'] else 'off'} | device secret {ev.get('secret', '?')}"
            + (f" (id {ev['secret_id']})" if ev.get("secret_id") else "")
            + (" [power was lost]" if ev.get("power_lost") else ""))


def log(test: str, passed: bool, detail: str):
    line = f"{datetime.now():%Y-%m-%d %H:%M:%S}  {test:10s} {'PASS' if passed else 'FAIL'}  {detail}"
    print(("\n" + line))
    with LOG.open("a") as f:
        f.write(line + "\n")


def cmd_status(s):
    restart()
    b = boot_event(read_lines(s, 3.0))
    if b is None:
        log("status", False, "no boot line within 3 s (old firmware?)")
        return
    print("Nucleo:", describe_boot(b[1]))
    log("status", True, describe_boot(b[1]))


def cmd_watchdog(s):
    """L2: a stuck main loop must not leave the detector dead. 'H' makes the firmware stop
    refreshing the watchdog (interrupts off, endless loop); the IWDG must reset the chip."""
    restart()
    first = boot_event(read_lines(s, 3.0))
    if first is None:
        log("watchdog", False, "no boot line within 3 s (old firmware?)")
        return
    if not first[1]["demo_commands"]:
        log("watchdog", False, "this firmware has the demo commands disabled (SEC_DEMO_COMMANDS 0)")
        return
    read_lines(s, 1.0)                                # detector running normally
    print("Sending 'H': the firmware stops its main loop on purpose...")
    t_send = time.perf_counter()
    s.write(b"H")
    s.flush()
    lines = read_lines(s, 3.0)
    hung = next((t for t, text in lines if "hung on purpose" in text), None)
    again = boot_event(lines)
    if hung is None or again is None:
        log("watchdog", False, f"hang acknowledged: {hung is not None}, restarted: {again is not None}")
        return
    ms = (again[0] - hung) * 1000
    print(f"  {(hung - t_send) * 1000:5.0f} ms  firmware: main loop hung")
    print(f"  {(again[0] - t_send) * 1000:5.0f} ms  Nucleo restarted, reset cause: {again[1]['reset']}")
    log("watchdog", again[1]["reset"] == "watchdog",
        f"hang -> restart in {ms:.0f} ms (timeout {again[1]['watchdog_ms']} ms nominal), "
        f"reset cause reported: {again[1]['reset']}")


def fingerprint(key_hex: str) -> str:
    """Same FNV-1a fingerprint as the firmware (words big-endian from the hex, bytes little-endian)."""
    h = 2166136261
    for i in range(4):
        for byte in int(key_hex[8 * i:8 * i + 8], 16).to_bytes(4, "little"):
            h = ((h ^ byte) * 16777619) & 0xFFFFFFFF
    return f"{h:08x}"


def json_events(lines, kind: str) -> list[tuple[float, dict]]:
    out = []
    for t, text in lines:
        if text.startswith("{") and f'"type":"{kind}"' in text:
            try:
                out.append((t, json.loads(text)))
            except ValueError:
                pass
    return out


def pc_keypair():
    priv = ec.generate_private_key(ec.SECP256R1())
    n = priv.public_key().public_numbers()
    return priv, n.x.to_bytes(32, "big") + n.y.to_bytes(32, "big")


def send_pc_key(s, pc_pub: bytes, wait_s: float = 5.0) -> dict | None:
    """'Q' + the PC's public key; the chip answers within ~0.5 s (entropy + 2 P-256 operations)."""
    s.write(b"Q" + pc_pub.hex().encode() + b"\n")
    s.flush()
    lines, end = [], time.perf_counter() + wait_s
    while time.perf_counter() < end and not json_events(lines, "provision"):
        lines += read_lines(s, 0.1)
    ev = json_events(lines, "provision")
    return ev[0][1] if ev else None


def provision(s) -> tuple[bool, str, dict | None]:
    """Provisioning station, ECDH: the PC sends a fresh P-256 public key, the chip makes its own
    key pair from its entropy source and answers with its public key. Both sides derive the
    same 128-bit device secret; only public keys cross the cable. The PC keeps its copy of the
    derived secret in keys/device_secret.key (git-ignored) to check the signed lines; its
    private key is thrown away."""
    priv, pc_pub = pc_keypair()
    r = send_pc_key(s, pc_pub)
    if r is None:
        return False, "no answer", None
    if not r["ok"]:
        return False, r["msg"], r
    dev_pub = bytes.fromhex(r["device_pub"])
    dev_key = ec.EllipticCurvePublicNumbers(int.from_bytes(dev_pub[:32], "big"), int.from_bytes(dev_pub[32:], "big"),
                                            ec.SECP256R1()).public_key()
    shared = priv.exchange(ec.ECDH(), dev_key)
    key = hashlib.sha256(b"can-ids hmac key v1" + shared + dev_pub + pc_pub).digest()[:16].hex()
    match = r["secret_id"] == fingerprint(key)
    if match:
        save_key(key)
    return match, (f"chip made its key pair ({r['entropy_samples']} entropy samples in {r['entropy_ms']} ms, health tests "
                   f"passed: longest run {r['max_repeat']}, max low byte {r['max_same_low_byte']}/512; total {r['total_ms']} ms); "
                   f"ECDH secret fingerprint chip {r['secret_id']} vs PC {fingerprint(key)}: "
                   f"{'MATCH' if match else 'MISMATCH'}"
                   f"{', PC copy in ' + str(KEY_FILE.relative_to(ROOT)) if match else ''}"), r


def cmd_provision(s):
    restart()
    b = boot_event(read_lines(s, 3.0))
    if b is None:
        log("provision", False, "no boot line within 3 s (old firmware?)")
        return
    print("Nucleo:", describe_boot(b[1]))
    ok, msg, _ = provision(s)
    print("1) provision:", msg)
    r = send_pc_key(s, pc_keypair()[1])
    refused = r is not None and not r["ok"]
    print(f"2) second provisioning, must be refused: {r['msg'] if r else 'no answer'}")
    log("provision", ok and refused, f"{msg}; second provisioning {'refused' if refused else 'NOT refused'}")


def cmd_tamper(s, wait_s: float = 30.0):
    """P2: the blue USER button (PC13 = RTC tamper input) plays the enclosure switch."""
    restart()
    b = boot_event(read_lines(s, 3.0))
    if b is None:
        log("tamper", False, "no boot line within 3 s (old firmware?)")
        return
    if b[1].get("secret") != "present":
        ok, msg, _ = provision(s)
        print("No secret on the chip, provisioning one first:", msg)
        if not ok:
            log("tamper", False, f"could not provision: {msg}")
            return
    print(f"\n>>> Press the BLUE button on the Nucleo now (the 'enclosure opened' switch), within {wait_s:.0f} s <<<\n")
    lines, end = [], time.perf_counter() + wait_s
    while time.perf_counter() < end and not json_events(lines, "tamper"):
        lines += read_lines(s, 0.2)
    ev = json_events(lines, "tamper")
    if not ev:
        log("tamper", False, "no tamper event (button not pressed?)")
        return
    print(f"Nucleo: {ev[0][1]['msg']}, backup registers read back as zero: {ev[0][1]['backup_registers_zero']}")
    st = json_events(read_lines(s, 2.5), "status")
    live = st[-1][1]["secret"] if st else "?"
    print(f"Status line after the event: secret {live}, detector still running ({st[-1][1]['fps'] if st else '?'} frames/s), "
          f"line signature: {'none (mac null): the PC can no longer trust this device' if st and st[-1][1].get('mac', 1) is None else 'present?!'}")
    restart()
    again = boot_event(read_lines(s, 3.0))
    after = again[1].get("secret") if again else "?"
    print(f"After a restart the Nucleo still reports: secret {after}")
    passed = ev[0][1]["backup_registers_zero"] and live == "erased" and after == "erased"
    log("tamper", passed, f"button pressed -> secret erased in hardware (registers zero: "
        f"{ev[0][1]['backup_registers_zero']}), status '{live}', after restart '{after}'")
    print("(Run 'provision' to give the chip a new secret.)")


def cmd_signing(s):
    """Every JSON line carries an HMAC made with the device secret. Checks: (1) the real lines
    verify with the PC's copy of the key, (2) a line changed by one character is rejected,
    (3) a made-up alert is rejected, (4) a genuine line sent again later is rejected."""
    key = load_key()
    if key is None:
        log("signing", False, f"no {KEY_FILE.relative_to(ROOT)}: run 'provision' first (press the button first "
                              "if the chip already has a secret the PC does not know)")
        return
    restart()
    lines = [t for _, t in read_lines(s, 4.0) if t.startswith("{")]
    v = Verifier(key)
    verdicts = [v.check(t) for t in lines]
    n_ok = verdicts.count("ok")
    print(f"1) {n_ok}/{len(lines)} JSON lines from the Nucleo verified (boot line, info, status)")
    if n_ok == 0:
        log("signing", False, f"no line verified ({set(verdicts)}): the chip's secret is not the one in "
                              f"{KEY_FILE.relative_to(ROOT)}? press the button, then 'provision'")
        return
    status = next(t for t in reversed(lines) if '"status"' in t)
    changed = status.replace('"overflow":0', '"overflow":7', 1) if '"overflow":0' in status else status.replace('"fps":', '"fps":1', 1)
    r_changed = v.check(changed)
    print(f"2) status line with one value changed            -> {r_changed}")
    boot, seq = v.last
    fake_body = (f'{{"type":"alert","t_ms":1000,"level":"ALERT","id":"0x386","reasons":["model"],'
                 f'"novel_bytes":[],"pair_bytes":[],"p":99,"boot":{boot},"seq":{seq + 1}}}')
    fake = fake_body[:-1] + f',"mac":"{secrets.token_hex(16)}"}}'
    r_fake = v.check(fake)
    print(f"3) made-up ALERT with a guessed MAC              -> {r_fake}")
    r_replay = v.check(lines[0])
    print(f"4) genuine boot line sent again                  -> {r_replay}")
    wrong = Verifier(bytes(16))
    r_wrong = wrong.check(lines[-1])
    print(f"5) genuine line checked with a different key     -> {r_wrong}")
    mac_us = json.loads(status).get("mac_us")
    passed = n_ok == len(lines) and r_changed == r_fake == r_wrong == "forged" and r_replay == "replayed"
    log("signing", passed, f"{n_ok}/{len(lines)} lines verified; changed line {r_changed}, made-up alert {r_fake}, "
                           f"replayed line {r_replay}, other key {r_wrong}; HMAC {mac_us} us per line on the chip")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("test", choices=["status", "watchdog", "provision", "tamper", "signing"])
    ap.add_argument("--nucleo", default="/dev/ttyACM0")
    args = ap.parse_args()
    with serial.Serial(args.nucleo, NUCLEO_BAUD, timeout=0.05) as s:
        {"status": cmd_status, "watchdog": cmd_watchdog, "provision": cmd_provision,
         "tamper": cmd_tamper, "signing": cmd_signing}[args.test](s)


if __name__ == "__main__":
    main()
