"""Device-protection demos (step 3), run against the Nucleo over the ST-LINK.

    python pc/security_demo.py status       # restart the Nucleo, show reset cause + protection settings
    python pc/security_demo.py watchdog     # demo L2: hang the main loop on purpose -> watchdog reset
    python pc/security_demo.py provision    # ECDH: the chip makes its own secret (only if none is present)
    python pc/security_demo.py tamper       # demo P2: press the blue button = enclosure opened -> secret erased
    python pc/security_demo.py signing      # every JSON line is signed: forged / replayed lines are rejected
    python pc/security_demo.py readout      # P1: can a debugger read the firmware out of flash? (RDP)
    python pc/security_demo.py wrp          # L1c: can the bootloader be overwritten? (write protection)
    python pc/security_demo.py unlock       # P1 + P1b: lock (RDP 1), try to read, unlock (RDP 0 = mass erase):
                                            #   is the device secret destroyed? Then reinstalls everything (~2 min)

The ST-LINK serial port (/dev/ttyACM0) carries the Nucleo's JSON lines; the restart
uses STM32_Programmer_CLI (bundled with STM32CubeIDE) over SWD, without erasing anything.
Each run appends its result to results/security_tests.txt.
"""

import argparse
import glob
import json
import re
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
            + (" [power was lost]" if ev.get("power_lost") else "")
            + (f" | secure boot: verified, firmware version {ev['secure_boot']['fw_version']} "
               f"(minimum {ev['secure_boot']['min_version']}, checked in {ev['secure_boot']['check_ms']} ms)"
               if ev.get("secure_boot", {}).get("verified") else " | secure boot: NOT verified"))


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
    s.write(b"\nH")                                  # newline first: clears any partial line in the firmware
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
    by = again[1].get("erased_by") if again else "?"
    print(f"After a restart the Nucleo still reports: secret {after} (erased by: {by})")
    passed = ev[0][1]["backup_registers_zero"] and live == "erased" and after == "erased" and by == "tamper"
    log("tamper", passed, f"button pressed -> secret erased in hardware (registers zero: "
        f"{ev[0][1]['backup_registers_zero']}), status '{live}', after restart '{after}' (erased_by {by})")
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
    lines = [t for _, t in read_lines(s, 4.0) if t.startswith("{") and '"type":"secure_boot"' not in t]   # bootloader: unsigned by design
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


def cli(*args: str) -> str:
    r = subprocess.run([programmer(), "-c", "port=SWD", *args], capture_output=True, text=True)
    return re.sub(r"\x1b\[[0-9;]*m", "", r.stdout + r.stderr)


def option_bytes() -> dict:
    out = cli("mode=HOTPLUG", "-ob", "displ")
    ob = {}
    for name in ("RDP", "BOR_LEV", "nWRP0", "nWRP1", "nWRP2", "nWRP3"):
        m = re.search(rf"{name}\s*:\s*(0x[0-9A-Fa-f]+)", out)
        ob[name] = int(m.group(1), 16) if m else None
    return ob


def rdp_name(v) -> str:
    return "unknown" if v is None else "level 0" if v == 0xAA else "level 2" if v == 0xCC else "level 1"


def cmd_readout(_s):
    """P1: read 64 bytes of the application (0x08010000) and of the bootloader over SWD."""
    ob = option_bytes()
    results = []
    for name, addr in (("application", "0x08010000"), ("bootloader", "0x08000000")):
        out = cli("mode=HOTPLUG", "-r32", addr, "64")
        words = re.findall(rf"{addr[:-1]}\w : ((?:[0-9A-F]{{8}} ?)+)", out)
        ok = bool(words)
        results.append(ok)
        print(f"  read {name} at {addr}: " + (f"SUCCEEDED, first words {words[0].split()[:4]}" if ok
              else "FAILED: " + (re.findall(r"Error[^\n]*", out) or ["no data"])[0]))
    level = rdp_name(ob["RDP"])
    readable = all(results)
    passed = (level == "level 0" and readable) or (level == "level 1" and not any(results))
    log("readout", passed, f"RDP {level}: flash read over SWD {'succeeded (firmware and model can be copied)' if readable else 'refused'}")


def cmd_wrp(s):
    """L1c: try to rewrite the bootloader (the same bytes, so harmless if not protected),
    then check the bootloader still verifies the IDS and a normal signed update still works."""
    import sign_firmware as sf
    ob = option_bytes()
    protected = [n for n in ("nWRP0", "nWRP1") if ob[n] == 0]
    print(f"  write protection: sectors {', '.join(n[-1] for n in protected) or 'none'}")
    bl = ROOT / "bootloader" / "build" / "bootloader.elf"
    out = cli("mode=UR", "-w", str(bl), "-v")
    written = "Download verified successfully" in out
    err = (re.findall(r"(?:Error|Warning)[^\n]*", out) or ["-"])[0]
    print(f"  overwrite the bootloader over SWD: {'SUCCEEDED' if written else 'REFUSED: ' + err}")
    restart()                                       # the bootloader states the current minimum version
    sb = json_events(read_lines(s, 3.0), "secure_boot")
    version = sb[0][1]["min_version"] if sb else 1
    img = sf.BUILD / "wrp_test_signed.bin"
    img.write_bytes(sf.signed_image(sf.APP_BIN.read_bytes(), version, sf.load_key()))
    s.reset_input_buffer()
    upd = sf.flash(img)
    print(f"  normal signed firmware update (sectors 3-7, version {version}): {'succeeded' if upd else 'FAILED'}")
    b = boot_event(read_lines(s, 3.0))
    verified = bool(b and b[1].get("secure_boot", {}).get("verified"))
    print(f"  after both: secure boot {'verified' if verified else 'NOT verified'}")
    passed = verified and upd and (written != bool(protected))
    log("wrp", passed, f"sectors protected: {', '.join(n[-1] for n in protected) or 'none'}; bootloader overwrite "
                       f"{'succeeded' if written else 'refused'}; signed update {'ok' if upd else 'failed'}; "
                       f"secure boot after: {'verified' if verified else 'NOT verified'}")


def read_words(addr: str, n: int = 5) -> list[str]:
    out = cli("mode=HOTPLUG", "-r32", addr, str(4 * n))
    return " ".join(re.findall(r"0x4\w+ : ((?:[0-9A-F]{8} ?)+)", out)).split()


def enable_bkpsram_clock():
    ahb1 = int(read_words("0x40023830", 1)[0], 16)
    cli("mode=HOTPLUG", "-w32", "0x40023830", f"0x{ahb1 | 0x40000:08X}")


def reinstall(s) -> dict | None:
    """Bootloader + the current signed image + write protection, after a mass erase."""
    import sign_firmware as sf
    cli("mode=UR", "-ob", "nWRP0=1", "nWRP1=1")
    cli("mode=UR", "reset=HWrst", "-w", str(ROOT / "bootloader" / "build" / "bootloader.elf"), "-v")
    sf.flash()
    cli("mode=UR", "-ob", "nWRP0=0", "nWRP1=0")
    restart()
    b = boot_event(read_lines(s, 3.0))
    return b[1] if b else None


def cmd_unlock(s):
    """The attack a debugger owner would try on a locked board: lower read protection (which
    mass-erases the flash), then load their own code and read the key from backup memory.
    The key is split: A in the RTC backup registers, B in the backup SRAM; the unlock must
    destroy B, so A alone (random) is useless."""
    restart()
    b = boot_event(read_lines(s, 3.0))
    if not b or b[1].get("secret") != "present":
        ok, msg, _ = provision(s)
        print("provisioned a key first:", msg)
    print("1) lock: read protection level 1")
    cli("mode=UR", "-ob", "RDP=0xBB")
    locked_read = bool(re.findall(r"0x08010000 : ([0-9A-F]{8})", cli("mode=HOTPLUG", "-r32", "0x08010000", "16")))
    print(f"   debugger reads the firmware: {'YES (!)' if locked_read else 'refused'}")
    print("2) unlock: read protection back to level 0 (the chip mass-erases its flash)")
    cli("mode=UR", "-ob", "RDP=0xAA", "nWRP0=1", "nWRP1=1")
    time.sleep(2)
    flash = re.findall(r"0x08010000 : ([0-9A-F]{8})", cli("mode=HOTPLUG", "-r32", "0x08010000", "16"))
    erased = bool(flash) and flash[0] == "FFFFFFFF"
    share_a = read_words("0x40002850")
    enable_bkpsram_clock()
    share_b = read_words("0x40024000")
    a_left = bool(share_a) and share_a[0] == "5EC2E7A1"
    b_gone = bool(share_b) and all(w == "00000000" for w in share_b)
    print(f"   flash erased: {erased}; share A (backup registers) still there: {a_left}; share B (backup SRAM) erased: {b_gone}")
    key = load_key()
    rebuilt = "".join(share_a[1:5]).lower() if a_left else ""
    print(f"   attacker's best guess (share A alone) equals the key: {rebuilt == (key.hex() if key else None)}")
    print("3) reinstall bootloader + signed IDS + write protection")
    first = reinstall(s)
    restart()
    second = boot_event(read_lines(s, 3.0))
    verdicts = [first and first.get("erased_by"), second and second[1].get("erased_by")]
    print(f"   IDS after reinstall: secret {first and first.get('secret')}, erased_by {verdicts[0]}; after another restart: {verdicts[1]}")
    passed = not locked_read and erased and b_gone and rebuilt != (key.hex() if key else None) and verdicts == ["debug_unlock"] * 2
    log("unlock", passed, f"RDP1 read refused: {not locked_read}; RDP 1->0 erased flash: {erased}, share B: {b_gone}, "
                          f"share A left: {a_left} (useless alone); IDS reports erased_by {verdicts[0]} (and after restart: {verdicts[1]})")
    print("(Run 'provision' to give the chip a new secret.)")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("test", choices=["status", "watchdog", "provision", "tamper", "signing", "readout", "wrp", "unlock"])
    ap.add_argument("--nucleo", default="/dev/ttyACM0")
    args = ap.parse_args()
    with serial.Serial(args.nucleo, NUCLEO_BAUD, timeout=0.05) as s:
        {"status": cmd_status, "watchdog": cmd_watchdog, "provision": cmd_provision,
         "tamper": cmd_tamper, "signing": cmd_signing, "readout": cmd_readout, "wrp": cmd_wrp,
         "unlock": cmd_unlock}[args.test](s)


if __name__ == "__main__":
    main()
