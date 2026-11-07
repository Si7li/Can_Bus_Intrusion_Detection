"""Device-protection demos (step 3), run against the Nucleo over the ST-LINK.

    python pc/security_demo.py status       # restart the Nucleo, show reset cause + protection settings
    python pc/security_demo.py watchdog     # demo L2: hang the main loop on purpose -> watchdog reset

The ST-LINK serial port (/dev/ttyACM0) carries the Nucleo's JSON lines; the restart
uses STM32_Programmer_CLI (bundled with STM32CubeIDE) over SWD, without erasing anything.
Each run appends its result to results/security_tests.txt.
"""

import argparse
import glob
import json
import shutil
import subprocess
import time
from datetime import datetime
from pathlib import Path

import serial

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
        if text.startswith("{") and '"boot"' in text:
            return t, json.loads(text)
    return None


def describe_boot(ev: dict) -> str:
    return (f"reset cause {ev['reset']} | read protection (RDP) {ev['rdp']} | brown-out reset {ev['bor']} | "
            f"write-protected sectors {ev['wrp_sectors'] or 'none'} | watchdog {ev['watchdog_ms']} ms | "
            f"demo commands {'on' if ev['demo_commands'] else 'off'}")


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


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("test", choices=["status", "watchdog"])
    ap.add_argument("--nucleo", default="/dev/ttyACM0")
    args = ap.parse_args()
    with serial.Serial(args.nucleo, NUCLEO_BAUD, timeout=0.05) as s:
        {"status": cmd_status, "watchdog": cmd_watchdog}[args.test](s)


if __name__ == "__main__":
    main()
