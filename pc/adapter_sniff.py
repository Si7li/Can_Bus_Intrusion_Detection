"""Identify the USB-CAN adapter's serial protocol from real traffic.

    python pc/adapter_sniff.py              # needs the Nucleo on the bus, sending 0x123

The Nucleo test firmware sends ID 0x123 every 100 ms with data
[counter (4 bytes LE), CA FE BA BE]. This script listens to /dev/ttyUSB0 at
each common baud rate and looks for the bytes CA FE BA BE (binary adapters)
or the text "CAFEBABE" (ASCII adapters). Where they show up, it prints the
raw bytes around them, which reveals the adapter's frame format.
"""

import argparse
import time

import serial

BAUDS = [2_000_000, 1_000_000, 921_600, 576_000, 500_000, 460_800, 230_400, 115_200, 57_600, 38_400, 19_200, 9_600]
MARK_BIN = bytes.fromhex("CAFEBABE")
MARK_TXT = b"CAFEBABE"


def listen(port: str, baud: int, seconds: float) -> bytes:
    with serial.Serial(port, baud, timeout=0.05) as s:
        s.reset_input_buffer()
        t0, buf = time.time(), b""
        while time.time() - t0 < seconds:
            buf += s.read(4096)
        return buf


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", default="/dev/ttyUSB0")
    ap.add_argument("--seconds", type=float, default=1.5)
    args = ap.parse_args()

    found = False
    for baud in BAUDS:
        buf = listen(args.port, baud, args.seconds)
        hits_bin, hits_txt = buf.count(MARK_BIN), buf.upper().count(MARK_TXT)
        print(f"{baud:>9} baud: {len(buf):6d} bytes, marker found {hits_bin} x (binary) / {hits_txt} x (text)")
        if hits_bin or hits_txt:
            found = True
            if hits_bin:
                i = buf.find(MARK_BIN)
                chunk = buf[max(0, i - 12): i + 12]
                print("   bytes around the marker:", chunk.hex(" ").upper())
                # print 3 consecutive frames to see the framing (start/end bytes)
                j = buf.find(MARK_BIN, i + 4)
                if j > 0:
                    print(f"   distance between two markers: {j - i} bytes")
                    print("   one full period:", buf[i - 12: j - 12].hex(" ").upper() if i >= 12 else "")
            else:
                i = buf.upper().find(MARK_TXT)
                print("   text around the marker:", buf[max(0, i - 30): i + 20])
    if not found:
        print("\nMarker never seen. Check: Nucleo running the CAN firmware (status line shows tx increasing),"
              " wiring CANH-CANH / CANL-CANL, common GND, adapter switch on 500K.")


if __name__ == "__main__":
    main()
