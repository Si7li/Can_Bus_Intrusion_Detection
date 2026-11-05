"""Talk to the USB-CAN adapter (THRYCY "USB-CAN", CH340, /dev/ttyUSB0).

    python pc/adapter_test.py --listen        # print every frame on the bus
    python pc/adapter_test.py --send          # send one test frame (0x321) per second
    python pc/adapter_test.py --set-bitrate 500000   # store a new CAN bitrate in the adapter

Protocol (identified 2026-11-05 by sniffing the Nucleo's test frames): Robotell,
serial port at 500,000 baud. Each frame is
    AA AA | ID (4 bytes LE) | data (8) | DLC | channel | ext | rtr | checksum | 55 55
with 0xA5 as escape byte before any AA/55/A5 inside the frame. python-can
supports it as interface "robotell".

The adapter came set to 125 kbit/s CAN; it was switched to 500 kbit/s (stored
in the adapter) to match the ROAD dataset and the firmware.
"""

import argparse
import time

import can

PORT = "/dev/ttyUSB0"
SERIAL_BAUD = 500_000      # USB-serial speed of this adapter (not the CAN bitrate)


def open_bus(port: str, bitrate: int | None = None):
    return can.Bus(interface="robotell", channel=f"{port}@{SERIAL_BAUD}", bitrate=bitrate)


def listen(port: str):
    bus = open_bus(port)
    print(f"Listening on {port}, Ctrl+C to stop")
    try:
        for msg in bus:
            print(f"{msg.timestamp:.3f}  {msg.arbitration_id:03X}  [{msg.dlc}]  {msg.data.hex(' ').upper()}")
    except KeyboardInterrupt:
        pass
    finally:
        bus.shutdown()


def send(port: str):
    bus = open_bus(port)
    print(f"Sending 0x321 once per second on {port}, Ctrl+C to stop")
    try:
        i = 0
        while True:
            bus.send(can.Message(arbitration_id=0x321, data=[i & 0xFF, 0, 0, 0, 0, 0, 0, 0], is_extended_id=False))
            print(f"sent 321#{i & 0xFF:02X}00000000000000")
            i += 1
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        bus.shutdown()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", default=PORT)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--listen", action="store_true")
    g.add_argument("--send", action="store_true")
    g.add_argument("--set-bitrate", type=int, metavar="BPS")
    args = ap.parse_args()
    if args.listen:
        listen(args.port)
    elif args.send:
        send(args.port)
    else:
        open_bus(args.port, bitrate=args.set_bitrate).shutdown()
        print(f"adapter CAN bitrate set to {args.set_bitrate}")


if __name__ == "__main__":
    main()
