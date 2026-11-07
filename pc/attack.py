"""Launch an attack into the live demo (pc/demo_server.py must be running) and watch the verdict.

    python pc/attack.py list                     # available attacks
    python pc/attack.py max_speedometer          # first 15 s of the real attack
    python pc/attack.py speed_spoof --seconds 8  # masquerade: forged speed, normal timing

The demo server mixes the attack frames into the car traffic on the CAN bus. This script
then follows the Nucleo's verdict: ALERT / WARNING and how long after the first attack frame.
"""

import argparse
import json
import sys
import time
import urllib.request

SERVER = "http://127.0.0.1:8050"


def call(path: str, body: dict | None = None) -> dict:
    req = urllib.request.Request(SERVER + path, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return json.loads(r.read())
    except OSError:
        sys.exit("demo server not running: start it first with  python pc/demo_server.py")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("attack", help="attack name, or 'list'")
    ap.add_argument("--seconds", type=float, default=15.0, help="how long (recordings: the first N seconds)")
    args = ap.parse_args()
    if args.attack == "list":
        for a in call("/api/attacks"):
            print(f"  {a['name']:22s} {a['about']}")
        return
    r = call("/api/attack", {"name": args.attack, "seconds": args.seconds})
    if not r.get("ok"):
        sys.exit(r.get("error", "refused") + "  (see: python pc/attack.py list)")
    print(f"attack '{r['name']}' launched: {r['frames']:,} injected frames over {r['seconds']} s")
    shown = set()
    while True:
        st = call(f"/api/attack/{r['id']}")
        for key, label in (("warning_s", "WARNING"), ("alert_s", "ALERT")):
            if st.get(key) is not None and key not in shown:
                shown.add(key)
                print(f"  Nucleo {label:7s} {st[key]:5.2f} s after the first attack frame: {st['what']}")
        if st.get("finished"):
            break
        time.sleep(0.1)
    if st.get("alert_s") is not None:
        print(f"result: DETECTED (ALERT after {st['alert_s']:.2f} s)")
    elif st.get("warning_s") is not None:
        print(f"result: flagged as unusual only (WARNING after {st['warning_s']:.2f} s), no ALERT")
    else:
        print("result: NOT detected")


if __name__ == "__main__":
    main()
