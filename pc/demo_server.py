"""Live demo server: a car driving normally on the CAN bus, the Nucleo watching it, a dashboard.

    python pc/demo_server.py                 # terminal 1, then open http://localhost:8050
    python pc/attack.py list                 # terminal 2: attacks you can launch
    python pc/attack.py max_speedometer      # inject an attack into the live traffic

What it does:
  * CAR: loops 41 minutes of a clean drive of the CAN-MIRGU car (Day 6, a day never used to build
    the detector; minutes 6 to 47.7, where the car is moving) on the CAN bus through the USB-CAN adapter, in real time (~1,800 frames/s).
    Between two loops the bus is silent for 1.5 s, which the Nucleo treats as "car restarted".
  * ATTACKS: on request (pc/attack.py or the dashboard buttons) it mixes attack frames into
    the live traffic: the forged frames of a real CAN-MIRGU attack recording, or a generated
    attack (DoS flood, fuzzing, speed spoof).
  * NUCLEO: reads the IDS's JSON lines from the ST-LINK serial port, checks every line's HMAC
    signature (pc/signed_link.py), keeps the incidents, the status and the protection state.
  * DASHBOARD: http://localhost:8050 (pc/dashboard/index.html), refreshed 4 times a second:
    vehicle speed and steering decoded from the frames on the bus, traffic per CAN ID, the
    IDS's verdicts, the three protection layers, and LEDs mirroring the board's.

Speed (0x386) and steering angle (0x2B0) are decoded with the public Hyundai/Kia layout
(opendbc): four 14-bit wheel speeds x 0.03125 km/h, signed 16-bit angle x 0.1 deg. It fits the
data (0-122 km/h, the four wheels agree within 1.2 km/h, angle within +-470 deg), but MIRGU
does not publish its signal definitions.
"""

import argparse
import collections
import hashlib
import heapq
import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import numpy as np
import pandas as pd
import serial

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "ml" / "src"))
import signals  # noqa: E402
from robotell import SERIAL_BAUD, encode  # noqa: E402
from signed_link import Verifier  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data" / "processed" / "mirgu"
DASH = Path(__file__).resolve().parent / "dashboard" / "index.html"
BYTES = [f"b{i}" for i in range(8)]
DRIVE = "benign_day6_file1_part1"
LOOP_GAP_S = 1.5                     # silence between loops (> 1 s: the Nucleo resets its history)
LOOP = (360.0, 2860.0)               # the part of the drive that is looped: 6 to 47.7 min, the car is moving
                                     # (city, then highway up to 122 km/h); it is parked before and after
SECOC = {0x386: 0x786, 0x2B0: 0x7B0} # data ID -> authenticator ID (must match firmware ids_secoc.h)
signals.use_dataset("mirgu")


def secoc_key():
    """The SecOC key the car (sending ECU) shares with the Nucleo: SHA-256("can-ids secoc v1"
    || device secret)[:16]. The device secret is the chip's, provisioned over ECDH; the PC
    keeps its copy in keys/device_secret.key. None if not provisioned."""
    try:
        secret = bytes.fromhex((ROOT / "keys" / "device_secret.key").read_text().strip())
    except (OSError, ValueError):
        return None
    return hashlib.sha256(b"can-ids secoc v1" + secret).digest()[:16]


def secoc_tag(key: bytes, data_id: int, data: bytes, fresh: int) -> bytes:
    """Authenticator payload: freshness (4 B BE) || first 4 bytes of AES-CMAC over
    data ID (2 B BE) || DLC || data. Matches ids_secoc.c tag_of()."""
    from cryptography.hazmat.primitives.ciphers import algorithms
    from cryptography.hazmat.primitives.cmac import CMAC
    body = bytes([data_id >> 8, data_id & 0xFF, len(data)]) + data + fresh.to_bytes(4, "big")
    c = CMAC(algorithms.AES(key))
    c.update(body)
    return fresh.to_bytes(4, "big") + c.finalize()[:4]


def decode_speed(d: bytes) -> float:
    return sum((d[2 * i] | (d[2 * i + 1] << 8)) & 0x3FFF for i in range(4)) * 0.03125 / 4


def encode_speed(kmh: float, orig: bytes) -> bytes:
    raw = int(round(kmh / 0.03125)) & 0x3FFF
    out = bytearray(orig)
    for i in range(4):
        w = (orig[2 * i] | (orig[2 * i + 1] << 8)) & 0xC000 | raw
        out[2 * i], out[2 * i + 1] = w & 0xFF, w >> 8
    return bytes(out)


def decode_steering(d: bytes) -> float:
    return int.from_bytes(d[0:2], "little", signed=True) * 0.1


# ------------------------------------------------------------------ attack library
def recording_attack(file: str, seconds: float):
    """The forged frames of a real CAN-MIRGU attack recording (label 1), first `seconds` s."""
    df = pd.read_parquet(DATA / "attacks" / f"{file}.parquet", columns=["t", "id", "dlc", "label"] + BYTES)
    f = df[df["label"] == 1]
    t = f["t"].to_numpy() - f["t"].iloc[0]
    keep = t <= seconds
    frames = [(float(tt), int(i), bytes(row[:n])) for tt, i, n, row in
              zip(t[keep], f["id"].to_numpy()[keep], f["dlc"].to_numpy()[keep], f[BYTES].to_numpy(np.uint8)[keep])]
    return frames, []


def dos_attack(seconds: float):
    """ID 0x000 as fast as the bus allows. 0x000 wins every arbitration, so the car's own
    frames cannot get on the bus meanwhile: they are dropped for the duration."""
    n = int(seconds * 3000)
    return [(k / 3000, 0x000, bytes(8)) for k in range(n)], [(0.0, seconds, lambda i, d: None)]


def fuzzing_attack(seconds: float):
    """Random data on random IDs, 500 frames/s (the IDs are mostly not used by this car)."""
    rng = np.random.default_rng()
    n = int(seconds * 500)
    return [(k / 500, int(rng.integers(0, 0x800)), bytes(rng.integers(0, 256, 8, dtype=np.uint8))) for k in range(n)], []


def speed_spoof(seconds: float, kmh: float = 180.0):
    """Masquerade: the speedometer frames (0x386) keep their normal timing, but carry a forged
    speed. No extra frames: only the values are wrong (the case the AI is for)."""
    def f(i, d):
        return encode_speed(kmh, d) if i == 0x386 else d
    return [], [(0.0, seconds, f)]


def unknown_id(seconds: float):
    """A device that does not belong on this bus: ID 0x6FF, 10 frames/s."""
    n = int(seconds * 10)
    return [(k / 10, 0x6FF, bytes([0xDE, 0xAD, 0xBE, 0xEF, 0, 0, 0, k & 0xFF])) for k in range(n)], []


def split_of(file: str) -> str:
    try:
        import mirgu_split
        return mirgu_split.attack_split(file)
    except Exception:
        return "?"


RECORDINGS = {          # short name -> CAN-MIRGU recording
    "max_speedometer": "max_speedometer_attack", "steering_angle_replay": "steering_angle_replay",
    "parking_brake": "parking_break_attack", "ems_replay": "ems_replay_attack",
    "wiper_warning": "wiper_warning_attack", "fuzzing_random_ids": "fuzzing_random_ids",
    "reverse_speedometer": "reverse_speedometer_fuzzing_attack", "door_open": "door_open_warning_attack",
    "drive_mode": "drive_mode_changing_attack", "fca_warning": "fca_warning_attack",
    "power_steering": "power_steering_attack", "gear_shifter": "gear_shifter_attack_1",
}
GENERATED = {
    "dos": (dos_attack, "DoS flood of ID 0x000; the car's frames cannot get through"),
    "fuzzing": (fuzzing_attack, "random data on random IDs, 500 frames/s"),
    "speed_spoof": (speed_spoof, "masquerade: speedometer frames at normal timing, forged 180 km/h "
                                 "(the AI misses this; SecOC authentication catches it)"),
    "unknown_id": (unknown_id, "a device that does not belong on the bus (ID 0x6FF)"),
}


def attack_catalog() -> list[dict]:
    out = []
    for name, file in RECORDINGS.items():
        sp = split_of(file)
        out.append({"name": name, "kind": "recording", "split": sp,
                    "about": f"forged frames of the real CAN-MIRGU recording {file} "
                             f"({'test split: never used to build the detector' if sp == 'test' else sp + ' split'})"})
    for name, (_, about) in GENERATED.items():
        out.append({"name": name, "kind": "generated", "split": "-", "about": about})
    return out


# ------------------------------------------------------------------ the car
class Car(threading.Thread):
    def __init__(self, port: str):
        super().__init__(daemon=True)
        self.port = port
        df = pd.read_parquet(DATA / "ambient" / f"{DRIVE}.parquet", columns=["t", "id", "dlc"] + BYTES)
        self.t = (df["t"] - df["t"].iloc[0]).to_numpy()
        self.ids = df["id"].to_numpy().astype(np.int32)
        self.dlc = df["dlc"].to_numpy().astype(np.int32)
        self.data = df[BYTES].to_numpy(np.uint8)
        self.length = LOOP[1] - LOOP[0]
        self.normal_ids = set(int(i) for i in np.unique(self.ids)) | set(SECOC.values())
        del df
        self.secoc_key = secoc_key()            # the car signs the protected IDs if a secret is provisioned
        self.fresh = {d: 0 for d in SECOC}      # freshness counter per protected ID
        self.lock = threading.Lock()
        self.inject: list = []                  # heap of (abs time, seq, id, data)
        self.filters: list = []                 # (abs start, abs end, fn(id, data) -> data or None)
        self.seq = 0
        self.loops, self.drive_t, self.state = 0, 0.0, "starting"
        self.speed = self.steering = 0.0
        self.sent = self.sent_attack = 0
        self.per_id = collections.Counter()     # frames per ID in the current second
        self.id_rate: dict = {}
        self.fps = 0
        self.error = None

    def schedule(self, frames, filters, delay: float = 0.3) -> tuple[float, float]:
        t0 = time.perf_counter() + delay
        end = t0 + max([f[0] for f in frames] + [fl[1] for fl in filters] + [0.0])
        with self.lock:
            for rel, i, d in frames:
                self.seq += 1
                heapq.heappush(self.inject, (t0 + rel, self.seq, i, d))
            for a, b, fn in filters:
                self.filters.append((t0 + a, t0 + b, fn))
        return t0, end

    def _account(self, i: int, d: bytes, attack: bool):
        self.per_id[i] += 1
        self.sent += 1
        self.sent_attack += attack
        if i == 0x386 and len(d) >= 8:
            self.speed = decode_speed(d)
        elif i == 0x2B0 and len(d) >= 2:
            self.steering = decode_steering(d)

    def run(self):
        try:
            with serial.Serial(self.port, SERIAL_BAUD, timeout=0) as s:
                def drain():                                    # discard what the adapter sends back
                    while True:
                        if not s.read(4096):
                            time.sleep(0.01)
                threading.Thread(target=drain, daemon=True).start()
                while True:
                    self._play(s, LOOP[0], LOOP[1])
                    self.loops += 1
                    self.state = "restarting (bus silent 1.5 s)"
                    time.sleep(LOOP_GAP_S)
        except serial.SerialException as e:
            self.error = f"CAN adapter: {e}"
            self.state = "error"

    def _play(self, s, start_s: float, end_s: float):
        i = int(np.searchsorted(self.t, start_s))
        t0 = time.perf_counter() - self.t[i]
        n, sec = int(np.searchsorted(self.t, end_s)), int(time.perf_counter())
        self.state = "driving"
        while i < n:
            now = time.perf_counter()
            j = int(np.searchsorted(self.t, now - t0, side="right"))
            out = []
            with self.lock:
                self.filters = [f for f in self.filters if f[1] > now]
                active = [f[2] for f in self.filters if f[0] <= now]
                for k in range(i, j):
                    cid, orig = int(self.ids[k]), bytes(self.data[k, :self.dlc[k]])
                    d = orig
                    for fn in active:
                        d = fn(cid, d) if d is not None else None
                    if d is not None:
                        out.append(encode(cid, d))
                        self._account(cid, d, False)
                        if self.secoc_key and cid in SECOC:
                            # the genuine ECU authenticates the REAL data; a filter that forged
                            # the data frame above makes the chip recompute a different MAC -> caught
                            self.fresh[cid] += 1
                            auth = secoc_tag(self.secoc_key, cid, orig, self.fresh[cid])
                            out.append(encode(SECOC[cid], auth))
                            self._account(SECOC[cid], auth, False)
                while self.inject and self.inject[0][0] <= now:
                    _, _, cid, d = heapq.heappop(self.inject)
                    out.append(encode(cid, d))
                    self._account(cid, d, True)
            if out:
                s.write(b"".join(out))
            i = j
            self.drive_t = float(self.t[min(i, n - 1)]) - start_s
            if int(now) != sec:                                 # once per second: rates per ID
                sec = int(now)
                self.id_rate, self.per_id = dict(self.per_id), collections.Counter()
                self.fps = sum(self.id_rate.values())
            time.sleep(0.001)


# ------------------------------------------------------------------ the Nucleo
class Nucleo(threading.Thread):
    def __init__(self, port: str):
        super().__init__(daemon=True)
        self.port = port
        self.verifier = Verifier()
        self.lock = threading.Lock()
        self.status: dict = {}
        self.boot: dict = {}
        self.bootloader: dict = {}
        self.self_test = None
        self.incident = None                    # open incident
        self.incidents = collections.deque(maxlen=40)
        self.log = collections.deque(maxlen=60)
        self.last_line = 0.0
        self.untrusted = 0
        self.tamper_at = None
        self.attacks: list = []                 # filled by the server: ground truth
        self.error = None

    def _log(self, text: str, kind: str = "info"):
        self.log.appendleft({"t": time.time(), "kind": kind, "text": text})

    def _attack_at(self, t: float):
        for a in reversed(self.attacks):
            if a["start"] - 0.05 <= t <= a["end"] + 1.5:
                return a
        return None

    def run(self):
        try:
            ser = serial.Serial(self.port, 921600, timeout=0.1)
        except serial.SerialException as e:
            self.error = f"Nucleo serial port: {e}"
            return
        buf = b""
        while True:
            buf += ser.read(4096)
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                self._line(line.decode(errors="replace").strip())

    def _line(self, text: str):
        now = time.perf_counter()
        if not text:
            return
        self.last_line = now
        k = text.rfind('{"type":')
        if k > 0:                    # a partial line glued in front (port opened mid-line, or a reset)
            text = text[k:]
        if not text.startswith("{"):
            if "SELF-TEST" in text:
                self.self_test = text.replace("->", "").strip()
            return
        verdict = self.verifier.check(text)
        try:
            ev = json.loads(text)
        except ValueError:
            return
        if verdict in ("forged", "replayed"):
            self.untrusted += 1
            self._log(f"untrusted line ignored ({verdict}): {text[:80]}", "bad")
            return
        kind = ev.get("type")
        with self.lock:
            if kind == "status":
                self.status = ev
            elif kind == "boot":
                self.boot = ev
                self._log(f"Nucleo started (reset: {ev.get('reset')})")
            elif kind == "secure_boot":
                self.bootloader = ev
                self._log("bootloader: " + ("firmware signature valid" if ev.get("ok") else "FIRMWARE REFUSED: " + ev.get("reason", "")),
                          "info" if ev.get("ok") else "bad")
            elif kind == "tamper":
                self.tamper_at = time.time()
                self._log("TAMPER: " + ev.get("msg", ""), "bad")
            elif kind == "alert":
                self._alert(ev, now, verdict)
            elif kind == "incident_end" and self.incident:
                inc = self.incident
                inc["open"] = False
                inc["duration_s"] = round(ev.get("duration_ms", 0) / 1000, 1)
                inc["frames"] = ev.get("frames")
                inc["ids"] = [{"id": e["id"], "frames": e["frames"], "what": signals.describe(e)} for e in ev.get("ids", [])]
                if ev.get("unknown_id_frames"):
                    inc["ids"].append({"id": "unknown IDs", "frames": ev["unknown_id_frames"], "what": "IDs not in this car"})
                self.incident = None
            elif kind == "info":
                self._log("Nucleo: " + ev.get("msg", ""))

    def _alert(self, ev: dict, now: float, verdict: str):
        what = signals.describe(ev)
        atk = self._attack_at(now)
        if self.incident is None:
            self.incident = {"t": time.time(), "level": ev["level"], "what": what, "id": ev["id"], "open": True,
                             "signed": verdict == "ok", "attack": atk["name"] if atk else None,
                             "delay_s": None, "ids": [], "duration_s": None, "frames": None}
            self.incidents.appendleft(self.incident)
        else:
            self.incident["level"], self.incident["what"] = ev["level"], what
            if atk and not self.incident["attack"]:
                self.incident["attack"] = atk["name"]
        if atk is not None:
            key = "alert_s" if ev["level"] == "ALERT" else "warning_s"
            if atk.get(key) is None:
                atk[key] = round(now - atk["start"], 3)
                atk["what"] = what
                if self.incident["delay_s"] is None:
                    self.incident["delay_s"] = atk[key]
        self._log(f"{ev['level']}: {what}" + (f"  [attack: {atk['name']}]" if atk else "  [no attack running]"),
                  "alert" if ev["level"] == "ALERT" else "warning")


# ------------------------------------------------------------------ server
class Demo:
    def __init__(self, args):
        self.car = Car(args.can)
        self.nucleo = Nucleo(args.nucleo)
        self.nucleo.attacks = self.attacks = []
        self.history = collections.deque(maxlen=240)          # 60 s at 4 Hz
        self.catalog = attack_catalog()

    def start(self):
        self.car.start()
        self.nucleo.start()
        threading.Thread(target=self._sample, daemon=True).start()

    def _sample(self):
        while True:
            st = self.nucleo.status
            self.history.append({"t": time.time(), "speed": round(self.car.speed, 1), "steering": round(self.car.steering, 1),
                                 "fps_car": self.car.fps, "fps_ids": st.get("fps", 0) if time.perf_counter() - self.nucleo.last_line < 3 else 0,
                                 "cpu": float(st.get("cpu_pct", 0) or 0)})
            time.sleep(0.25)

    def launch(self, name: str, seconds: float) -> dict:
        if name in RECORDINGS:
            frames, filters = recording_attack(RECORDINGS[name], seconds)
        elif name in GENERATED:
            frames, filters = GENERATED[name][0](seconds)
        else:
            return {"ok": False, "error": f"unknown attack {name!r}"}
        t0, end = self.car.schedule(frames, filters)
        a = {"id": len(self.attacks) + 1, "name": name, "start": t0, "end": end, "frames": len(frames),
             "seconds": round(end - t0, 1), "alert_s": None, "warning_s": None, "what": None, "wall": time.time() + 0.3}
        self.attacks.append(a)
        self.nucleo._log(f"attack launched: {name} ({len(frames)} injected frames"
                         + (", real frames modified or dropped" if filters else "") + f", {a['seconds']} s)", "attack")
        return {"ok": True, **{k: a[k] for k in ("id", "name", "frames", "seconds")}}

    def attack_state(self, k: int) -> dict:
        a = next((a for a in self.attacks if a["id"] == k), None)
        if a is None:
            return {"ok": False}
        now = time.perf_counter()
        return {"ok": True, "name": a["name"], "running": now < a["end"], "finished": now > a["end"] + 2.0,
                "elapsed_s": round(now - a["start"], 1), "seconds": a["seconds"], "alert_s": a["alert_s"],
                "warning_s": a["warning_s"], "what": a["what"]}

    def state(self) -> dict:
        car, nu = self.car, self.nucleo
        now = time.perf_counter()
        st, boot = dict(nu.status), dict(nu.boot)
        connected = now - nu.last_line < 3
        inc = nu.incident
        level = inc["level"] if inc else None
        running = [a["name"] for a in self.attacks if a["start"] - 0.3 <= now <= a["end"]]
        ids = sorted(car.id_rate.items(), key=lambda kv: -kv[1])
        return {
            "car": {"state": car.state, "error": car.error, "drive": DRIVE, "loops": car.loops,
                    "drive_t": round(car.drive_t), "length": round(car.length), "speed": round(car.speed, 1),
                    "steering": round(car.steering, 1), "fps": car.fps, "sent": car.sent, "sent_attack": car.sent_attack,
                    "attack_running": running,
                    "ids": [{"id": f"0x{i:03X}", "fps": r, "normal": i in car.normal_ids, "name": next((v for (cid, b), v in signals.MIRGU_SIGNALS.items()
                                                                          if cid == i and b is None), None)
                             or next((v for (cid, b), v in signals.MIRGU_SIGNALS.items() if cid == i), "")}
                            for i, r in sorted(ids, key=lambda kv: (kv[0] in car.normal_ids, -kv[1]))[:24]],
                    "n_ids": len(ids)},
            "nucleo": {"connected": connected, "error": nu.error, "status": st, "boot": boot, "bootloader": nu.bootloader,
                       "self_test": nu.self_test, "link": dict(nu.verifier.counts), "untrusted": nu.untrusted,
                       "has_key": nu.verifier.key is not None,
                       "tamper_recent": bool(nu.tamper_at and time.time() - nu.tamper_at < 10),
                       "leds": {"blue": connected and st.get("fps", 0) > 0,
                                "green": connected and inc is None, "yellow": level == "WARNING", "red": level == "ALERT"}},
            "incidents": list(nu.incidents)[:20],
            "attacks": [{k: a[k] for k in ("id", "name", "frames", "seconds", "alert_s", "warning_s", "what", "wall")}
                        for a in reversed(self.attacks[-15:])],
            "log": list(nu.log)[:40],
            "history": list(self.history),
            "catalog": self.catalog,
        }


def make_handler(demo: Demo):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _json(self, obj, code=200):
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path in ("/", "/index.html"):
                body = DASH.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            elif self.path == "/api/state":
                self._json(demo.state())
            elif self.path.startswith("/api/attack/"):
                self._json(demo.attack_state(int(self.path.rsplit("/", 1)[1])))
            elif self.path == "/api/attacks":
                self._json(demo.catalog)
            else:
                self._json({"error": "not found"}, 404)

        def do_POST(self):
            if self.path == "/api/attack":
                n = int(self.headers.get("Content-Length", 0))
                req = json.loads(self.rfile.read(n) or b"{}")
                self._json(demo.launch(req.get("name", ""), float(req.get("seconds", 15))))
            else:
                self._json({"error": "not found"}, 404)
    return H


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--can", default="/dev/ttyUSB0", help="USB-CAN adapter")
    ap.add_argument("--nucleo", default="/dev/ttyACM0", help="Nucleo ST-LINK serial port")
    ap.add_argument("--port", type=int, default=8050, help="dashboard port")
    ap.add_argument("--no-restart", action="store_true", help="do not restart the Nucleo at start-up")
    args = ap.parse_args()
    print(f"loading the drive {DRIVE} ...")
    demo = Demo(args)
    demo.start()
    if not args.no_restart:                    # fresh boot: the dashboard gets the boot / secure-boot lines
        time.sleep(0.5)
        try:
            import security_demo
            security_demo.restart()
        except Exception as e:
            print(f"(could not restart the Nucleo over SWD: {e})")
    srv = ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(demo))
    print(f"car driving on the CAN bus ({demo.car.length / 60:.0f} min of driving, looped); dashboard: http://localhost:{args.port}")
    print("launch attacks from another terminal:  python pc/attack.py list")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")


if __name__ == "__main__":
    main()
