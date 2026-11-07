"""Explanation step (option B): turn a Nucleo alert into a readable attack description.

The model only says normal / attack. The firmware also reports WHICH ID and
bytes looked wrong and WHY (unknown ID, timing, value never seen, broken signal
pair). This table maps ID/byte to a signal name, using the ROAD documentation
(capture_metadata.json: which ID and byte each attack writes) and the signal
pairs found automatically in normal traffic (results/road_profile.json).
"""

import json
from pathlib import Path

PROFILE = Path(__file__).resolve().parents[1] / "results" / "road_profile.json"

# (id, byte) -> signal name. byte None = whole frame.
SIGNALS = {
    (0x0D0, 5): "speedometer (vehicle speed)",
    (0x0D0, 2): "reverse light / gear state",
    (0x6E0, None): "wheel speeds",
    (0x4E7, 5): "engine coolant temperature",
    (0x295, 6): "gear selector (found by the pair search)",
    (0x0C0, 0): "gear selector (found by the pair search)",
}


ROAD_SIGNALS = dict(SIGNALS)


def signal_name(can_id: int, byte: int) -> str:
    return SIGNALS.get((can_id, byte)) or SIGNALS.get((can_id, None)) or f"0x{can_id:03X} byte {byte}"


def _partners() -> dict:
    """(id, byte) -> (partner id, partner byte) from the profile's signal pairs."""
    try:
        pairs = json.loads(PROFILE.read_text())["pairs"]
    except (OSError, KeyError, ValueError):
        return {}
    return {(int(p["id"]), p["byte"]): (int(p["partner_id"]), p["partner_byte"]) for p in pairs}


PARTNERS = _partners()

# CAN-MIRGU (2016 electric car): IDs and bytes from Attacks_metadata.json (what each attack writes
# and what the dashboard showed). Byte None = whole frame.
MIRGU_SIGNALS = {
    (0x2B0, 1): "steering angle", (0x2B0, None): "steering angle sensor",
    (0x07F, 1): "brake / fog light state", (0x160, None): "brake system status",
    (0x251, None): "forward collision avoidance (FCA)", (0x381, None): "power steering",
    (0x386, None): "speedometer (wheel speeds)", (0x559, 2): "wiper state",
    (0x371, None): "engine management (EMS)", (0x394, 6): "parking brake",
    (0x372, None): "gear shifter / drive mode", (0x541, None): "door status",
    (0x50C, None): "drive mode", (0x593, None): "tyre pressure monitoring",
}


def use_dataset(name: str):
    """Switch the signal names and pairs to another car ('road' or 'mirgu')."""
    global PROFILE, PARTNERS
    root = Path(__file__).resolve().parents[1] / "results"
    SIGNALS.clear()
    SIGNALS.update(ROAD_SIGNALS if name == "road" else MIRGU_SIGNALS)
    PROFILE = root / "road_profile.json" if name == "road" else root / "mirgu" / "mirgu_profile.json"
    PARTNERS = _partners()


def describe(ev: dict) -> str:
    """One line for an 'alert' event (or one entry of an incident's 'ids').

    ALERT = attack evidence, worded "forged". WARNING = the model fired on a value
    never seen before, which may be a new but normal car state, worded "unusual"."""
    reasons = ev.get("reasons", [])
    if "unknown_id" in reasons:
        return f"unknown CAN ID {ev['id']}: frame from a device that does not belong on this bus (fuzzing / injection)"
    can_id = int(ev["id"], 16)
    name = signal_name(can_id, None)
    if "auth_mac" in reasons:
        return f"forged {name} on authenticated ID {ev['id']}: message authentication code invalid (SecOC)"
    if "auth_replay" in reasons:
        return f"replayed {name} on authenticated ID {ev['id']}: freshness counter not newer (SecOC)"
    if "auth_missing" in reasons:
        return f"injected frame on authenticated ID {ev['id']}: no valid authenticator (SecOC)"
    novel, pair = ev.get("novel_bytes", []), ev.get("pair_bytes", [])
    parts = []
    for b in sorted(set(novel) | set(pair)):
        why = []
        if b in novel:
            why.append("value never seen in normal traffic")
        if b in pair:
            p = PARTNERS.get((can_id, b))
            why.append(f"contradicts {signal_name(*p)}" if p else "contradicts its partner signal")
        parts.append(f"{signal_name(can_id, b)} [{', '.join(why)}]")
    if "too_fast" in reasons:
        name = SIGNALS.get((can_id, None))
        parts.append(f"{name + ' ' if name else ''}0x{can_id:03X} arriving faster than normal (extra frames injected)")
    if not parts:
        parts.append(f"changes on 0x{can_id:03X}")
    return ("forged " if ev.get("level") == "ALERT" else "unusual ") + "; ".join(parts)
