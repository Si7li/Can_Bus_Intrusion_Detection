"""Minimal Robotell protocol encoder for the THRYCY USB-CAN adapter (CH340).

Packet: AA AA | body (escaped) | 55 55, body = ID (4 bytes LE), data (8), DLC,
channel, format (0 = standard, 1 = extended), type (0 = data), checksum (sum of
the 16 previous bytes). Any AA / 55 / A5 byte in the body is preceded by A5.
(Same format as python-can's "robotell" interface, which is too slow for
replaying 2,400 frames/s one call at a time.)
"""

HEAD, TAIL, ESC = 0xAA, 0x55, 0xA5
SERIAL_BAUD = 1_000_000      # adapter's USB-serial speed (was 500,000 out of the box)


def encode(can_id: int, data: bytes, extended: bool = False) -> bytes:
    body = bytearray(can_id.to_bytes(4, "little"))
    body += bytes(data[:8]).ljust(8, b"\0")
    body += bytes([min(len(data), 8), 0, 1 if extended else 0, 0])
    body.append(sum(body) & 0xFF)
    out = bytearray([HEAD, HEAD])
    for b in body:
        if b in (HEAD, TAIL, ESC):
            out.append(ESC)
        out.append(b)
    out += bytes([TAIL, TAIL])
    return bytes(out)


def road_frame(can_id: int, data: bytes) -> bytes:
    """ROAD's ID 0xFFF does not fit in 11 bits: send it as an extended frame
    (the firmware maps extended 0xFFF back to 0xFFF, any other extended ID is unknown)."""
    return encode(can_id, data, extended=can_id > 0x7FF)
