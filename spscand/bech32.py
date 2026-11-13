"""Bech32m (BIP350) without the 90-character limit, for BIP352 addresses."""

from __future__ import annotations

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32M_CONST = 0x2BC830A3


def _polymod(values: list[int]) -> int:
    generator = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if (top >> i) & 1 else 0
    return chk


def _hrp_expand(hrp: str) -> list[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def convertbits(data, frombits: int, tobits: int, pad: bool) -> list[int]:
    acc = bits = 0
    out = []
    maxv = (1 << tobits) - 1
    for value in data:
        if value < 0 or value >> frombits:
            raise ValueError("invalid data value")
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            out.append((acc >> bits) & maxv)
    if pad:
        if bits:
            out.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        raise ValueError("invalid padding")
    return out


def encode(hrp: str, version: int, data: bytes) -> str:
    values = [version] + convertbits(data, 8, 5, True)
    polymod = _polymod(_hrp_expand(hrp) + values + [0] * 6) ^ _BECH32M_CONST
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(CHARSET[v] for v in values + checksum)


def decode(address: str) -> tuple[str, int, bytes]:
    """Return (hrp, version, data) of a bech32m string."""
    if address.lower() != address and address.upper() != address:
        raise ValueError("mixed case")
    address = address.lower()
    pos = address.rfind("1")
    if pos < 1 or pos + 7 > len(address):
        raise ValueError("invalid separator position")
    hrp = address[:pos]
    if any(ord(c) < 33 or ord(c) > 126 for c in hrp):
        raise ValueError("invalid human-readable part")
    try:
        values = [CHARSET.index(c) for c in address[pos + 1:]]
    except ValueError:
        raise ValueError("invalid character") from None
    if _polymod(_hrp_expand(hrp) + values) != _BECH32M_CONST:
        raise ValueError("invalid bech32m checksum")
    payload = values[:-6]
    if not payload:
        raise ValueError("missing version")
    return hrp, payload[0], bytes(convertbits(payload[1:], 5, 8, False))
