"""BIP352 (Silent Payments) receiving, version 1.1.2."""

from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import new as hashlib_new, sha256
from typing import Sequence

from . import bech32
from .secp import N, InfinityError, Point

K_MAX = 2323
# Labels are checked by adding each to P_k when there are at most this many
# labels per remaining output, else by subtracting P_k from each output.
LABEL_ADDITION_RATIO = 2
# BIP341 NUMS point H (x-only): script-path spends with this internal key are skipped.
NUMS_H = bytes.fromhex("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")

HRP = {"main": "sp", "test": "tsp", "testnet4": "tsp", "signet": "tsp", "regtest": "tsp"}


class InvalidScalarError(ValueError):
    """A hash is 0 or >= n; BIP352 says to fail rather than reduce it."""


def tagged_hash(tag: str, msg: bytes) -> bytes:
    tag_hash = sha256(tag.encode()).digest()
    return sha256(tag_hash + tag_hash + msg).digest()


def _hash_scalar(tag: str, msg: bytes) -> int:
    value = int.from_bytes(tagged_hash(tag, msg), "big")
    if not 0 < value < N:
        raise InvalidScalarError(f"{tag} hash is not a valid scalar")
    return value


def _hash160(data: bytes) -> bytes:
    return hashlib_new("ripemd160", sha256(data).digest()).digest()


@dataclass(frozen=True)
class TxInput:
    txid: str  # display (big-endian) hex
    vout: int
    script_sig: bytes
    witness: tuple[bytes, ...]
    prevout_script: bytes

    def outpoint(self) -> bytes:
        return bytes.fromhex(self.txid)[::-1] + self.vout.to_bytes(4, "little")


def _is_p2tr(spk: bytes) -> bool:
    return len(spk) == 34 and spk[0] == 0x51 and spk[1] == 0x20


def _is_p2wpkh(spk: bytes) -> bool:
    return len(spk) == 22 and spk[0] == 0x00 and spk[1] == 0x14


def _is_p2sh(spk: bytes) -> bool:
    return len(spk) == 23 and spk[0] == 0xA9 and spk[1] == 0x14 and spk[22] == 0x87


def _is_p2pkh(spk: bytes) -> bool:
    return len(spk) == 25 and spk[:3] == b"\x76\xa9\x14" and spk[23:] == b"\x88\xac"


def spends_future_segwit(spk: bytes) -> bool:
    # Witness v2-v16: a transaction spending one is not eligible, so that
    # future output types can define their own rules.
    return 4 <= len(spk) <= 42 and 0x52 <= spk[0] <= 0x60 and spk[1] == len(spk) - 2


def _compressed(data: bytes) -> Point | None:
    if len(data) != 33:
        return None
    try:
        return Point.parse(data)
    except ValueError:
        return None


def input_public_key(txin: TxInput) -> Point | None:
    """The key this input contributes, or None if BIP352 skips it."""
    spk = txin.prevout_script
    if _is_p2pkh(spk):
        # Search the scriptSig from the back for a key matching the hash, so a
        # malleated (non-template) scriptSig still yields the key.
        key_hash = spk[3:23]
        script = txin.script_sig
        for end in range(len(script), 32, -1):
            candidate = script[end - 33:end]
            if _hash160(candidate) == key_hash:
                key = _compressed(candidate)
                if key is not None:
                    return key
        return None
    if _is_p2sh(spk):
        if _is_p2wpkh(txin.script_sig[1:]) and txin.witness:
            return _compressed(txin.witness[-1])
        return None
    if _is_p2wpkh(spk):
        return _compressed(txin.witness[-1]) if txin.witness else None
    if _is_p2tr(spk):
        stack = list(txin.witness)
        if not stack:
            return None
        if len(stack) > 1 and stack[-1][:1] == b"\x50":
            stack.pop()  # annex
        # Script path with the NUMS internal key: no one has the key, skip.
        if len(stack) > 1 and stack[-1][1:33] == NUMS_H:
            return None
        try:
            return Point.lift_x(spk[2:])
        except ValueError:
            return None
    return None


def tweak_point(inputs: Sequence[TxInput]) -> Point | None:
    """input_hash·A, or None if the inputs make the transaction ineligible.

    The caller checks that the transaction has a taproot output.
    """
    keys = []
    for txin in inputs:
        if spends_future_segwit(txin.prevout_script):
            return None
        key = input_public_key(txin)
        if key is not None:
            keys.append(key)
    if not keys:
        return None
    try:
        total = Point.sum(keys)
    except InfinityError:
        return None
    smallest = min(txin.outpoint() for txin in inputs)
    input_hash = _hash_scalar("BIP0352/Inputs", smallest + total.serialize())
    return total.mul(input_hash)


def label_tweak(scan_secret: int, m: int) -> int:
    return _hash_scalar("BIP0352/Label", scan_secret.to_bytes(32, "big") + m.to_bytes(4, "big"))


def encode_address(scan_pubkey: Point, spend_pubkey: Point, network: str) -> str:
    return bech32.encode(HRP[network], 0, scan_pubkey.serialize() + spend_pubkey.serialize())


def decode_address(address: str, network: str) -> tuple[Point, Point]:
    hrp, version, data = bech32.decode(address)
    if hrp != HRP[network]:
        raise ValueError(f"expected a {HRP[network]} address")
    if version == 31:
        raise ValueError("unsupported silent payment address version")
    if version == 0 and len(data) != 66:
        raise ValueError("version 0 address must carry 66 bytes")
    # Versions 1-30 may append data; a version 0 reader uses the first 66 bytes.
    if len(data) < 66:
        raise ValueError("address too short")
    return Point.parse(data[:33]), Point.parse(data[33:66])


def index_keys(outputs: Sequence[bytes]) -> dict[bytes, list[int]]:
    by_key: dict[bytes, list[int]] = {}
    for index, key in enumerate(outputs):
        by_key.setdefault(key, []).append(index)
    return by_key


@dataclass(frozen=True)
class Found:
    index: int  # position in the outputs passed to scan()
    xonly: bytes
    tweak: int  # spend with (b_spend + tweak) mod n
    label: int | None


@dataclass
class Receiver:
    scan_secret: int
    spend_pubkey: Point
    labels: Sequence[int] = ()
    check_change_label: bool = True
    _label_points: dict[bytes, tuple[int, int]] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        wanted = set(self.labels)
        # BIP352 reserves m = 0 for change; a wallet restored from backup must find it.
        if self.check_change_label:
            wanted.add(0)
        self._label_points = {}
        self._label_list = []
        for m in sorted(wanted):
            tweak = label_tweak(self.scan_secret, m)
            point = Point.from_secret(tweak)
            self._label_points[point.serialize()] = (m, tweak)
            self._label_list.append((m, tweak, point))

    @property
    def scan_pubkey(self) -> Point:
        return Point.from_secret(self.scan_secret)

    def address(self, network: str, label: int | None = None) -> str:
        spend = self.spend_pubkey
        if label is not None:
            spend = spend.add_generator(label_tweak(self.scan_secret, label))
        return encode_address(self.scan_pubkey, spend, network)

    def scan(self, tweak: Point, outputs: Sequence[bytes],
             by_key: dict[bytes, list[int]] | None = None) -> list[Found]:
        """Find this receiver's outputs among x-only taproot keys.

        Pass `by_key` (from index_keys) to reuse one index for many tweaks.
        """
        if by_key is None:
            by_key = index_keys(outputs)
        secret = tweak.mul(self.scan_secret).serialize()
        taken: set[int] = set()
        lifted: dict[int, Point | None] = {}
        found: list[Found] = []
        for k in range(K_MAX):
            t_k = _hash_scalar("BIP0352/SharedSecret", secret + k.to_bytes(4, "big"))
            p_k = self.spend_pubkey.add_generator(t_k)
            match = self._match(p_k, t_k, outputs, by_key, taken, lifted)
            if match is None:
                break
            found.append(match)
            taken.add(match.index)
        return found

    def _match(self, p_k, t_k, outputs, by_key, taken, lifted) -> Found | None:
        def first(key):
            return next((i for i in by_key.get(key, ()) if i not in taken), None)

        # A direct match is checked first; a sender following BIP352 never
        # produces both a direct and a labelled match for the same k.
        index = first(p_k.xonly())
        if index is not None:
            return Found(index, p_k.xonly(), t_k, None)
        if len(self._label_list) <= LABEL_ADDITION_RATIO * (len(outputs) - len(taken)):
            # Few labels: x(P_k + label) matching an output is equivalent to
            # (+/-output - P_k) being the label, and cheaper.
            for m, label_scalar, label_point in self._label_list:
                try:
                    key = (p_k + label_point).xonly()
                except InfinityError:
                    continue
                index = first(key)
                if index is not None:
                    return Found(index, key, (t_k + label_scalar) % N, m)
            return None
        for index, key in enumerate(outputs):
            if index in taken:
                continue
            if index not in lifted:
                try:
                    lifted[index] = Point.lift_x(key)
                except ValueError:
                    lifted[index] = None
            point = lifted[index]
            if point is None:
                continue
            for candidate in (point, -point):
                try:
                    diff = (candidate - p_k).serialize()
                except InfinityError:
                    continue
                label = self._label_points.get(diff)
                if label is not None:
                    m, label_scalar = label
                    return Found(index, key, (t_k + label_scalar) % N, m)
        return None
