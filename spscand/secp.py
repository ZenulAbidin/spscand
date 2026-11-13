"""ctypes binding to the system libsecp256k1: the public-key operations a
watch-only scanner needs. SPSCAND_LIBSECP256K1 overrides the library path."""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import secrets
from typing import Iterable

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

_CONTEXT_SIGN_VERIFY = 0x0301  # legacy flags, accepted by every release
_EC_COMPRESSED = 0x0102


class InfinityError(ValueError):
    pass


def _load() -> ctypes.CDLL:
    candidates = [
        os.environ.get("SPSCAND_LIBSECP256K1"),
        "libsecp256k1.so.2",
        "libsecp256k1.so.1",
        "libsecp256k1.so",
        ctypes.util.find_library("secp256k1"),
        "libsecp256k1.dylib",
    ]
    errors = []
    for name in candidates:
        if not name:
            continue
        try:
            return ctypes.CDLL(name)
        except OSError as exc:
            errors.append(f"{name}: {exc}")
    raise ImportError(
        "libsecp256k1 not found (install it, e.g. apt install libsecp256k1-1, "
        "or set SPSCAND_LIBSECP256K1): " + "; ".join(errors)
    )


_lib = _load()
_c = ctypes.c_char_p
_vp = ctypes.c_void_p
_int = ctypes.c_int

_lib.secp256k1_context_create.restype = _vp
_lib.secp256k1_context_create.argtypes = [ctypes.c_uint]
_lib.secp256k1_context_randomize.restype = _int
_lib.secp256k1_context_randomize.argtypes = [_vp, _c]
_lib.secp256k1_ec_pubkey_parse.restype = _int
_lib.secp256k1_ec_pubkey_parse.argtypes = [_vp, _c, _c, ctypes.c_size_t]
_lib.secp256k1_ec_pubkey_serialize.restype = _int
_lib.secp256k1_ec_pubkey_serialize.argtypes = [
    _vp, _c, ctypes.POINTER(ctypes.c_size_t), _c, ctypes.c_uint
]
_lib.secp256k1_ec_pubkey_create.restype = _int
_lib.secp256k1_ec_pubkey_create.argtypes = [_vp, _c, _c]
_lib.secp256k1_ec_pubkey_combine.restype = _int
_lib.secp256k1_ec_pubkey_combine.argtypes = [
    _vp, _c, ctypes.POINTER(ctypes.c_char_p), ctypes.c_size_t
]
_lib.secp256k1_ec_pubkey_tweak_add.restype = _int
_lib.secp256k1_ec_pubkey_tweak_add.argtypes = [_vp, _c, _c]
_lib.secp256k1_ec_pubkey_tweak_mul.restype = _int
_lib.secp256k1_ec_pubkey_tweak_mul.argtypes = [_vp, _c, _c]
_lib.secp256k1_ec_pubkey_negate.restype = _int
_lib.secp256k1_ec_pubkey_negate.argtypes = [_vp, _c]

_ctx = _lib.secp256k1_context_create(_CONTEXT_SIGN_VERIFY)
_lib.secp256k1_context_randomize(_ctx, secrets.token_bytes(32))


def _scalar(value: int) -> bytes:
    if not 0 < value < N:
        raise ValueError("scalar out of range")
    return value.to_bytes(32, "big")


class Point:
    """A secp256k1 point other than infinity, in libsecp256k1's internal form."""

    __slots__ = ("_raw",)

    def __init__(self, raw: ctypes.Array) -> None:
        self._raw = raw

    @classmethod
    def parse(cls, data: bytes) -> "Point":
        if len(data) != 33:
            raise ValueError("expected a 33-byte compressed public key")
        raw = ctypes.create_string_buffer(64)
        if not _lib.secp256k1_ec_pubkey_parse(_ctx, raw, data, 33):
            raise ValueError("invalid public key")
        return cls(raw)

    @classmethod
    def lift_x(cls, x: bytes) -> "Point":
        if len(x) != 32:
            raise ValueError("expected a 32-byte x-only key")
        return cls.parse(b"\x02" + x)

    @classmethod
    def from_secret(cls, secret: int) -> "Point":
        raw = ctypes.create_string_buffer(64)
        if not _lib.secp256k1_ec_pubkey_create(_ctx, raw, _scalar(secret)):
            raise ValueError("invalid secret key")
        return cls(raw)

    @classmethod
    def sum(cls, points: Iterable["Point"]) -> "Point":
        raws = [p._raw for p in points]
        array = (ctypes.c_char_p * len(raws))(
            *[ctypes.cast(r, ctypes.c_char_p) for r in raws]
        )
        out = ctypes.create_string_buffer(64)
        if not _lib.secp256k1_ec_pubkey_combine(_ctx, out, array, len(raws)):
            raise InfinityError("sum is the point at infinity")
        return cls(out)

    def _copy(self) -> ctypes.Array:
        return ctypes.create_string_buffer(self._raw.raw, 64)

    def serialize(self) -> bytes:
        out = ctypes.create_string_buffer(33)
        size = ctypes.c_size_t(33)
        _lib.secp256k1_ec_pubkey_serialize(
            _ctx, out, ctypes.byref(size), self._raw, _EC_COMPRESSED
        )
        return out.raw

    def xonly(self) -> bytes:
        return self.serialize()[1:]

    def mul(self, scalar: int) -> "Point":
        raw = self._copy()
        if not _lib.secp256k1_ec_pubkey_tweak_mul(_ctx, raw, _scalar(scalar)):
            raise ValueError("invalid scalar")
        return Point(raw)

    def add_generator(self, scalar: int) -> "Point":
        """self + scalar·G"""
        raw = self._copy()
        if not _lib.secp256k1_ec_pubkey_tweak_add(_ctx, raw, _scalar(scalar)):
            raise InfinityError("result is the point at infinity")
        return Point(raw)

    def __neg__(self) -> "Point":
        raw = self._copy()
        _lib.secp256k1_ec_pubkey_negate(_ctx, raw)
        return Point(raw)

    def __add__(self, other: "Point") -> "Point":
        return Point.sum((self, other))

    def __sub__(self, other: "Point") -> "Point":
        return Point.sum((self, -other))

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Point) and self.serialize() == other.serialize()
