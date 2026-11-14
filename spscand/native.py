"""ctypes binding to libspscan, the C scanning library in libspscan/.

spscand works without it, using the Python code in bip352.py; with it, label
matching and filter checks are much faster. SPSCAND_LIBSPSCAN sets the library
path; SPSCAND_PURE_PYTHON=1 disables it.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import secrets
from pathlib import Path
from typing import Sequence

OK, ERR_ARG, ERR_NOMEM, ERR_SCALAR, ERR_INFINITY, ERR_FILTER, ERR_SPACE = 0, -1, -2, -3, -4, -5, -6
NO_CHANGE_LABEL, LABELS_BY_ADDITION, LABELS_BY_SUBTRACTION = 1, 2, 4

_c = ctypes.c_char_p
_size = ctypes.c_size_t


class Match(ctypes.Structure):
    _fields_ = [("tweak", ctypes.c_uint32), ("output", ctypes.c_uint32), ("k", ctypes.c_uint32),
                ("label", ctypes.c_int64), ("key_tweak", ctypes.c_ubyte * 32)]


class Input(ctypes.Structure):
    _fields_ = [("outpoint", _c), ("script_sig", _c), ("script_sig_len", _size),
                ("witness", ctypes.POINTER(_c)), ("witness_lens", ctypes.POINTER(_size)),
                ("n_witness", _size), ("prevout_script", _c), ("prevout_script_len", _size)]


class NativeError(RuntimeError):
    def __init__(self, function: str, code: int) -> None:
        super().__init__(f"{function} failed with error {code}")
        self.code = code


def _load() -> ctypes.CDLL | None:
    if os.environ.get("SPSCAND_PURE_PYTHON") == "1":
        return None
    path = os.environ.get("SPSCAND_LIBSPSCAN")
    if path:
        return ctypes.CDLL(path)  # set explicitly: a failure should be loud
    checkout = Path(__file__).resolve().parent.parent / "libspscan" / "libspscan.so"
    for name in (str(checkout), "libspscan.so.0", ctypes.util.find_library("spscan")):
        if not name:
            continue
        try:
            return ctypes.CDLL(name)
        except OSError:
            continue
    return None


_lib = _load()

if _lib is not None:
    _vp = ctypes.c_void_p
    _int_p = ctypes.POINTER(ctypes.c_int)
    _lib.spscan_version.restype = _c
    _lib.spscan_receiver_create.argtypes = [ctypes.POINTER(_vp), _c, _c,
                                            ctypes.POINTER(ctypes.c_uint32), _size,
                                            ctypes.c_uint, _c]
    _lib.spscan_receiver_destroy.argtypes = [_vp]
    _lib.spscan_receiver_destroy.restype = None
    _lib.spscan_receiver_scan_pubkey.argtypes = [_vp, _c]
    _lib.spscan_scan.argtypes = [_vp, _c, _size, _c, _size, ctypes.POINTER(Match),
                                 ctypes.POINTER(_size)]
    _lib.spscan_tweak_from_inputs.argtypes = [ctypes.POINTER(Input), _size, _c]
    _lib.spscan_gcs_match_any.argtypes = [_c, _size, _c, ctypes.POINTER(_c),
                                          ctypes.POINTER(_size), _size, _int_p]
    _lib.spscan_gcs_build.argtypes = [_c, ctypes.POINTER(_c), ctypes.POINTER(_size), _size,
                                      _c, ctypes.POINTER(_size)]
    _lib.spscan_filter_check.argtypes = [_vp, _c, _size, _c, _size, _c, _int_p]


def available() -> bool:
    return _lib is not None


def version() -> str:
    return _lib.spscan_version().decode()


def _check(function: str, code: int) -> int:
    if code < 0:
        raise NativeError(function, code)
    return code


class Receiver:
    def __init__(self, scan_secret: int, spend_pubkey: bytes, labels: Sequence[int] = (),
                 flags: int = 0) -> None:
        self._handle = ctypes.c_void_p()
        array = (ctypes.c_uint32 * max(len(labels), 1))(*labels)
        _check("spscan_receiver_create", _lib.spscan_receiver_create(
            ctypes.byref(self._handle), scan_secret.to_bytes(32, "big"), spend_pubkey,
            array, len(labels), flags, secrets.token_bytes(32)))

    def __del__(self) -> None:
        if getattr(self, "_handle", None) and _lib is not None:
            _lib.spscan_receiver_destroy(self._handle)
            self._handle = None

    def scan_pubkey(self) -> bytes:
        out = ctypes.create_string_buffer(33)
        _check("spscan_receiver_scan_pubkey", _lib.spscan_receiver_scan_pubkey(self._handle, out))
        return out.raw

    def scan(self, tweaks: Sequence[bytes], outputs: Sequence[bytes]
             ) -> list[tuple[int, int, int, int | None]]:
        """(tweak index, output index, key tweak, label) for each match."""
        tweak_data, output_data = b"".join(tweaks), b"".join(outputs)
        room = 16
        while True:
            matches = (Match * room)()
            count = _size(room)
            code = _lib.spscan_scan(self._handle, tweak_data, len(tweaks), output_data,
                                    len(outputs), matches, ctypes.byref(count))
            if code != ERR_SPACE:
                break
            room = count.value
        _check("spscan_scan", code)
        return [(m.tweak, m.output, int.from_bytes(bytes(m.key_tweak), "big"),
                 None if m.label < 0 else m.label) for m in matches[:count.value]]

    def filter_check(self, tweaks: Sequence[bytes], filter_data: bytes, block_hash: bytes) -> bool:
        """block_hash in internal byte order."""
        match = ctypes.c_int()
        _check("spscan_filter_check", _lib.spscan_filter_check(
            self._handle, b"".join(tweaks), len(tweaks), filter_data, len(filter_data),
            block_hash, ctypes.byref(match)))
        return bool(match.value)


def tweak_from_inputs(inputs) -> bytes | None:
    """inputs: bip352.TxInput objects. Returns the 33-byte tweak or None."""
    keep = []
    array = (Input * max(len(inputs), 1))()
    for slot, txin in zip(array, inputs):
        witness = (_c * max(len(txin.witness), 1))(*txin.witness)
        lens = (_size * max(len(txin.witness), 1))(*map(len, txin.witness))
        outpoint = txin.outpoint()
        keep += [witness, lens, outpoint]
        slot.outpoint = outpoint
        slot.script_sig, slot.script_sig_len = txin.script_sig, len(txin.script_sig)
        slot.witness, slot.witness_lens, slot.n_witness = witness, lens, len(txin.witness)
        slot.prevout_script = txin.prevout_script
        slot.prevout_script_len = len(txin.prevout_script)
    out = ctypes.create_string_buffer(33)
    code = _check("spscan_tweak_from_inputs",
                  _lib.spscan_tweak_from_inputs(array, len(inputs), out))
    return out.raw if code == 1 else None


def _items(items: Sequence[bytes]):
    return (_c * max(len(items), 1))(*items), (_size * max(len(items), 1))(*map(len, items))


def gcs_match_any(filter_data: bytes, block_hash: bytes, items: Sequence[bytes]) -> bool:
    pointers, lens = _items(items)
    match = ctypes.c_int()
    _check("spscan_gcs_match_any", _lib.spscan_gcs_match_any(
        filter_data, len(filter_data), block_hash, pointers, lens, len(items), ctypes.byref(match)))
    return bool(match.value)


def gcs_build(block_hash: bytes, items: Sequence[bytes]) -> bytes:
    pointers, lens = _items(items)
    size = _size(9 + 3 * len(items) + 8)
    out = ctypes.create_string_buffer(size.value)
    _check("spscan_gcs_build", _lib.spscan_gcs_build(block_hash, pointers, lens, len(items),
                                                     out, ctypes.byref(size)))
    return out.raw[:size.value]
