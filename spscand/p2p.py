"""A minimal Bitcoin P2P client: BIP157 compact filters and whole blocks.

It speaks the unencrypted v1 protocol, so a network observer (or a Tor exit,
for a clearnet peer) sees which filters and blocks are fetched; .onion peers
avoid that.
"""

from __future__ import annotations

import hashlib
import secrets
import socket
import struct
import time
from dataclasses import dataclass

from . import __version__
from .socks import connect as socks_connect, parse_proxy

MAGIC = {"main": "f9beb4d9", "test": "0b110907", "testnet4": "1c163f28",
         "signet": "0a03cf40", "regtest": "fabfb5da"}
DEFAULT_PORT = {"main": 8333, "test": 18333, "testnet4": 48333, "signet": 38333, "regtest": 18444}
PROTOCOL_VERSION = 70016
NODE_NETWORK = 1
NODE_COMPACT_FILTERS = 1 << 6
MSG_BLOCK = 2
BASIC_FILTER = 0
MAX_MESSAGE = 32 * 1024 * 1024  # Core's limit on a message (a block) is 32 MB
# A peer that has not indexed a block's filter yet stays silent; ask again later.
FILTER_TIMEOUT = 30


class P2PError(OSError):
    pass


def dsha256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def compact_size(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


class Reader:
    def __init__(self, data: bytes) -> None:
        self.data, self.pos = data, 0

    def take(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise P2PError("truncated message")
        chunk = self.data[self.pos:self.pos + n]
        self.pos += n
        return chunk

    def compact(self) -> int:
        first = self.take(1)[0]
        if first < 0xFD:
            return first
        return int.from_bytes(self.take({0xFD: 2, 0xFE: 4, 0xFF: 8}[first]), "little")

    def var_bytes(self) -> bytes:
        return self.take(self.compact())


def parse_peer(text: str, network: str) -> tuple[str, int]:
    """host, host:port or [ipv6]:port."""
    if text.startswith("["):
        host, _, rest = text[1:].partition("]")
        return host, int(rest[1:]) if rest.startswith(":") else DEFAULT_PORT[network]
    host, sep, port = text.rpartition(":")
    if sep and port.isdigit() and ":" not in host:
        return host, int(port)
    return text, DEFAULT_PORT[network]


@dataclass
class Tx:
    txid: str
    coinbase: bool
    inputs: list[tuple[str, int]]       # spent outpoints (display txid, vout)
    outputs: list[tuple[int, bytes]]    # (value in sat, scriptPubKey)


def _parse_tx(r: Reader) -> Tx:
    start = r.pos
    version = r.take(4)
    segwit = r.data[r.pos:r.pos + 2] == b"\x00\x01"
    if segwit:
        r.take(2)
    body_start = r.pos
    inputs, coinbase = [], False
    for _ in range(r.compact()):
        prev = r.take(32)
        vout = struct.unpack("<I", r.take(4))[0]
        r.var_bytes()
        r.take(4)
        if prev == bytes(32) and vout == 0xFFFFFFFF:
            coinbase = True
        inputs.append((prev[::-1].hex(), vout))
    outputs = []
    for _ in range(r.compact()):
        value = struct.unpack("<q", r.take(8))[0]
        outputs.append((value, r.var_bytes()))
    body_end = r.pos
    if segwit:
        for _ in inputs:
            for _ in range(r.compact()):
                r.var_bytes()
    locktime = r.take(4)
    if segwit:
        stripped = version + r.data[body_start:body_end] + locktime
    else:
        stripped = r.data[start:r.pos]
    return Tx(dsha256(stripped)[::-1].hex(), coinbase, [] if coinbase else inputs, outputs)


def merkle_root(txids: list[bytes]) -> bytes:
    level = txids
    while len(level) > 1:
        if len(level) % 2:
            level = level + [level[-1]]
        level = [dsha256(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def parse_block(raw: bytes, expected_hash: str | None = None) -> tuple[bytes, list[Tx]]:
    """The 80-byte header and the transactions, after checking the hash and merkle root."""
    header = raw[:80]
    if len(header) != 80:
        raise P2PError("truncated block")
    block_hash = dsha256(header)[::-1].hex()
    if expected_hash is not None and block_hash != expected_hash:
        raise P2PError(f"peer sent block {block_hash}, not {expected_hash}")
    r = Reader(raw)
    r.pos = 80
    txs = [_parse_tx(r) for _ in range(r.compact())]
    if r.pos != len(raw):
        raise P2PError("trailing data after block")
    txids = [bytes.fromhex(t.txid)[::-1] for t in txs]
    # Duplicated transactions leave the merkle root unchanged (CVE-2012-2459).
    if not txs or len(set(txids)) != len(txids) or merkle_root(txids) != header[36:68]:
        raise P2PError(f"block {block_hash} does not match its merkle root")
    return header, txs


class Peer:
    """One connection. Through a SOCKS proxy each Peer uses fresh credentials,
    so Tor (IsolateSOCKSAuth) puts it on a circuit of its own."""

    def __init__(self, host: str, port: int, network: str, *, proxy: str = "",
                 timeout: float = 60) -> None:
        self.host, self.port, self.timeout = host, port, timeout
        self.magic = bytes.fromhex(MAGIC[network])
        if proxy:
            self.sock = socks_connect(parse_proxy(proxy), host, port, timeout)
        else:
            self.sock = socket.create_connection((host, port), timeout)
        try:
            self._handshake()
        except BaseException:
            self.close()
            raise

    def __repr__(self) -> str:
        return f"peer {self.host}:{self.port}"

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass

    def send(self, command: str, payload: bytes = b"") -> None:
        header = (self.magic + command.encode().ljust(12, b"\0") +
                  struct.pack("<I", len(payload)) + dsha256(payload)[:4])
        self.sock.sendall(header + payload)

    def _recv_exact(self, n: int) -> bytes:
        data = bytearray()
        while len(data) < n:
            chunk = self.sock.recv(min(n - len(data), 1 << 20))
            if not chunk:
                raise P2PError(f"{self} closed the connection")
            data += chunk
        return bytes(data)

    def recv(self) -> tuple[str, bytes]:
        header = self._recv_exact(24)
        if header[:4] != self.magic:
            raise P2PError(f"{self} is on another network")
        length = struct.unpack("<I", header[16:20])[0]
        if length > MAX_MESSAGE:
            raise P2PError(f"{self} sent an oversized message")
        payload = self._recv_exact(length)
        if dsha256(payload)[:4] != header[20:24]:
            raise P2PError(f"{self} sent a corrupt message")
        command = header[4:16].rstrip(b"\0").decode("ascii", "replace")
        if command == "ping":
            self.send("pong", payload)
        return command, payload

    def wait_for(self, *commands: str, timeout: float | None = None) -> tuple[str, bytes]:
        """The next of these messages, skipping others. Every read is bounded
        by the deadline: a peer sending pings and invs while ignoring the
        request cannot hold us past it."""
        deadline = time.monotonic() + (self.timeout if timeout is None else timeout)
        try:
            while (left := deadline - time.monotonic()) > 0:
                self.sock.settimeout(left)
                command, payload = self.recv()
                if command in commands:
                    return command, payload
        except TimeoutError:
            pass  # the stream may now be mid-message: the caller drops the connection
        finally:
            self.sock.settimeout(self.timeout)
        raise P2PError(f"{self} did not answer in time")

    def _handshake(self) -> None:
        empty_addr = struct.pack("<Q", 0) + bytes(16) + struct.pack(">H", 0)
        agent = f"/spscand:{__version__}/".encode()
        self.send("version", struct.pack("<iQq", PROTOCOL_VERSION, 0, int(time.time())) +
                  empty_addr + empty_addr + secrets.token_bytes(8) +
                  compact_size(len(agent)) + agent + struct.pack("<i", 0) + b"\0")
        got_version = got_verack = False
        while not (got_version and got_verack):
            command, payload = self.wait_for("version", "verack")
            if command == "version":
                got_version = True
                self.services = struct.unpack("<Q", payload[4:12])[0]
                self.send("verack")
            else:
                got_verack = True
        if not self.services & NODE_COMPACT_FILTERS:
            raise P2PError(f"{self} does not serve compact filters (peerblockfilters=1)")

    def cfheaders(self, start: int, stop_hash: str) -> tuple[bytes, list[bytes]]:
        """(previous filter header, filter hashes) for heights start..stop."""
        stop = bytes.fromhex(stop_hash)[::-1]
        self.send("getcfheaders", bytes([BASIC_FILTER]) + struct.pack("<I", start) + stop)
        # Core does not answer at all for a block it has not indexed yet.
        _, payload = self.wait_for("cfheaders", timeout=min(self.timeout, FILTER_TIMEOUT))
        r = Reader(payload)
        if r.take(1)[0] != BASIC_FILTER or r.take(32) != stop:
            raise P2PError(f"{self} answered another cfheaders request")
        prev = r.take(32)
        return prev, [r.take(32) for _ in range(r.compact())]

    def cfilters(self, start: int, stop_hash: str, count: int) -> list[tuple[str, bytes]]:
        """(block hash, filter) for heights start..stop, in order."""
        stop = bytes.fromhex(stop_hash)[::-1]
        self.send("getcfilters", bytes([BASIC_FILTER]) + struct.pack("<I", start) + stop)
        filters = []
        while len(filters) < count:
            _, payload = self.wait_for("cfilter", timeout=min(self.timeout, FILTER_TIMEOUT))
            r = Reader(payload)
            if r.take(1)[0] != BASIC_FILTER:
                raise P2PError(f"{self} sent a filter of another type")
            block_hash = r.take(32)[::-1].hex()
            filters.append((block_hash, r.var_bytes()))
        return filters

    def block(self, block_hash: str) -> bytes:
        self.send("getdata", compact_size(1) + struct.pack("<I", MSG_BLOCK) +
                  bytes.fromhex(block_hash)[::-1])
        command, payload = self.wait_for("block", "notfound")
        if command == "notfound":
            raise P2PError(f"{self} does not have block {block_hash}")
        return payload


def filter_header(filter_hash: bytes, prev_header: bytes) -> bytes:
    return dsha256(filter_hash + prev_header)
