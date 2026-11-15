"""A fake Bitcoin P2P peer serving BIP157 filters and blocks of a synthetic chain,
and helpers to build that chain. Tests can make it lie."""

from __future__ import annotations

import secrets
import socketserver
import struct
import threading
import time

from spscand import native
from spscand.p2p import (BASIC_FILTER, MAGIC, NODE_COMPACT_FILTERS, NODE_NETWORK, Reader,
                         compact_size, dsha256, filter_header, merkle_root)


def tx_bytes(inputs: list[tuple[bytes, int]], outputs: list[tuple[int, bytes]]) -> bytes:
    """A legacy-serialized transaction. inputs: (prev txid internal order, vout)."""
    data = struct.pack("<i", 2) + compact_size(len(inputs))
    for prev, vout in inputs:
        data += prev + struct.pack("<I", vout) + b"\x00" + b"\xff\xff\xff\xff"
    data += compact_size(len(outputs))
    for value, script in outputs:
        data += struct.pack("<q", value) + compact_size(len(script)) + script
    return data + bytes(4)


def coinbase(height: int) -> bytes:
    return (struct.pack("<i", 2) + b"\x01" + bytes(32) + b"\xff\xff\xff\xff" +
            b"\x04" + struct.pack("<I", height) + b"\xff\xff\xff\xff" +
            b"\x01" + struct.pack("<q", 50 * 10**8) + b"\x01\x51" + bytes(4))


class FakeBlock:
    def __init__(self, height: int, prev_hash: bytes, txs: list[bytes],
                 spent_scripts: list[bytes]) -> None:
        self.height = height
        self.txs = txs
        txids = [dsha256(t) for t in txs]
        self.header = (struct.pack("<i", 0x20000000) + prev_hash + merkle_root(txids) +
                       struct.pack("<III", 1700000000 + height, 0x207FFFFF, 0))
        self.hash = dsha256(self.header)  # internal order
        self.raw = self.header + compact_size(len(txs)) + b"".join(txs)
        self.txids = [t[::-1].hex() for t in txids]
        elements = set(spent_scripts)
        for t in txs:
            r = Reader(t)
            r.take(4)
            for _ in range(r.compact()):
                r.take(36)
                r.var_bytes()
                r.take(4)
            for _ in range(r.compact()):
                r.take(8)
                script = r.var_bytes()
                if script and script[0] != 0x6A:
                    elements.add(script)
        self.filter = native.gcs_build(self.hash, sorted(elements))

    @property
    def hash_hex(self) -> str:
        return self.hash[::-1].hex()


class FakeChain:
    def __init__(self) -> None:
        self.blocks: list[FakeBlock] = []

    def add(self, txs: list[bytes] = (), spent_scripts: list[bytes] = ()) -> FakeBlock:
        height = len(self.blocks)
        prev = self.blocks[-1].hash if self.blocks else bytes(32)
        block = FakeBlock(height, prev, [coinbase(height)] + list(txs), list(spent_scripts))
        self.blocks.append(block)
        return block

    def filter_headers(self) -> list[bytes]:
        headers, prev = [], bytes(32)
        for block in self.blocks:
            prev = filter_header(dsha256(block.filter), prev)
            headers.append(prev)
        return headers


class FakePeer:
    def __init__(self, chain: FakeChain, network: str = "regtest") -> None:
        self.chain = chain
        self.magic = bytes.fromhex(MAGIC[network])
        self.services = NODE_NETWORK | NODE_COMPACT_FILTERS
        self.lie_filter_at: int | None = None   # serve a wrong filter for this height
        self.lie_header_at: int | None = None   # and a matching false header chain
        self.unindexed: set[int] = set()  # heights whose filters it ignores requests for, as Core
        self.requests: list[tuple[str, object]] = []
        self.connections = 0
        peer = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                peer.connections += 1
                try:
                    while True:
                        command, payload = self.recv()
                        peer.requests.append((command, payload))
                        self.answer(command, payload)
                except (ConnectionError, OSError, IndexError):
                    pass

            def recv_exact(self, n):
                data = b""
                while len(data) < n:
                    chunk = self.request.recv(n - len(data))
                    if not chunk:
                        raise ConnectionError
                    data += chunk
                return data

            def recv(self):
                header = self.recv_exact(24)
                payload = self.recv_exact(struct.unpack("<I", header[16:20])[0])
                return header[4:16].rstrip(b"\0").decode(), payload

            def send(self, command, payload=b""):
                self.request.sendall(peer.magic + command.encode().ljust(12, b"\0") +
                                     struct.pack("<I", len(payload)) + dsha256(payload)[:4] + payload)

            def answer(self, command, payload):
                if command == "version":
                    self.send("version", struct.pack("<iQq", 70016, peer.services, 0) +
                              bytes(52) + secrets.token_bytes(8) + b"\x00" +
                              struct.pack("<i", len(peer.chain.blocks) - 1) + b"\x00")
                    self.send("ping", bytes(8))
                    self.send("verack")
                elif command in ("getcfheaders", "getcfilters"):
                    start = struct.unpack("<I", payload[1:5])[0]
                    stop_hash = payload[5:37]
                    stop = next(b.height for b in peer.chain.blocks if b.hash == stop_hash)
                    if stop in peer.unindexed:
                        time.sleep(0.4)  # no answer; one ping, then silence
                        self.send("ping", bytes(8))
                        time.sleep(4)
                        return
                    filters = [b.filter for b in peer.chain.blocks]
                    if peer.lie_filter_at is not None:
                        filters[peer.lie_filter_at] = native.gcs_build(
                            peer.chain.blocks[peer.lie_filter_at].hash, [b"\x51"])
                    if command == "getcfilters":
                        for height in range(start, stop + 1):
                            block = peer.chain.blocks[height]
                            self.send("cfilter", bytes([BASIC_FILTER]) + block.hash +
                                      compact_size(len(filters[height])) + filters[height])
                        return
                    honest = [dsha256(f) for f in (b.filter for b in peer.chain.blocks)]
                    hashes = [dsha256(f) for f in filters] if peer.lie_header_at is not None else honest
                    prev = bytes(32)
                    for h in hashes[:start]:
                        prev = filter_header(h, prev)
                    self.send("cfheaders", bytes([BASIC_FILTER]) + stop_hash + prev +
                              compact_size(stop - start + 1) + b"".join(hashes[start:stop + 1]))
                elif command == "getdata":
                    wanted = payload[5:37]
                    block = next((b for b in peer.chain.blocks if b.hash == wanted), None)
                    if block is None:
                        self.send("notfound", payload)
                    else:
                        self.send("block", block.raw)

        class Server(socketserver.ThreadingTCPServer):
            daemon_threads = True
            allow_reuse_address = True

        self.server = Server(("127.0.0.1", 0), Handler)
        self.address = f"127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def blocks_served(self) -> list[str]:
        return [payload[5:37][::-1].hex() for command, payload in self.requests if command == "getdata"]

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
