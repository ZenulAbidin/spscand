"""BIP158 filters (Core's test vectors) and the filters backend against fake peers."""

import json
import random
import tempfile
import threading
import time
import unittest
from unittest import mock
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from spscand import native, p2p
from spscand.backends import BackendError, FilterBackend
from spscand.bip352 import Receiver
from spscand.scanner import Scanner
from spscand.secp import N, Point
from spscand.store import Store

from fake_peer import FakeChain, FakePeer, tx_bytes
from socks_server import SocksServer
from test_native import _pay

VECTORS = Path(__file__).parent / "reference" / "blockfilters.json"
needs_native = unittest.skipUnless(native.available(), "libspscan not built (make -C libspscan)")


@needs_native
class FilterVectors(unittest.TestCase):
    def test_basic_filters(self):
        rows = json.loads(VECTORS.read_text())[1:]
        for height, block_hash, block_hex, prev_scripts, prev_header, want, header, note in rows:
            with self.subTest(note or height):
                raw = bytes.fromhex(block_hex)
                _, txs = p2p.parse_block(raw, block_hash)
                elements = {script for tx in txs for _, script in tx.outputs
                            if script and script[0] != 0x6A}
                elements |= {bytes.fromhex(s) for s in prev_scripts if s}
                key = bytes.fromhex(block_hash)[::-1]
                got = native.gcs_build(key, sorted(elements))
                self.assertEqual(got.hex(), want)
                self.assertEqual(
                    p2p.filter_header(p2p.dsha256(got), bytes.fromhex(prev_header)[::-1])[::-1].hex(),
                    header)
                if elements:
                    for element in elements:
                        self.assertTrue(native.gcs_match_any(got, key, [element]))

    def test_filter_check(self):
        rng = random.Random(158)
        receiver = Receiver(rng.randrange(1, N), Point.from_secret(rng.randrange(1, N)), labels=[1, 9])
        strangers = [_pay(rng, rng.randrange(1, N), Point.from_secret(rng.randrange(1, N)))
                     for _ in range(300)]
        key = bytes(range(32))
        scripts = [b"\x51\x20" + k for _, keys in strangers for k in keys]
        tweaks = [t for t, _ in strangers]
        empty = native.gcs_build(key, scripts)
        self.assertFalse(receiver.filter_check(tweaks, empty, key))
        for label in (None, 0, 9):
            tweak, keys = _pay(rng, receiver.scan_secret, receiver.spend_pubkey, label=label)
            paid = native.gcs_build(key, scripts + [b"\x51\x20" + keys[0]])
            with self.subTest(label=label):
                self.assertTrue(receiver.filter_check(tweaks + [tweak], paid, key))
                self.assertFalse(receiver.filter_check(tweaks, paid, key))
        unknown = _pay(rng, receiver.scan_secret, receiver.spend_pubkey, label=5)
        self.assertFalse(receiver.filter_check(
            [unknown[0]], native.gcs_build(key, [b"\x51\x20" + unknown[1][0]]), key))


class TweakServer:
    """BlindBit's /info, /tweaks and /spent-outputs for a FakeChain."""

    def __init__(self, chain: FakeChain) -> None:
        self.chain = chain
        self.tweaks: dict[int, list[str]] = {}
        self.paths: list[str] = []
        server = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                server.paths.append(self.path)
                parts = self.path.strip("/").split("/")
                if parts == ["info"]:
                    body = {"network": "regtest", "height": len(server.chain.blocks) - 1,
                            "tweaks_full_basic": True}
                else:
                    block = server.chain.blocks[int(parts[1])]
                    body = {"block_identifier": {"block_hash": block.hash_hex,
                                                 "block_height": block.height},
                            "index": server.tweaks.get(block.height, []) if parts[0] == "tweaks" else []}
                data = json.dumps(body).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.http = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.http.server_address[1]}"
        threading.Thread(target=self.http.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.http.shutdown()
        self.http.server_close()


@needs_native
class FilterBackendTest(unittest.TestCase):
    def setUp(self):
        rng = random.Random(157)
        self.rng = rng
        self.receiver = Receiver(rng.randrange(1, N), Point.from_secret(rng.randrange(1, N)), labels=[1])
        self.chain = FakeChain()
        self.server = TweakServer(self.chain)
        self.chain.add()  # block 0
        # Block 1: a payment to us (two outputs, one labelled) next to strangers.
        self.chain.add()
        tweak, keys = _pay(rng, self.receiver.scan_secret, self.receiver.spend_pubkey)
        tweak1, keys1 = _pay(rng, self.receiver.scan_secret, self.receiver.spend_pubkey, label=1)
        self.payment = tx_bytes([(rng.randbytes(32), 0)],
                                [(5000, b"\x51\x20" + keys[0]), (7000, b"\x51\x20" + keys1[0])])
        self.paid_keys = (keys[0], keys1[0])
        txs, tweaks = [self.payment], [tweak, tweak1]
        for _ in range(20):
            t, k = _pay(rng, rng.randrange(1, N), Point.from_secret(rng.randrange(1, N)))
            txs.append(tx_bytes([(rng.randbytes(32), 1)], [(1000, b"\x51\x20" + k[0])]))
            tweaks.append(t)
        self._replace(1, txs, tweaks)
        # Block 2: strangers only. Block 3: our first output is spent.
        self._extend([tx_bytes([(rng.randbytes(32), 0)], [(1, b"\x00\x14" + bytes(20))])],
                     [Point.from_secret(rng.randrange(1, N))])
        payment_txid = p2p.dsha256(self.payment)
        self.spend = tx_bytes([(payment_txid, 0)], [(4000, b"\x00\x14" + bytes(20))])
        self._extend([self.spend], [], spent_scripts=[b"\x51\x20" + keys[0]])
        self._extend([], [])
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name) / "w.sqlite", create=True)
        self.store.set_meta("birthday", "1")
        self.peers = [FakePeer(self.chain), FakePeer(self.chain)]

    def tearDown(self):
        for peer in self.peers:
            peer.close()
        self.server.close()
        self.store.close()
        self.tmp.cleanup()

    def _replace(self, height, txs, tweaks):
        del self.chain.blocks[height:]
        self._extend(txs, tweaks)

    def _extend(self, txs, tweaks, spent_scripts=()):
        block = self.chain.add(txs, spent_scripts)
        self.server.tweaks[block.height] = [t.serialize().hex() for t in tweaks]

    def scanner(self, peers=None, proxy="", timeout=10):
        backend = FilterBackend(self.server.url, [p.address for p in (peers or self.peers)],
                                proxy=proxy, timeout=timeout)
        self.assertEqual(backend.network(), "regtest")
        self.addCleanup(backend.close)
        return Scanner(self.store, self.receiver, backend), backend

    def test_finds_payment_and_spend_fetching_only_those_blocks(self):
        scanner, _ = self.scanner()
        self.assertEqual(scanner.sync(), 4)
        outputs = {o.vout: o for o in self.store.outputs()}
        self.assertEqual(sorted(outputs), [0, 1])
        self.assertEqual((outputs[0].amount, outputs[0].label), (5000, None))
        self.assertEqual((outputs[1].amount, outputs[1].label), (7000, 1))
        self.assertEqual(outputs[0].spent_txid, p2p.dsha256(self.spend)[::-1].hex())
        self.assertEqual(outputs[0].spent_height, 3)
        self.assertIsNone(outputs[1].spent_height)
        served = sorted(h for peer in self.peers for h in peer.blocks_served())
        self.assertEqual(served, sorted([self.chain.blocks[1].hash_hex, self.chain.blocks[3].hash_hex]))
        # The tweak server was asked for every block, nothing else.
        self.assertTrue(all(p == "/info" or p.split("/")[1] in ("tweaks", "spent-outputs")
                            for p in self.server.paths))

    def test_false_filter_is_rejected(self):
        self.peers[0].lie_filter_at = 1  # omits our payment, header honest
        scanner, _ = self.scanner(peers=[self.peers[0]])
        with self.assertRaisesRegex(BackendError, "does not match its header"):
            scanner.sync()

    def test_peers_disagreeing_is_an_error(self):
        self.peers[1].lie_filter_at = 1
        self.peers[1].lie_header_at = 1  # a consistent false filter chain
        scanner, _ = self.scanner()
        with self.assertRaisesRegex(BackendError, "peers disagree"):
            scanner.sync()
        self.assertEqual(self.store.outputs(), [])

    def test_unanswered_filter_request_times_out(self):
        # Core ignores a request for a block whose filter it has not indexed
        # yet, while still sending pings: give up at the deadline, retry later.
        tip = len(self.chain.blocks) - 1
        for peer in self.peers:
            peer.unindexed.add(tip)
        scanner, _ = self.scanner(timeout=3)
        started = time.monotonic()
        with mock.patch.object(p2p, "FILTER_TIMEOUT", 0.5), \
                self.assertRaisesRegex(BackendError, "no peer served filter headers"):
            scanner.sync()
        self.assertLess(time.monotonic() - started, 2.5)
        for peer in self.peers:
            peer.unindexed.clear()
        self.assertEqual(scanner.sync(), 4)
        self.assertEqual(len(self.store.outputs()), 2)

    def test_unreachable_peer_is_skipped(self):
        scanner, _ = self.scanner(peers=[self.peers[0]])
        backend = scanner.backend
        backend.peer_specs.append("127.0.0.1:1")
        backend.network()
        self.assertEqual(scanner.sync(), 4)
        self.assertEqual(len(self.store.outputs()), 2)

    def test_tor_isolation(self):
        names = {f"peer{i}xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.onion":
                 ("127.0.0.1", int(p.address.split(":")[1])) for i, p in enumerate(self.peers)}
        socks = SocksServer(names)
        try:
            backend = FilterBackend(self.server.url, [f"{n}:{port}" for n, (_, port) in names.items()],
                                    proxy=socks.url, timeout=10)
            backend.network()
            scanner = Scanner(self.store, self.receiver, backend)
            scanner.sync()
            backend.close()
        finally:
            socks.close()
        self.assertEqual(len(self.store.outputs()), 2)
        peer_requests = [r for r in socks.requests if r["host"] in names]
        self.assertTrue(all(r["kind"] == 3 for r in peer_requests))
        # Two filter connections plus one per downloaded block, each with its own credentials.
        self.assertEqual(len(peer_requests), 4)
        self.assertEqual(len({r["user"] for r in peer_requests}), 4)


@needs_native
class BlockParsing(unittest.TestCase):
    def test_duplicated_transactions_are_rejected(self):
        chain = FakeChain()
        tx = tx_bytes([(bytes(range(32)), 0)], [(1, b"\x51")])
        chain.add([tx, tx[:]])  # 3 txs: coinbase, tx, tx
        block = chain.blocks[0]
        with self.assertRaisesRegex(p2p.P2PError, "merkle"):
            p2p.parse_block(block.raw, block.hash_hex)

    def test_wrong_hash(self):
        chain = FakeChain()
        block = chain.add()
        with self.assertRaisesRegex(p2p.P2PError, "not"):
            p2p.parse_block(block.raw, "00" * 32)


if __name__ == "__main__":
    unittest.main()
