"""The BlindBit backend against real BlindBit responses for mainnet block 833044,
served over a SOCKS5 proxy under a .onion name."""

import gzip
import json
import os
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from socks_server import SocksServer
from spscand.backends import BackendError, BlindBitBackend
from spscand.bip352 import TxInput, tweak_point

FIXTURES = Path(__file__).parent / "fixtures"
HEIGHT = 833044
ONION = "blindbitxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.onion"


def _responses():
    block = json.loads(gzip.decompress((FIXTURES / "block-833044.json.gz").read_bytes()))
    ident = {"block_hash": block["hash"], "block_height": HEIGHT}
    spent = [spk[4:20] for tx in block["txs"] for *_, spk in tx["vin"]
             if len(spk) == 68 and spk.startswith("5120")]
    return block, {
        f"/tweaks/{HEIGHT}": json.loads((FIXTURES / "tweaks-833044.json").read_text()),
        f"/utxos/{HEIGHT}": json.loads((FIXTURES / "utxos-833044.json").read_text()),
        f"/spent-outputs/{HEIGHT}": {"block_identifier": ident, "index": spent},
        "/info": {"network": "mainnet", "height": HEIGHT, "tweaks_full_basic": True},
    }


class BlindBitOverSocks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.block, responses = _responses()
        cls.requests = []
        test = cls

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                test.requests.append((self.headers["Host"], self.path))
                body, status = responses.get(self.path), 200
                if body is None:  # BlindBit's error shape
                    body, status = {"success": False, "data": {"error": "not found"}}, 500
                data = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        cls.http = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=cls.http.serve_forever, daemon=True).start()
        cls.socks = SocksServer({ONION: cls.http.server_address})

    @classmethod
    def tearDownClass(cls):
        cls.socks.close()
        cls.http.shutdown()

    def setUp(self):
        self.requests.clear()
        self.socks.requests.clear()

    def backend(self):
        return BlindBitBackend(f"http://{ONION}", proxy=self.socks.url)

    def test_block_matches_raw_block(self):
        with mock.patch.dict(os.environ, {"http_proxy": "http://127.0.0.1:9"}):
            backend = self.backend()
            self.assertEqual(backend.network(), "main")
            block = backend.block(HEIGHT)
        tweaks, outputs = [], []
        for tx in self.block["txs"]:
            taproot = [(tx["txid"], n, value, spk[4:]) for n, (spk, value) in enumerate(tx["vout"])
                       if len(spk) == 68 and spk.startswith("5120")]
            if not tx["vin"] or not taproot:
                continue
            tweak = tweak_point([
                TxInput(txid, vout, bytes.fromhex(sig), tuple(bytes.fromhex(w) for w in wit),
                        bytes.fromhex(spk))
                for txid, vout, sig, wit, spk in tx["vin"]])
            if tweak is not None:
                tweaks.append(tweak.serialize())
                outputs += taproot
        self.assertEqual((block.hash, block.prev_hash), (self.block["hash"], None))
        [group] = block.groups
        self.assertEqual(sorted(t.serialize() for t in group.tweaks), sorted(tweaks))
        self.assertEqual(sorted((o.txid, o.vout, o.amount, o.key.hex()) for o in group.outputs),
                         sorted(outputs))
        self.assertTrue(block.spent_prefixes)
        # Only whole-block requests, and none for anything wallet-specific.
        self.assertEqual(sorted(p for _, p in self.requests), sorted([
            "/info", f"/tweaks/{HEIGHT}", f"/utxos/{HEIGHT}", f"/spent-outputs/{HEIGHT}"]))

    def test_proxy_resolves_names_and_isolates(self):
        first, second = self.backend(), self.backend()
        first.tip()
        first.tip()
        second.tip()
        seen = self.socks.requests
        self.assertEqual(len(seen), 3)
        self.assertTrue(all(r["kind"] == 3 and r["host"] == ONION for r in seen), seen)
        self.assertEqual({host for host, _ in self.requests}, {ONION})
        # Same credentials within one backend, different between backends.
        self.assertEqual(seen[0]["user"], seen[1]["user"])
        self.assertNotEqual(seen[0]["user"], seen[2]["user"])

    def test_error_response(self):
        with self.assertRaisesRegex(BackendError, "not found"):
            self.backend().block(HEIGHT + 1)


if __name__ == "__main__":
    unittest.main()
