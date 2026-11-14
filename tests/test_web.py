"""spscand web against a fake mainnet BlindBit serving synthetic blocks."""

import json
import random
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from spscand import native
from spscand.bip352 import encode_address
from spscand.secp import Point

from test_native import _key, _pay

ROOT = Path(__file__).resolve().parent.parent
NODE = shutil.which("node")
WASM = ROOT / "libspscan" / "spscan.wasm"

if native.available():
    from spscand import web
    BASE = web.TAPROOT_HEIGHT
    N_BLOCKS = 60


def _make_chain(rng, scan_secret, spend):
    """{height: (hash, txs)} with payments to (scan_secret, spend) at known places."""
    plan = {BASE + 5: [(None, 1)], BASE + 20: [(0, 2)], BASE + 41: [(3, 1), (None, 1)],
            BASE + N_BLOCKS - 1: [(None, 1)]}
    chain = {}
    for height in range(BASE, BASE + N_BLOCKS):
        txs = []
        n_strangers = 0 if height == BASE + 10 else rng.randrange(5, 40)
        for _ in range(n_strangers):
            tweak, keys = _pay(rng, _key(rng), Point.from_secret(_key(rng)), count=rng.choice([1, 2]))
            txs.append((tweak, keys))
        for label, count in plan.get(height, []):
            txs.append(_pay(rng, scan_secret, spend, label=label, count=count))
        rng.shuffle(txs)
        block = []
        for tweak, keys in txs:
            txid = rng.randbytes(32).hex()
            utxos = [{"vout": v + 1, "amount": 1000 + rng.randrange(10**6),
                      "pubkey": key.hex()} for v, key in enumerate(keys)]
            block.append({"txid": txid, "tweak": tweak.serialize().hex(), "inputs": [],
                          "utxos": utxos})
        chain[height] = (rng.randbytes(32).hex(), block)
    return chain, plan


class FakeBlindBit:
    def __init__(self, chain):
        self.chain = chain
        self.requests = []
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                fake.requests.append(self.path)
                parts = self.path.strip("/").split("/")
                if parts == ["info"]:
                    body = {"network": "main", "height": max(fake.chain), "tweaks_only": False,
                            "tweaks_full_basic": True}
                elif len(parts) == 2 and int(parts[1]) in fake.chain:
                    height = int(parts[1])
                    block_hash, txs = fake.chain[height]
                    ident = {"block_hash": block_hash, "block_height": height}
                    if parts[0] == "full-block":
                        body = {"block_identifier": ident, "index": txs}
                    elif parts[0] == "spent-outputs":
                        body = {"block_identifier": ident, "index": []}
                    else:
                        self.send_error(404)
                        return
                else:
                    self.send_error(404)
                    return
                data = json.dumps(body).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()


@unittest.skipUnless(native.available(), "libspscan not built")
class WebService(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        rng = random.Random(1352)
        cls.scan_secret = _key(rng)
        cls.spend = Point.from_secret(_key(rng))
        cls.address = encode_address(Point.from_secret(cls.scan_secret), cls.spend, "main")
        cls.chain_data, cls.plan = _make_chain(rng, cls.scan_secret, cls.spend)
        cls.fake = FakeBlindBit(cls.chain_data)
        cls.tmp = tempfile.TemporaryDirectory()
        cls.chain = web.Chain(web.BlindBit(cls.fake.url), web.BlockCache(Path(cls.tmp.name) / "c.sqlite"))
        cls.chain.tip = cls.chain.source.tip()
        cls.jobs = web.Jobs(cls.chain, None, workers=1, per_client=1)
        cls.jobs.start()
        cls.server = web.serve("127.0.0.1:0", cls.chain, cls.jobs, ROOT / "web")
        cls.url = f"http://127.0.0.1:{cls.server.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.fake.server.shutdown()
        cls.tmp.cleanup()

    def _get(self, path):
        with urllib.request.urlopen(self.url + path) as response:
            return response.status, response.headers, response.read()

    def _post(self, path, payload):
        request = urllib.request.Request(self.url + path, data=json.dumps(payload).encode(),
                                         headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def _expected(self, labels=()):
        """(height, label) of each expected payment output."""
        want = []
        for height, plan in self.plan.items():
            for label, count in plan:
                if label is None or label == 0 or label in labels:
                    want += [(height, label)] * count
        return sorted(want, key=lambda x: (x[0], -1 if x[1] is None else x[1]))

    def test_blocks_and_filters(self):
        status, headers, body = self._get(f"/v1/blocks?from={BASE}&count=1000")
        self.assertEqual(headers["Content-Type"], "application/octet-stream")
        self.assertEqual(body[:4], b"SPB1")
        count = int.from_bytes(body[4:8], "little")
        self.assertEqual(count, N_BLOCKS)
        receiver = native.Receiver(self.scan_secret, self.spend.serialize(), [3])
        at, hits = 8, []
        for _ in range(count):
            height = int.from_bytes(body[at:at + 4], "little")
            block_hash = body[at + 4:at + 36]
            n = int.from_bytes(body[at + 36:at + 40], "little")
            tweaks = body[at + 40:at + 40 + 33 * n]
            at += 40 + 33 * n
            flen = int.from_bytes(body[at:at + 4], "little")
            filt = body[at + 4:at + 4 + flen]
            at += 4 + flen
            self.assertEqual(block_hash, bytes.fromhex(self.chain_data[height][0])[::-1])
            if n and receiver.filter_check([tweaks[i:i + 33] for i in range(0, len(tweaks), 33)],
                                           filt, block_hash):
                hits.append(height)
            if height == BASE + 10:
                self.assertEqual(n, 0)
        self.assertEqual(at, len(body))
        self.assertTrue(set(self.plan) <= set(hits), hits)
        self.assertLessEqual(len(hits), len(self.plan) + 1)  # false positives are rare

    def test_bad_requests(self):
        for path in (f"/v1/blocks?from={BASE - 1}", "/v1/blocks?from=x", "/v1/outputs?heights=",
                     "/v1/outputs?heights=" + ",".join(str(BASE + i) for i in range(40))):
            with self.subTest(path), self.assertRaises(urllib.error.HTTPError) as ctx:
                self._get(path)
            self.assertEqual(ctx.exception.code, 400)

    def test_page_headers(self):
        status, headers, body = self._get("/")
        self.assertIn(b"Silent payments scanner", body)
        self.assertIn("script-src 'self' 'wasm-unsafe-eval'", headers["Content-Security-Policy"])
        if WASM.exists():
            status, headers, body = self._get("/spscan.wasm")
            self.assertEqual(headers["Content-Type"], "application/wasm")
            self.assertEqual(body[:4], b"\0asm")

    def test_server_job(self):
        status, body = self._post("/v1/jobs", {"address": self.address,
                                               "scan_key": f"{self.scan_secret:064x}",
                                               "from": BASE, "labels": [3]})
        self.assertEqual(status, 202, body)
        # one job per client at a time
        status, again = self._post("/v1/jobs", {"address": self.address,
                                                "scan_key": f"{self.scan_secret:064x}", "from": BASE})
        self.assertIn(status, (202, 429))
        for _ in range(200):
            job = json.loads(self._get(f"/v1/jobs/{body['id']}")[2])
            if job["status"] in ("done", "failed"):
                break
            time.sleep(0.05)
        self.assertEqual(job["status"], "done", job)
        self.assertEqual(job["progress"], 1)
        got = sorted(((p["height"], p["label"]) for p in job["payments"]),
                     key=lambda x: (x[0], -1 if x[1] is None else x[1]))
        self.assertEqual(got, self._expected([3]))
        for p in job["payments"]:
            txs = self.chain_data[p["height"]][1]
            tx = next(t for t in txs if t["txid"] == p["txid"])
            self.assertIn((p["vout"], p["amount"]), [(u["vout"], u["amount"]) for u in tx["utxos"]])
        request = urllib.request.Request(f"{self.url}/v1/jobs/{body['id']}", method="DELETE")
        urllib.request.urlopen(request).close()
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self._get(f"/v1/jobs/{body['id']}")
        self.assertEqual(ctx.exception.code, 404)
        if status == 202:
            self.jobs.delete(again["id"])

    def test_job_rejects_wrong_key(self):
        other = (self.scan_secret + 1).to_bytes(32, "big").hex()
        status, body = self._post("/v1/jobs", {"address": self.address, "scan_key": other, "from": BASE})
        self.assertEqual(status, 400)
        self.assertIn("does not belong", body["error"])
        status, body = self._post("/v1/jobs", {"address": self.address, "scan_key": "zz", "from": BASE})
        self.assertEqual(status, 400)
        status, body = self._post("/v1/jobs", {"address": "sp1qbad", "scan_key": other, "from": BASE})
        self.assertEqual(status, 400)

    @unittest.skipUnless(NODE and WASM.exists(), "needs node and spscan.wasm")
    def test_browser_scan(self):
        proc = subprocess.run([NODE, str(ROOT / "tests" / "web_scan.mjs"), self.url, self.address,
                               f"{self.scan_secret:064x}", str(BASE)],
                              capture_output=True, text=True, timeout=300)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        out = json.loads(proc.stdout)
        self.assertEqual(out["fetched"], N_BLOCKS)
        self.assertTrue(set(out["candidates"]) <= set(out["asked"]))
        self.assertGreaterEqual(len(out["asked"]), 4 * len(out["candidates"]))
        got = sorted(((p["height"], p["label"]) for p in out["payments"]),
                     key=lambda x: (x[0], -1 if x[1] is None else x[1]))
        self.assertEqual(got, self._expected())

    def test_sync_fills_cache(self):
        chain = web.Chain(web.BlindBit(self.fake.url),
                          web.BlockCache(Path(self.tmp.name) / "sync.sqlite"), workers=2)
        thread = threading.Thread(target=chain.run, daemon=True)
        thread.start()
        for _ in range(200):
            if chain.cache.count() == N_BLOCKS:
                break
            time.sleep(0.05)
        chain.stop.set()
        thread.join(30)
        self.assertEqual(chain.cache.count(), N_BLOCKS)
        # a reorg at the tip replaces the cached block
        tip = max(self.chain_data)
        old_hash, txs = self.chain_data[tip]
        self.chain_data[tip] = ("ab" * 32, txs)
        try:
            chain._check_recent()
            self.assertEqual(chain.cache.hash_at(tip), bytes.fromhex("ab" * 32)[::-1])
        finally:
            self.chain_data[tip] = (old_hash, txs)


if __name__ == "__main__":
    unittest.main()
