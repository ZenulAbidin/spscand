"""The local JSON API: authentication and responses."""

import json
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from spscand import __version__
from spscand.api import State, serve
from spscand.store import MempoolOutput, Output, Store


class ApiTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "wallet.sqlite"
        self.store = Store(self.db_path, create=True)
        self.state = State("regtest", "core", [{"label": None, "address": "sprt1example"}])
        self.servers = []

    def tearDown(self):
        for server in self.servers:
            server.shutdown()
            server.server_close()
        self.store.close()
        self.tmp.cleanup()

    def serve(self, token=""):
        server = serve("127.0.0.1:0", self.db_path, self.state, token)
        self.servers.append(server)
        return f"http://127.0.0.1:{server.server_address[1]}"

    def post(self, url, body, token=None):
        request = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST")
        if token is not None:
            request.add_header("Authorization", f"Bearer {token}")
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as exc:
            return exc.code, json.load(exc)

    def get(self, url, token=None):
        request = urllib.request.Request(url)
        if token is not None:
            request.add_header("Authorization", f"Bearer {token}")
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as exc:
            return exc.code, json.load(exc)

    def test_tokenless_api_only_on_loopback(self):
        for listen in ("0.0.0.0:0", "[::]:0", "192.0.2.1:0"):
            with self.subTest(listen=listen), self.assertRaisesRegex(ValueError, "needs a token"):
                serve(listen, self.db_path, self.state, "")

    def test_token_is_checked(self):
        base = self.serve(token="s3cret")
        self.assertEqual(self.get(f"{base}/v1/status")[0], 401)
        self.assertEqual(self.get(f"{base}/v1/status", token="wrong")[0], 401)
        status, body = self.get(f"{base}/v1/status", token="s3cret")
        self.assertEqual(status, 200)
        self.assertEqual(body["network"], "regtest")

    def test_status_reports_version(self):
        status, body = self.get(f"{self.serve()}/v1/status")
        self.assertEqual(status, 200)
        self.assertEqual(body["version"], __version__)
        self.assertIsNone(body["scanned_height"])

    def test_outputs_since_height(self):
        def output(txid, height, spent_height=None):
            return Output(txid=txid * 64, vout=0, amount=1000, pubkey="ab" * 32,
                          tweak="cd" * 32, label=None, height=height, block_hash="00" * 32,
                          spent_txid=None, spent_height=spent_height)

        with self.store.transaction():
            self.store.add_output(output("a", 5))
            self.store.add_output(output("b", 5, spent_height=12))
            self.store.add_output(output("c", 10))
            self.store.record_block(12, "11" * 32)
        base = self.serve()

        def txids(query):
            status, body = self.get(f"{base}/v1/outputs?{query}")
            self.assertEqual(status, 200)
            return [row["txid"][0] for row in body]

        self.assertEqual(txids(""), ["a", "b", "c"])
        self.assertEqual(txids("since_height=10"), ["b", "c"])
        self.assertEqual(txids("since_height=13"), [])
        self.assertEqual(txids("since_height=10&unspent=1"), ["c"])
        self.assertEqual(self.get(f"{base}/v1/outputs?since_height=-1")[0], 400)
        self.assertEqual(self.get(f"{base}/v1/outputs?since_height=x")[0], 400)

    def test_unconfirmed_outputs_and_pending_balance(self):
        ours = Output(txid="a" * 64, vout=0, amount=1000, pubkey="ab" * 32, tweak="cd" * 32,
                      label=None, height=5, block_hash="00" * 32, spent_txid=None,
                      spent_height=None)
        incoming = MempoolOutput(txid="b" * 64, vout=1, amount=250, pubkey="ef" * 32,
                                 tweak="12" * 32, label=3)
        with self.store.transaction():
            self.store.add_output(ours)
            self.store.record_block(6, "11" * 32)
            self.store.add_mempool_tx("b" * 64, [("c" * 64, 0)], 1, [incoming], [])
            self.store.add_mempool_tx("d" * 64, [("a" * 64, 0)], 1, [], [("a" * 64, 0)])
        base = self.serve()

        status, rows = self.get(f"{base}/v1/outputs")
        self.assertEqual(status, 200)
        by_txid = {row["txid"][0]: row for row in rows}
        self.assertEqual(by_txid["a"]["status"], "confirmed")
        self.assertEqual(by_txid["a"]["confirmations"], 2)
        self.assertEqual(by_txid["a"]["pending_spent_txid"], "d" * 64)
        self.assertEqual(by_txid["b"]["status"], "unconfirmed")
        self.assertEqual(by_txid["b"]["confirmations"], 0)
        self.assertIsNone(by_txid["b"]["height"])
        self.assertEqual(by_txid["b"]["label"], 3)
        self.assertIsNone(by_txid["b"]["pending_spent_txid"])
        # Unconfirmed outputs are always new.
        _, rows = self.get(f"{base}/v1/outputs?since_height=100")
        self.assertEqual([row["txid"][0] for row in rows], ["b"])

        _, balance = self.get(f"{base}/v1/balance")
        self.assertEqual(balance["balance"], 1000)
        self.assertEqual(balance["outputs"], 1)
        self.assertEqual(balance["pending_in"], 250)
        self.assertEqual(balance["pending_out"], 1000)
        _, balance = self.get(f"{base}/v1/balance?min_conf=0")
        self.assertEqual(balance["balance"], 1000)

        _, status_body = self.get(f"{base}/v1/status")
        self.assertIsNone(status_body["mempool"])
        self.state.mempool = {"source": "core", "transactions": 12, "error": None}
        _, status_body = self.get(f"{base}/v1/status")
        self.assertEqual(status_body["mempool"]["transactions"], 12)


    def test_changes_need_a_token(self):
        base = self.serve()
        status, body = self.post(f"{base}/v1/labels", {"comment": "shop"})
        self.assertEqual(status, 403)
        base = self.serve(token="s3cret")
        self.assertEqual(self.post(f"{base}/v1/labels", {}, token="wrong")[0], 401)
        self.assertEqual(self.store.labels(), {})

    def test_add_labels(self):
        self.state.address_for = lambda m: f"sprt1label{m}"
        base = self.serve(token="s3cret")
        status, body = self.post(f"{base}/v1/labels", {"comment": "shop"}, token="s3cret")
        self.assertEqual((status, body), (200, {"label": 1, "comment": "shop",
                                                "address": "sprt1label1"}))
        status, body = self.post(f"{base}/v1/labels", {}, token="s3cret")
        self.assertEqual(body["label"], 2)
        status, body = self.post(f"{base}/v1/labels", {"m": 7, "comment": "x"}, token="s3cret")
        self.assertEqual(body["label"], 7)
        status, body = self.post(f"{base}/v1/labels", {"m": 1, "comment": "café"},
                                 token="s3cret")
        self.assertEqual(self.store.labels(), {1: "café", 2: "", 7: "x"})
        _, addresses = self.get(f"{base}/v1/addresses", token="s3cret")
        self.assertEqual(sorted(a["label"] for a in addresses if a["label"]), [1, 2, 7])
        for bad in ({"m": 0}, {"m": -1}, {"m": True}, {"m": "1"}, {"comment": 5},
                    {"comment": "x" * 201}):
            with self.subTest(bad):
                self.assertEqual(self.post(f"{base}/v1/labels", bad, token="s3cret")[0], 400)
        self.assertEqual(self.post(f"{base}/v1/nothing", {}, token="s3cret")[0], 404)


if __name__ == "__main__":
    unittest.main()
