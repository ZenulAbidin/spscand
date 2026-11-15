"""The local JSON API: authentication and responses."""

import json
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from spscand import __version__
from spscand.api import State, serve
from spscand.store import Output, Store


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


if __name__ == "__main__":
    unittest.main()
