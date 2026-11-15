"""The local JSON API: authentication and responses."""

import json
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from spscand.api import State, serve
from spscand.store import Store


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


if __name__ == "__main__":
    unittest.main()
