"""spscand pair: the pairing string and the API token it sets up."""

import contextlib
import io
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest import mock
from urllib.parse import parse_qs, urlsplit

from spscand.bip352 import Receiver
from spscand.cli import main
from spscand.secp import Point

SCAN, SPEND = 0x1111, 0x2222


class PairTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.datadir = Path(self.tmp.name) / "spscand"
        self.address = Receiver(SCAN, Point.from_secret(SPEND)).address("regtest")
        self.run_cli("init", "--network", "regtest", "--address", self.address,
                     "--birthday", "100", stdin=f"{SCAN:064x}\n")

    def tearDown(self):
        self.tmp.cleanup()

    def run_cli(self, *argv, stdin=""):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(sys, "stdin", io.StringIO(stdin)), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            main(["--datadir", str(self.datadir), *argv])
        return out.getvalue(), err.getvalue()

    def config(self):
        return tomllib.loads((self.datadir / "spscand.toml").read_text())

    def pair(self, *argv):
        out, err = self.run_cli("pair", *argv)
        parts = urlsplit(out.strip())
        self.assertEqual((parts.scheme, parts.netloc), ("spscand", "pair"))
        return {k: v[0] for k, v in parse_qs(parts.query).items()}, err

    def test_sets_a_token_once(self):
        self.assertEqual(self.config()["api"]["token"], "")
        fields, err = self.pair()
        self.assertIn("restart", err)
        token = self.config()["api"]["token"]
        self.assertEqual(len(token), 32)
        self.assertEqual(fields, {"url": "http://127.0.0.1:7352", "token": token,
                                  "network": "regtest", "address": self.address})
        # Everything else in the file is kept.
        self.assertEqual(self.config()["api"]["listen"], "127.0.0.1:7352")
        self.assertEqual(self.config()["backend"]["type"], "core")
        self.assertEqual((self.datadir / "spscand.toml").stat().st_mode & 0o777, 0o600)
        fields, err = self.pair("--url", "http://" + "a" * 56 + ".onion:7352")
        self.assertEqual(fields["token"], token)
        self.assertEqual(err, "")
        self.assertTrue(fields["url"].endswith(".onion:7352"))

    def test_listening_beyond_loopback_needs_the_url(self):
        path = self.datadir / "spscand.toml"
        path.write_text(path.read_text().replace('listen = "127.0.0.1:7352"',
                                                 'listen = "0.0.0.0:7352"'))
        with self.assertRaisesRegex(SystemExit, "--url"):
            self.pair()

    def test_config_without_api_section(self):
        path = self.datadir / "spscand.toml"
        text = path.read_text()
        path.write_text(text[:text.index("[api]")])
        fields, _ = self.pair()
        self.assertEqual(self.config()["api"]["token"], fields["token"])


if __name__ == "__main__":
    unittest.main()
