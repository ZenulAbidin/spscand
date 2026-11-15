"""spscand.toml: the [mempool] section."""

import tempfile
import unittest
from pathlib import Path

from spscand.backends import BlindBitBackend, CoreBackend
from spscand.config import Config


class MempoolConfigTest(unittest.TestCase):
    def load(self, text):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "spscand.toml"
            path.write_text(text)
            return Config.load(path)

    def test_defaults(self):
        config = self.load("")
        self.assertEqual(config.mempool_source, "auto")
        self.assertEqual(config.mempool_poll_seconds, 5)

    def test_auto_follows_the_backend(self):
        config = self.load('[backend]\ntype = "core"\n')
        backend = config.make_backend()
        self.assertIs(config.make_mempool_source(backend), backend)
        config = self.load('[backend]\ntype = "blindbit"\n')
        self.assertIsNone(config.make_mempool_source(config.make_backend()))

    def test_core_beside_blindbit(self):
        config = self.load('[backend]\ntype = "blindbit"\nproxy = "socks5h://127.0.0.1:9050"\n'
                           'rpc_url = "http://127.0.0.1:18443"\n[mempool]\nsource = "core"\n')
        backend = config.make_backend()
        self.assertIsInstance(backend, BlindBitBackend)
        core = config.make_mempool_source(backend)
        self.assertIsInstance(core, CoreBackend)
        self.assertEqual(core.url, "http://127.0.0.1:18443")
        # The Tor proxy is for BlindBit; the local node is reached directly.
        self.assertFalse(any(type(h).__module__ == "spscand.socks"
                             for h in core.http.opener.handlers))
        tor = config.make_backend()
        self.assertTrue(any(type(h).__module__ == "spscand.socks"
                            for h in tor.http.opener.handlers))

    def test_off(self):
        config = self.load('[backend]\ntype = "core"\n[mempool]\nsource = "off"\n')
        self.assertIsNone(config.make_mempool_source(config.make_backend()))

    def test_invalid(self):
        with self.assertRaisesRegex(ValueError, "source"):
            self.load('[mempool]\nsource = "blindbit"\n')
        with self.assertRaisesRegex(ValueError, "positive"):
            self.load('[mempool]\npoll_seconds = 0\n')


if __name__ == "__main__":
    unittest.main()
