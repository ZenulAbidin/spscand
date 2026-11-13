"""Cross-check against a real BlindBit Oracle v2 index of mainnet block 833044.

tweaks-833044.json and utxos-833044.json are BlindBit's /tweaks and /utxos
responses for the block; block-833044.json.gz is the same block's transactions
with prevouts (from mempool.space). spscand must derive exactly BlindBit's
tweak set from the raw data, which exercises the input rules on real traffic.
"""

import gzip
import json
import unittest
from pathlib import Path

from spscand.bip352 import TxInput, tweak_point

FIXTURES = Path(__file__).parent / "fixtures"


def _load(name):
    return json.loads((FIXTURES / name).read_text())


class MainnetBlindBit(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.block = json.loads(gzip.decompress((FIXTURES / "block-833044.json.gz").read_bytes()))
        cls.tweaks = _load("tweaks-833044.json")
        cls.utxos = _load("utxos-833044.json")
        cls.ours = {}
        for tx in cls.block["txs"]:
            taproot = [(n, value, spk[4:]) for n, (spk, value) in enumerate(tx["vout"])
                       if len(spk) == 68 and spk.startswith("5120")]
            if not tx["vin"] or not taproot:
                continue
            inputs = [TxInput(txid, vout, bytes.fromhex(sig), tuple(bytes.fromhex(w) for w in wit),
                              bytes.fromhex(spk))
                      for txid, vout, sig, wit, spk in tx["vin"]]
            tweak = tweak_point(inputs)
            if tweak is not None:
                cls.ours[tx["txid"]] = (tweak.serialize().hex(), taproot)

    def test_same_block(self):
        for body in (self.tweaks, self.utxos):
            self.assertEqual(body["block_identifier"]["block_hash"], self.block["hash"])

    def test_tweaks_match_blindbit(self):
        theirs = sorted(self.tweaks["index"])
        ours = sorted(tweak for tweak, _ in self.ours.values())
        self.assertEqual(len(theirs), 721)
        self.assertEqual(ours, theirs)

    def test_outputs_match_blindbit(self):
        theirs = sorted((u["txid"], u["vout"], u["amount"], u["pubkey"]) for u in self.utxos["index"])
        ours = sorted((txid, n, value, key) for txid, (_, outputs) in self.ours.items()
                      for n, value, key in outputs)
        self.assertEqual(ours, theirs)


if __name__ == "__main__":
    unittest.main()
