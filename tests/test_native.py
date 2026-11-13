"""libspscan against the BIP352 vectors and against the Python implementation."""

import gzip
import json
import random
import secrets
import unittest
from pathlib import Path

from spscand import native
from spscand.bip352 import Receiver, TxInput, label_tweak, tagged_hash, tweak_point_py
from spscand.secp import N, Point

from test_vectors import _cases, _inputs

FIXTURES = Path(__file__).parent / "fixtures"
STRATEGIES = {"auto": 0, "addition": native.LABELS_BY_ADDITION,
              "subtraction": native.LABELS_BY_SUBTRACTION}


def _key(rng) -> int:
    return rng.randrange(1, N)


def _pay(rng, scan_secret, spend, label=None, count=1):
    """A tweak and `count` output keys paying (scan_secret, spend[, label])."""
    tweak = Point.from_secret(_key(rng))
    secret = tweak.mul(scan_secret).serialize()
    if label is not None:
        spend = spend.add_generator(label_tweak(scan_secret, label))
    keys = []
    for k in range(count):
        t_k = int.from_bytes(tagged_hash("BIP0352/SharedSecret", secret + k.to_bytes(4, "big")), "big")
        keys.append(spend.add_generator(t_k).xonly())
    return tweak, keys


@unittest.skipUnless(native.available(), "libspscan not built (make -C libspscan)")
class NativeVectors(unittest.TestCase):
    def test_receiving_vectors(self):
        count = 0
        for name, test in _cases():
            given, expected = test["given"], test["expected"]
            inputs = _inputs(given["vin"])
            tweak = native.tweak_from_inputs(inputs)
            py = tweak_point_py(inputs)
            with self.subTest(name):
                self.assertEqual(tweak, None if py is None else py.serialize())
                self.assertEqual(tweak and tweak.hex(), expected.get("tweak"))
            if tweak is None:
                continue
            keys = given["key_material"]
            scan_secret = int(keys["scan_priv_key"], 16)
            spend = Point.from_secret(int(keys["spend_priv_key"], 16))
            outputs = [bytes.fromhex(o) for o in given["outputs"]]
            for strategy, flags in STRATEGIES.items():
                receiver = native.Receiver(scan_secret, spend.serialize(), given["labels"],
                                           flags | native.NO_CHANGE_LABEL)
                found = receiver.scan([tweak], outputs)
                with self.subTest(name, strategy=strategy):
                    if "n_outputs" in expected:
                        self.assertEqual(len(found), expected["n_outputs"])
                    got = sorted((outputs[o].hex(), f"{t:064x}") for _, o, t, _ in found)
                    want = sorted((o["pub_key"], o["priv_key_tweak"])
                                  for o in expected.get("outputs", []))
                    if want or "n_outputs" not in expected:
                        self.assertEqual(got, want)
            count += 1
        self.assertGreaterEqual(count, 25)

    def test_mainnet_tweaks(self):
        block = json.loads(gzip.decompress((FIXTURES / "block-833044.json.gz").read_bytes()))
        compared = 0
        for tx in block["txs"]:
            if not tx["vin"]:
                continue
            inputs = [TxInput(txid, vout, bytes.fromhex(sig), tuple(bytes.fromhex(w) for w in wit),
                              bytes.fromhex(spk))
                      for txid, vout, sig, wit, spk in tx["vin"]]
            py = tweak_point_py(inputs)
            self.assertEqual(native.tweak_from_inputs(inputs), py and py.serialize(), tx["txid"])
            compared += 1
        self.assertGreater(compared, 2500)


@unittest.skipUnless(native.available(), "libspscan not built (make -C libspscan)")
class NativeMatchesPython(unittest.TestCase):
    """A block-wide group with payments, labels, several k and key reuse."""

    def _block(self, rng, receiver, n_strangers=150):
        tweaks, outputs = [], []
        for _ in range(n_strangers):
            tweak, keys = _pay(rng, _key(rng), Point.from_secret(_key(rng)), count=2)
            tweaks.append(tweak)
            outputs += keys
        labels = list(receiver.labels) + [None]
        for i in range(12):
            tweak, keys = _pay(rng, receiver.scan_secret, receiver.spend_pubkey,
                               label=rng.choice(labels), count=rng.choice([1, 1, 2, 3]))
            tweaks.append(tweak)
            outputs += keys
            if i == 3:
                outputs.append(keys[0])  # the same key paid twice
        outputs += [Point.from_secret(_key(rng)).xonly() for _ in range(100)]
        outputs.append(b"\xff" * 32)  # not a valid x coordinate
        rng.shuffle(tweaks)
        rng.shuffle(outputs)
        return tweaks, outputs

    def _python(self, receiver, tweaks, outputs):
        receiver._native, saved = None, receiver._native
        try:
            return receiver.scan_group(tweaks, outputs)
        finally:
            receiver._native = saved

    def test_block_wide(self):
        rng = random.Random(352)
        for labels in ([], [1], [1, 2, 3, 77], list(range(1, 400))):
            receiver = Receiver(_key(rng), Point.from_secret(_key(rng)), labels=labels)
            tweaks, outputs = self._block(rng, receiver)
            want = self._python(receiver, tweaks, outputs)
            self.assertGreaterEqual(len(want), 12)
            for strategy, flags in STRATEGIES.items():
                handle = native.Receiver(receiver.scan_secret, receiver.spend_pubkey.serialize(),
                                         labels, flags)
                got = handle.scan([t.serialize() for t in tweaks], outputs)
                with self.subTest(labels=len(labels), strategy=strategy):
                    self.assertEqual([(t, o, tw, lab) for t, o, tw, lab in got],
                                     [(t, f.index, f.tweak, f.label) for t, f in want])
            self.assertEqual(receiver.scan_group(tweaks, outputs), want)

    def test_label_equal_to_output_key(self):
        # Choose the spend key so that P_0 equals the label-1 point L: then
        # P_0 + L is a doubling, which the batch formulas cannot compute.
        rng = random.Random(7)
        scan_secret = _key(rng)
        tweak = Point.from_secret(_key(rng))
        secret = tweak.mul(scan_secret).serialize()
        t_0 = int.from_bytes(tagged_hash("BIP0352/SharedSecret", secret + bytes(4)), "big")
        spend = Point.from_secret((label_tweak(scan_secret, 1) - t_0) % N)
        doubled = Point.from_secret(2 * label_tweak(scan_secret, 1) % N).xonly()
        outputs = [Point.from_secret(_key(rng)).xonly(), doubled]
        receiver = Receiver(scan_secret, spend, labels=[1])
        want = self._python(receiver, [tweak], outputs)
        self.assertEqual([(f.index, f.label) for _, f in want], [(1, 1)])
        for strategy, flags in STRATEGIES.items():
            handle = native.Receiver(scan_secret, spend.serialize(), [1], flags)
            with self.subTest(strategy=strategy):
                self.assertEqual(handle.scan([tweak.serialize()], outputs),
                                 [(0, f.index, f.tweak, f.label) for _, f in want])

    def test_many_matches_grow_the_buffer(self):
        rng = random.Random(3)
        receiver = Receiver(_key(rng), Point.from_secret(_key(rng)))
        tweak, keys = _pay(rng, receiver.scan_secret, receiver.spend_pubkey, count=40)
        found = receiver.scan_group([tweak], keys)
        self.assertEqual(sorted(f.index for _, f in found), list(range(40)))

    def test_bad_input_is_an_error(self):
        receiver = native.Receiver(5, Point.from_secret(7).serialize())
        with self.assertRaises(native.NativeError):
            receiver.scan([b"\x02" + b"\xff" * 32], [bytes(32)])
        with self.assertRaises(native.NativeError):
            native.Receiver(0, Point.from_secret(7).serialize())
        with self.assertRaises(native.NativeError):
            native.Receiver(5, b"\x05" + bytes(32))


if __name__ == "__main__":
    unittest.main()
