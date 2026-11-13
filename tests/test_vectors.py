"""Run every BIP352 receiving test vector against spscand.bip352."""

import json
import unittest
from io import BytesIO
from pathlib import Path

from unittest import mock

from spscand import bip352
from spscand.bip352 import Receiver, TxInput, tweak_point
from spscand.secp import N, Point

VECTORS = Path(__file__).parent / "reference" / "send_and_receive_test_vectors.json"


def _witness(hex_stack: str) -> tuple[bytes, ...]:
    if not hex_stack:
        return ()
    stream = BytesIO(bytes.fromhex(hex_stack))

    def compact() -> int:
        first = stream.read(1)[0]
        if first < 0xFD:
            return first
        return int.from_bytes(stream.read({0xFD: 2, 0xFE: 4, 0xFF: 8}[first]), "little")

    return tuple(stream.read(compact()) for _ in range(compact()))


def _inputs(vin) -> list[TxInput]:
    return [
        TxInput(
            txid=i["txid"],
            vout=i["vout"],
            script_sig=bytes.fromhex(i["scriptSig"]),
            witness=_witness(i["txinwitness"]),
            prevout_script=bytes.fromhex(i["prevout"]["scriptPubKey"]["hex"]),
        )
        for i in vin
    ]


def _cases():
    for case in json.loads(VECTORS.read_text()):
        for index, test in enumerate(case["receiving"]):
            yield f"{case['comment']} [{index}]", test


class ReceivingVectors(unittest.TestCase):
    def test_all_receiving_vectors(self):
        # Run once with each label-matching strategy forced.
        for ratio in (0, 10**9):
            with mock.patch.object(bip352, "LABEL_ADDITION_RATIO", ratio):
                count = 0
                for name, test in _cases():
                    with self.subTest(name, ratio=ratio):
                        self._check(test["given"], test["expected"])
                        count += 1
                self.assertGreaterEqual(count, 29)

    def test_change_label_does_not_add_matches(self):
        for name, test in _cases():
            given, expected = test["given"], test["expected"]
            tweak = tweak_point(_inputs(given["vin"]))
            if tweak is None or 0 in given["labels"]:
                continue
            keys = given["key_material"]
            receiver = Receiver(int(keys["scan_priv_key"], 16),
                                Point.from_secret(int(keys["spend_priv_key"], 16)),
                                labels=given["labels"])
            found = receiver.scan(tweak, [bytes.fromhex(o) for o in given["outputs"]])
            with self.subTest(name):
                self.assertEqual(len(found), expected.get("n_outputs", len(expected.get("outputs", []))))

    def _check(self, given, expected):
        keys = given["key_material"]
        scan_secret = int(keys["scan_priv_key"], 16)
        spend_secret = int(keys["spend_priv_key"], 16)
        # The vectors list exactly the labels to check, so the implicit change
        # label is disabled here; the daemon always enables it.
        receiver = Receiver(
            scan_secret,
            Point.from_secret(spend_secret),
            labels=given["labels"],
            check_change_label=False,
        )
        addresses = [receiver.address("main")] + [
            receiver.address("main", m) for m in given["labels"]
        ]
        self.assertEqual(sorted(addresses), sorted(expected["addresses"]))

        tweak = tweak_point(_inputs(given["vin"]))
        if expected.get("tweak") is None:
            self.assertIsNone(tweak)
            self.assertEqual(expected.get("outputs", []), [])
            return
        self.assertEqual(tweak.serialize().hex(), expected["tweak"])
        self.assertEqual(
            tweak.mul(scan_secret).serialize().hex(), expected["shared_secret"]
        )

        outputs = [bytes.fromhex(o) for o in given["outputs"]]
        found = receiver.scan(tweak, outputs)
        if "n_outputs" in expected:
            self.assertEqual(len(found), expected["n_outputs"])
        if expected.get("outputs"):
            got = sorted((f.xonly.hex(), f"{f.tweak:064x}") for f in found)
            want = sorted((o["pub_key"], o["priv_key_tweak"]) for o in expected["outputs"])
            self.assertEqual(got, want)
        elif "n_outputs" not in expected:
            self.assertEqual(found, [])
        for f in found:
            # The tweak must yield the output's key from the spend secret.
            self.assertEqual(
                Point.from_secret((spend_secret + f.tweak) % N).xonly(), f.xonly
            )
            self.assertEqual(outputs[f.index], f.xonly)


if __name__ == "__main__":
    unittest.main()
