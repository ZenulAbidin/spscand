"""Reading one transaction in Core's verbose JSON into a scan group."""

import json
import unittest
from decimal import Decimal
from io import BytesIO

from spscand.backends import scan_group
from spscand.bip352 import tweak_point

from tests.test_vectors import VECTORS, _inputs


def _witness_items(hex_stack: str) -> list[str]:
    if not hex_stack:
        return []
    stream = BytesIO(bytes.fromhex(hex_stack))

    def compact() -> int:
        first = stream.read(1)[0]
        if first < 0xFD:
            return first
        return int.from_bytes(stream.read({0xFD: 2, 0xFE: 4, 0xFF: 8}[first]), "little")

    return [stream.read(compact()).hex() for _ in range(compact())]


def core_tx(given: dict, txid: str = "11" * 32) -> dict:
    """A vector's transaction as getrawtransaction verbosity 2 would show it."""
    vin = []
    for i in given["vin"]:
        entry = {"txid": i["txid"], "vout": i["vout"],
                 "scriptSig": {"hex": i["scriptSig"]},
                 "prevout": {"scriptPubKey": {"hex": i["prevout"]["scriptPubKey"]["hex"]}}}
        witness = _witness_items(i["txinwitness"])
        if witness:
            entry["txinwitness"] = witness
        vin.append(entry)
    vout = [{"n": n, "value": Decimal("0.00010000"), "scriptPubKey": {"hex": "5120" + key}}
            for n, key in enumerate(given["outputs"])]
    vout.append({"n": len(vout), "value": Decimal("0.5"),
                 "scriptPubKey": {"hex": "0014" + "22" * 20}})
    return {"txid": txid, "vin": vin, "vout": vout}


class CoreTxTest(unittest.TestCase):
    def test_matches_tweak_of_every_vector(self):
        count = 0
        for case in json.loads(VECTORS.read_text()):
            for test in case["receiving"]:
                given = test["given"]
                if not given["outputs"]:
                    continue
                tx = core_tx(given)
                expected = tweak_point(_inputs(given["vin"]))
                group = scan_group(tx)
                with self.subTest(case["comment"]):
                    if expected is None:
                        self.assertIsNone(group)
                        continue
                    self.assertEqual(group.tweaks, [expected])
                    self.assertEqual([o.key.hex() for o in group.outputs], given["outputs"])
                    self.assertEqual({o.amount for o in group.outputs}, {10_000})
                    count += 1
        self.assertGreater(count, 20)

    def test_no_taproot_output(self):
        tx = {"txid": "11" * 32, "vin": [],
              "vout": [{"n": 0, "value": 1, "scriptPubKey": {"hex": "0014" + "22" * 20}}]}
        self.assertIsNone(scan_group(tx))

    def test_missing_prevout(self):
        case = json.loads(VECTORS.read_text())[0]["receiving"][0]["given"]
        tx = core_tx(case)
        del tx["vin"][0]["prevout"]
        with self.assertRaises(KeyError):
            scan_group(tx)


if __name__ == "__main__":
    unittest.main()
