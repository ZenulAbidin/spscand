"""libspscan/spscan.wasm (run under Node.js) against the native library.

Skipped unless both are built (make -C libspscan all wasm) and node is on PATH.
"""

import json
import random
import shutil
import subprocess
import unittest
from pathlib import Path

from spscand import native
from spscand.bip352 import Receiver
from spscand.secp import Point

import test_native
from test_native import STRATEGIES, _key
from test_vectors import _cases, _inputs

ROOT = Path(__file__).resolve().parent.parent
WASM = ROOT / "libspscan" / "spscan.wasm"
RUNNER = ROOT / "libspscan" / "wasm" / "run.mjs"
NODE = shutil.which("node")


def _taproot_filter(block_hash: bytes, outputs) -> bytes:
    return native.gcs_build(block_hash, [b"\x51\x20" + x for x in outputs])


@unittest.skipUnless(native.available() and WASM.exists() and NODE,
                     "needs libspscan.so, spscan.wasm and node")
class WasmMatchesNative(unittest.TestCase):
    def _case(self, scan_secret, spend, labels, flags, tweaks, outputs, block_hash=None):
        case = {"scan_key": f"{scan_secret:064x}", "spend_pubkey": spend.hex(), "labels": labels,
                "flags": flags, "tweaks": b"".join(tweaks).hex(), "outputs": b"".join(outputs).hex()}
        handle = native.Receiver(scan_secret, spend, labels, flags)
        want = {"matches": [[t, o, None, lab, f"{tw:064x}"]
                            for t, o, tw, lab in handle.scan(tweaks, outputs)], "filter": None,
                "scanPubkey": Point.from_secret(scan_secret).serialize().hex()}
        if block_hash is not None:
            filt = _taproot_filter(block_hash, outputs)
            case.update(filter=filt.hex(), block_hash=block_hash.hex())
            want["filter"] = handle.filter_check(tweaks, filt, block_hash)
        return case, want

    def _run(self, cases):
        proc = subprocess.run([NODE, str(RUNNER)], input=json.dumps({"cases": cases}),
                              capture_output=True, text=True, timeout=600, check=True)
        out = json.loads(proc.stdout)
        self.assertEqual(out["version"], native.version())
        return out["results"]

    def _compare(self, cases, wants):
        for i, (got, want) in enumerate(zip(self._run(cases), wants, strict=True)):
            with self.subTest(case=i):
                # native.Receiver.scan does not return k; compare everything else
                self.assertEqual([[t, o, lab, tw] for t, o, _k, lab, tw in got["matches"]],
                                 [[t, o, lab, tw] for t, o, _k, lab, tw in want["matches"]])
                self.assertEqual(got["filter"], want["filter"])
                self.assertEqual(got["scanPubkey"], want["scanPubkey"])

    def test_receiving_vectors(self):
        cases, wants = [], []
        for _name, test in _cases():
            given = test["given"]
            tweak = native.tweak_from_inputs(_inputs(given["vin"]))
            if tweak is None:
                continue
            keys = given["key_material"]
            spend = Point.from_secret(int(keys["spend_priv_key"], 16)).serialize()
            outputs = [bytes.fromhex(o) for o in given["outputs"]]
            for flags in STRATEGIES.values():
                case, want = self._case(int(keys["scan_priv_key"], 16), spend, given["labels"],
                                        flags | native.NO_CHANGE_LABEL, [tweak], outputs,
                                        block_hash=bytes(range(32)))
                cases.append(case)
                wants.append(want)
        self.assertGreaterEqual(len(cases), 75)
        self.assertTrue(any(w["matches"] for w in wants))
        self._compare(cases, wants)

    def test_block_wide_and_filters(self):
        rng = random.Random(7352)
        cases, wants = [], []
        for labels in ([], [1], [1, 2, 3, 77], list(range(1, 200))):
            receiver = Receiver(_key(rng), Point.from_secret(_key(rng)), labels=labels)
            tweaks, outputs = test_native.NativeMatchesPython._block(None, rng, receiver)
            tweaks = [t.serialize() for t in tweaks]
            spend = receiver.spend_pubkey.serialize()
            for flags in STRATEGIES.values():
                case, want = self._case(receiver.scan_secret, spend, labels, flags, tweaks,
                                        outputs, block_hash=rng.randbytes(32))
                self.assertTrue(want["matches"] and want["filter"])
                cases.append(case)
                wants.append(want)
            # A block that does not pay this receiver: no matches, and the filter says no.
            stranger = [o for o in outputs if not any(
                outputs[m[1]] == o for m in want["matches"])]
            case, want = self._case(receiver.scan_secret, spend, labels, 0, tweaks[:20],
                                    stranger, block_hash=rng.randbytes(32))
            cases.append(case)
            wants.append(want)
        self._compare(cases, wants)


if __name__ == "__main__":
    unittest.main()
