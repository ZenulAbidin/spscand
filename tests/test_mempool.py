"""The mempool watcher against a fake Bitcoin Core node."""

import copy
import json
import tempfile
import unittest
from pathlib import Path

from spscand.backends import BackendError
from spscand.bip352 import Receiver
from spscand.mempool import MempoolWatcher
from spscand.secp import Point
from spscand.store import Output, Store

from tests.test_core_tx import core_tx
from tests.test_vectors import VECTORS


class FakeCore:
    def __init__(self):
        self.mempool: dict[str, dict] = {}
        self.coins: dict[tuple[str, int], str] = {}  # confirmed outpoint -> script hex
        self.spenders: dict[tuple[str, int], str] = {}  # mempool spends
        self.blocks: list[tuple[str, list[str]]] = []  # (hash, txids) by height

    def call(self, method, *params):
        if method == "getrawmempool":
            return list(self.mempool)
        if method == "getrawtransaction":
            if params[0] not in self.mempool:
                raise BackendError("getrawtransaction: No such mempool transaction")
            return copy.deepcopy(self.mempool[params[0]])
        if method == "gettxout":
            script = self.coins.get((params[0], params[1]))
            return {"scriptPubKey": {"hex": script}} if script else None
        if method == "getblockcount":
            return len(self.blocks) - 1
        if method == "getblockhash":
            return self.blocks[params[0]][0]
        if method == "getblock":
            return {"tx": next(txids for h, txids in self.blocks if h == params[0])}
        if method == "gettxspendingprevout":
            result = []
            for item in params[0]:
                entry = dict(item)
                spender = self.spenders.get((item["txid"], item["vout"]))
                if spender:
                    entry["spendingtxid"] = spender
                result.append(entry)
            return result
        raise AssertionError(method)

    def call_many(self, method, params):
        results = []
        for p in params:
            try:
                results.append(self.call(method, *p))
            except BackendError:
                results.append(None)
        return results


class FakeScanner:
    def __init__(self, store, receiver):
        self.store, self.receiver, self.tip = store, receiver, 10
        self.events = []

    def emit(self, event, data):
        self.events.append((event, data))


def _vector():
    """The first receiving vector that pays two outputs, as a mempool transaction."""
    for case in json.loads(VECTORS.read_text()):
        for test in case["receiving"]:
            given, expected = test["given"], test["expected"]
            if len(expected.get("outputs", [])) >= 1 and not given["labels"]:
                return given, expected
    raise AssertionError("no vector")


class MempoolWatcherTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name) / "wallet.sqlite", create=True)
        with self.store.transaction():
            self.store.record_block(10, "aa" * 32)
        given, self.expected = _vector()
        keys = given["key_material"]
        receiver = Receiver(int(keys["scan_priv_key"], 16),
                            Point.from_secret(int(keys["spend_priv_key"], 16)))
        self.scanner = FakeScanner(self.store, receiver)
        self.core = FakeCore()
        self.core.blocks = [(f"{h:064x}", []) for h in range(11)]
        self.tx = core_tx(given, txid="f1" * 32)
        for vin in self.tx["vin"]:
            self.core.coins[(vin["txid"], vin["vout"])] = vin.pop("prevout")["scriptPubKey"]["hex"]
        self.watcher = MempoolWatcher(self.core, self.scanner)

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def events(self, name):
        return [data for event, data in self.scanner.events if event == name]

    def arrive(self):
        self.core.mempool[self.tx["txid"]] = self.tx
        self.watcher.poll()

    def test_arrival(self):
        self.arrive()
        found = self.store.mempool_outputs()
        self.assertEqual(sorted(o.pubkey for o in found),
                         sorted(o["pub_key"] for o in self.expected["outputs"]))
        self.assertEqual(sorted(o.tweak for o in found),
                         sorted(o["priv_key_tweak"] for o in self.expected["outputs"]))
        self.assertEqual(len(self.events("output.unconfirmed")), len(found))
        self.assertTrue(all(e["confirmations"] == 0 for e in self.events("output.unconfirmed")))
        # Seen again on the next poll: nothing new.
        self.watcher.poll()
        self.assertEqual(len(self.events("output.unconfirmed")), len(found))

    def test_missing_prevout_is_retried(self):
        first = (self.tx["vin"][0]["txid"], self.tx["vin"][0]["vout"])
        script = self.core.coins.pop(first)
        self.arrive()
        self.assertEqual(self.store.mempool_outputs(), [])
        self.core.coins[first] = script
        self.watcher.poll()
        self.assertTrue(self.store.mempool_outputs())

    def leave(self):
        del self.core.mempool[self.tx["txid"]]
        self.watcher.poll()
        return [e["reason"] for e in self.events("output.removed")]

    def test_replaced(self):
        self.arrive()
        vin = self.tx["vin"][0]
        self.core.spenders[(vin["txid"], vin["vout"])] = "f2" * 32
        reasons = self.leave()
        self.assertTrue(reasons)
        self.assertEqual(set(reasons), {"replaced"})
        self.assertEqual(self.store.mempool_outputs(), [])
        self.assertEqual(self.store.mempool_txids(), set())

    def test_evicted(self):
        self.arrive()
        self.assertEqual(set(self.leave()), {"evicted"})

    def test_conflicted(self):
        self.arrive()
        vin = self.tx["vin"][0]
        del self.core.coins[(vin["txid"], vin["vout"])]  # spent by a block
        self.assertEqual(set(self.leave()), {"conflicted"})

    def test_mined_before_the_block_scan(self):
        self.arrive()
        count = len(self.store.mempool_outputs())
        self.core.blocks.append(("bb" * 32, [self.tx["txid"]]))
        self.assertEqual(self.leave(), [])
        self.assertEqual(len(self.store.mempool_outputs()), count)
        # The block scan finds the outputs and drops the mempool rows.
        with self.store.transaction():
            for o in self.store.mempool_outputs():
                self.store.add_output(Output(o.txid, o.vout, o.amount, o.pubkey, o.tweak,
                                             o.label, 11, "bb" * 32, None, None))
            self.store.record_block(11, "bb" * 32)
            self.store.drop_confirmed_mempool()
        self.assertEqual(self.store.mempool_txids(), set())

    def test_restart_forgets_what_left_meanwhile(self):
        self.arrive()
        del self.core.mempool[self.tx["txid"]]
        watcher = MempoolWatcher(self.core, self.scanner)
        watcher.poll()
        self.assertEqual(self.store.mempool_txids(), set())
        self.assertEqual(set(e["reason"] for e in self.events("output.removed")), {"evicted"})

    def test_pending_spend(self):
        ours = Output("c0" * 32, 1, 9000, "ab" * 32, "cd" * 32, None, 5, "00" * 32, None, None)
        with self.store.transaction():
            self.store.add_output(ours)
        spend = {"txid": "f3" * 32, "vin": [{"txid": ours.txid, "vout": 1,
                                             "scriptSig": {"hex": ""}}],
                 "vout": [{"n": 0, "value": 1, "scriptPubKey": {"hex": "0014" + "22" * 20}}]}
        self.core.coins[(ours.txid, 1)] = "5120" + ours.pubkey
        self.core.mempool[spend["txid"]] = spend
        self.watcher.poll()
        self.assertEqual(self.store.mempool_spends(), {(ours.txid, 1): spend["txid"]})
        self.assertEqual(self.events("output.spending")[0]["pending_spent_txid"], spend["txid"])
        del self.core.mempool[spend["txid"]]
        self.watcher.poll()
        self.assertEqual(self.store.mempool_spends(), {})
        self.assertEqual(self.events("output.unspent")[0]["txid"], ours.txid)


if __name__ == "__main__":
    unittest.main()
