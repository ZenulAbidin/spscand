"""Scanner behaviour on an in-memory chain: receive, spend, reorg, rescan."""

import secrets
import tempfile
import unittest
from pathlib import Path

from spscand.backends import Block, ScanGroup, TaprootOutput
from spscand.bip352 import Receiver, label_tweak, tagged_hash
from spscand.scanner import ReorgTooDeep, Scanner
from spscand.secp import N, Point
from spscand.store import REORG_WINDOW, Store


def _key() -> int:
    return secrets.randbelow(N - 1) + 1


class Chain:
    """A fake backend: a list of blocks that tests can extend or replace."""

    name = "fake"

    def __init__(self):
        self.blocks: list[Block] = []

    def tip(self):
        return len(self.blocks) - 1

    def block_hash(self, height):
        return self.blocks[height].hash

    def block(self, height):
        return self.blocks[height]

    def add(self, txs=(), spent=None, prefixes=(), tag="a"):
        height = len(self.blocks)
        prev = self.blocks[-1].hash if self.blocks else None
        self.blocks.append(Block(height, f"{tag}{height:063x}", prev,
                                 [ScanGroup([tweak], outputs) for tweak, outputs in txs],
                                 spent_outpoints=dict(spent or {}),
                                 spent_prefixes=set(prefixes)))


def payment(receiver: Receiver, txid: str, label=None, count=1):
    """A transaction paying `receiver` `count` outputs (plus one unrelated output)."""
    tweak = Point.from_secret(_key())
    secret = tweak.mul(receiver.scan_secret).serialize()
    spend = receiver.spend_pubkey
    if label is not None:
        spend = spend.add_generator(label_tweak(receiver.scan_secret, label))
    outputs = [TaprootOutput(txid, 0, 1234, Point.from_secret(_key()).xonly())]
    for k in range(count):
        t_k = int.from_bytes(tagged_hash("BIP0352/SharedSecret", secret + k.to_bytes(4, "big")), "big")
        outputs.append(TaprootOutput(txid, k + 1, 1000 * (k + 1), spend.add_generator(t_k).xonly()))
    return tweak, outputs


class ScannerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name) / "w.sqlite", create=True)
        self.store.set_meta("birthday", "0")
        self.receiver = Receiver(_key(), Point.from_secret(_key()), labels=[1])
        self.chain = Chain()
        self.events = []
        self.scanner = Scanner(self.store, self.receiver, self.chain,
                               emit=lambda e, d: self.events.append((e, d["txid"], d["vout"])))

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def txid(self):
        return secrets.token_hex(32)

    def test_receive_labels_and_multiple_outputs(self):
        a, b, c = self.txid(), self.txid(), self.txid()
        self.chain.add([payment(self.receiver, a), payment(self.receiver, b, label=1, count=2),
                        payment(Receiver(_key(), Point.from_secret(_key())), c)])
        self.chain.add([payment(self.receiver, self.txid(), label=0)])
        self.assertEqual(self.scanner.sync(), 2)
        found = {(o.txid, o.vout): o for o in self.store.outputs()}
        self.assertEqual(sorted(o.label for o in found.values() if o.txid == b), [1, 1])
        self.assertEqual(found[(a, 1)].amount, 1000)
        self.assertNotIn((c, 1), found)
        self.assertEqual(sorted(str(o.label) for o in found.values()), ["0", "1", "1", "None"])

    def test_block_wide_group(self):
        """BlindBit's shape: all of a block's tweaks against all of its outputs."""
        a, b = self.txid(), self.txid()
        txs = [payment(self.receiver, a), payment(self.receiver, b, label=1, count=2),
               payment(Receiver(_key(), Point.from_secret(_key())), self.txid())]
        self.chain.add()
        block = self.chain.blocks.pop()
        block.groups = [ScanGroup([t for t, _ in txs], [o for _, outs in txs for o in outs])]
        self.chain.blocks.append(block)
        self.scanner.sync()
        self.assertEqual(sorted((o.txid, o.vout, o.label) for o in self.store.outputs()),
                         sorted([(a, 1, None), (b, 1, 1), (b, 2, 1)]))

    def test_key_reused_in_same_block(self):
        a, b = self.txid(), self.txid()
        tweak, outputs = payment(self.receiver, a)
        reuse = TaprootOutput(b, 3, 777, outputs[1].key)
        self.chain.add([(tweak, outputs), (Point.from_secret(_key()), [reuse])])
        self.scanner.sync()
        self.assertEqual(sorted((o.txid, o.vout, o.amount) for o in self.store.outputs()),
                         sorted([(a, 1, 1000), (b, 3, 777)]))

    def test_reorg_between_fetches_without_parent_hash(self):
        """BlindBit gives no parent hash; a reorg between two fetches is still caught."""
        a = self.txid()
        self.chain.add()
        self.chain.add([payment(self.receiver, a)])
        self.chain.add()
        fetch = self.chain.block

        def block(height):
            if height == 2 and self.chain.blocks[1].hash.startswith("a"):
                # Block 1 is replaced (without the payment) after we fetched it.
                self.chain.blocks[1:] = []
                self.chain.add(tag="b")
                self.chain.add(tag="b")
            found = fetch(height)
            return Block(found.height, found.hash, None, found.groups)

        self.chain.block = block
        self.scanner.sync()
        self.assertEqual(self.store.outputs(), [])
        self.assertEqual(self.store.block_hash(1), self.chain.block_hash(1))
        self.assertIn(("output.reorged", a, 1), self.events)

    def test_spend_by_outpoint_and_by_prefix(self):
        a, b = self.txid(), self.txid()
        self.chain.add([payment(self.receiver, a), payment(self.receiver, b)])
        self.scanner.sync()
        key_b = next(o.pubkey for o in self.store.outputs() if o.txid == b)
        self.chain.add(spent={(a, 1): "s" * 64}, prefixes={bytes.fromhex(key_b[:16])})
        self.scanner.sync()
        spent = {o.txid: o for o in self.store.outputs()}
        self.assertEqual((spent[a].spent_txid, spent[a].spent_height), ("s" * 64, 1))
        self.assertEqual((spent[b].spent_txid, spent[b].spent_height), (None, 1))
        self.assertEqual(self.store.outputs(unspent_only=True), [])

    def test_spend_in_same_block(self):
        a = self.txid()
        self.chain.add([payment(self.receiver, a)], spent={(a, 1): "s" * 64})
        self.scanner.sync()
        self.assertEqual(self.store.outputs()[0].spent_height, 0)
        self.assertEqual([e for e, *_ in self.events], ["output.received", "output.spent"])

    def test_reorg_rewinds_outputs_and_spends(self):
        a, b = self.txid(), self.txid()
        self.chain.add([payment(self.receiver, a)])
        self.chain.add([payment(self.receiver, b)], spent={(a, 1): "s" * 64})
        self.scanner.sync()
        # Replace block 1 with one that has neither the payment nor the spend.
        self.chain.blocks = self.chain.blocks[:1]
        self.chain.add(tag="b")
        self.chain.add(tag="b")
        self.scanner.sync()
        outputs = self.store.outputs()
        self.assertEqual([(o.txid, o.spent_height) for o in outputs], [(a, None)])
        self.assertIn(("output.reorged", b, 1), self.events)
        self.assertIn(("output.unspent", a, 1), self.events)
        self.assertEqual(self.store.scanned_height(), 2)
        self.assertEqual(self.store.block_hash(2), self.chain.block_hash(2))

    def test_reorg_deeper_than_window_needs_rescan(self):
        for _ in range(REORG_WINDOW + 5):
            self.chain.add()
        self.scanner.sync()
        self.chain.blocks = []
        for _ in range(REORG_WINDOW + 6):
            self.chain.add(tag="b")
        with self.assertRaises(ReorgTooDeep):
            self.scanner.sync()

    def test_rescan_reproduces_wallet(self):
        a = self.txid()
        self.chain.add([payment(self.receiver, a)])
        self.chain.add(spent={(a, 1): "s" * 64})
        self.scanner.sync()
        before = self.store.outputs()
        with self.store.transaction():
            self.store.rewind(-1)
        self.assertEqual(self.store.outputs(), [])
        self.scanner.sync()
        self.assertEqual(self.store.outputs(), before)


if __name__ == "__main__":
    unittest.main()
