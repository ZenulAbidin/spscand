"""Unconfirmed transactions in the wallet store."""

import tempfile
import unittest
from pathlib import Path

from spscand.store import MempoolOutput, Output, Store


def confirmed(txid, vout=0, height=10, spent_txid=None, spent_height=None):
    return Output(txid=txid, vout=vout, amount=5000, pubkey="ab" * 32, tweak="cd" * 32,
                  label=None, height=height, block_hash="00" * 32,
                  spent_txid=spent_txid, spent_height=spent_height)


def unconfirmed(txid, vout=0, amount=7000, label=None):
    return MempoolOutput(txid=txid, vout=vout, amount=amount, pubkey="ef" * 32,
                         tweak="12" * 32, label=label)


class MempoolStoreTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name) / "wallet.sqlite", create=True)

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_add_and_remove(self):
        pay, spend = "a" * 64, "b" * 64
        with self.store.transaction():
            self.store.add_output(confirmed("c" * 64))
            self.store.add_mempool_tx(pay, [("d" * 64, 1)], 100, [unconfirmed(pay, label=2)], [])
            self.store.add_mempool_tx(spend, [("c" * 64, 0)], 101, [], [("c" * 64, 0)])
        self.assertEqual(self.store.mempool_txids(), {pay, spend})
        self.assertEqual(self.store.mempool_inputs(pay), [("d" * 64, 1)])
        self.assertEqual(self.store.mempool_outputs(), [unconfirmed(pay, label=2)])
        self.assertEqual(self.store.mempool_spends(), {("c" * 64, 0): spend})
        self.assertEqual(unconfirmed(pay).as_dict()["status"], "unconfirmed")
        self.assertEqual(unconfirmed(pay).as_dict()["confirmations"], 0)

        with self.store.transaction():
            self.store.remove_mempool_tx(spend)
        self.assertEqual(self.store.mempool_spends(), {})
        self.assertEqual(self.store.mempool_txids(), {pay})

    def test_confirmation_drops_mempool_rows(self):
        pay, spend, other = "a" * 64, "b" * 64, "e" * 64
        with self.store.transaction():
            self.store.add_output(confirmed("c" * 64))
            self.store.add_mempool_tx(pay, [], 100, [unconfirmed(pay)], [])
            self.store.add_mempool_tx(spend, [("c" * 64, 0)], 100, [], [("c" * 64, 0)])
            self.store.add_mempool_tx(other, [], 100, [unconfirmed(other)], [])
        # A block confirms the payment and spends our output (by outpoint only,
        # as with BlindBit).
        with self.store.transaction():
            self.store.add_output(confirmed(pay, height=11))
            self.store.mark_spent("c" * 64, 0, None, 11)
            done = self.store.drop_confirmed_mempool()
        self.assertEqual(sorted(done), [pay, spend])
        self.assertEqual(self.store.mempool_txids(), {other})
        self.assertEqual([o.txid for o in self.store.mempool_outputs()], [other])
        self.assertEqual(self.store.mempool_spends(), {})


if __name__ == "__main__":
    unittest.main()
