"""Unconfirmed payments: watch a Bitcoin Core node's mempool.

Every transaction in the mempool is fetched and checked, as blocks are, so
the node is never asked about anything that would single out our payments.
Core does not return prevouts for mempool transactions, so the inputs'
scripts are looked up on the same node: gettxout for confirmed coins, the
parent transaction for unconfirmed ones.
"""

from __future__ import annotations

import logging
import time

from .backends import CoreBackend, scan_group
from .store import MempoolOutput

log = logging.getLogger("spscand")

BATCH = 200


def _chunks(items: list, size: int = BATCH):
    for start in range(0, len(items), size):
        yield items[start:start + size]


class MempoolWatcher:
    """Finds payments to us and spends of our outputs among unconfirmed
    transactions, and drops them again when they leave the mempool unmined."""

    def __init__(self, core: CoreBackend, scanner) -> None:
        self.core = core
        self.scanner = scanner  # for its store, receiver and emit, which may be replaced
        self.known: set[str] = set()
        self._block_txids: dict[str, set[str]] = {}

    @property
    def store(self):
        return self.scanner.store

    def poll(self) -> None:
        txids = set(self.core.call("getrawmempool"))
        tracked = self.store.mempool_txids()
        gone = (tracked | self.known) - txids
        new = txids - self.known - tracked
        # A transaction counts as known once it has been checked: if a request
        # fails halfway, the rest are checked on the next poll.
        self.known = (self.known | tracked) & txids
        for txid in sorted(gone & tracked):
            self._gone(txid)
        self._scan(sorted(new), txids)

    # -- leaving the mempool -------------------------------------------------

    def _mined_above_scan(self, txid: str) -> bool:
        """Is the transaction in a block the scanner has not reached yet?"""
        scanned = self.store.scanned_height()
        tip = self.core.call("getblockcount")
        start = (scanned if scanned is not None else tip) + 1
        for height in range(start, tip + 1):
            block_hash = self.core.call("getblockhash", height)
            if block_hash not in self._block_txids:
                block = self.core.call("getblock", block_hash, 1)
                self._block_txids[block_hash] = set(block["tx"])
            if txid in self._block_txids[block_hash]:
                return True
        if len(self._block_txids) > 50:
            self._block_txids.clear()
        return False

    def _why_gone(self, txid: str) -> str:
        inputs = self.store.mempool_inputs(txid)
        if not inputs:
            return "evicted"
        spenders = self.core.call(
            "gettxspendingprevout", [{"txid": t, "vout": v} for t, v in inputs])
        if any(s.get("spendingtxid") not in (None, txid) for s in spenders):
            return "replaced"
        coins = self.core.call_many("gettxout", [[t, v, False] for t, v in inputs])
        # An input spent in a block, or the output of an unconfirmed parent that left too.
        return "conflicted" if any(c is None for c in coins) else "evicted"

    def _gone(self, txid: str) -> None:
        if self._mined_above_scan(txid):
            return  # the next block scan confirms it
        reason = self._why_gone(txid)
        outputs = self.store.mempool_outputs(txid)
        spends = self.store.mempool_spends(txid)
        with self.store.transaction():
            self.store.remove_mempool_tx(txid)
        log.info("unconfirmed transaction %s left the mempool (%s)", txid, reason)
        for output in outputs:
            data = output.as_dict()
            data["reason"] = reason
            self.scanner.emit("output.removed", data)
        confirmed = {(o.txid, o.vout): o for o in self.store.outputs(unspent_only=True)}
        for outpoint in spends:
            if outpoint in confirmed:
                self.scanner.emit("output.unspent", confirmed[outpoint].as_dict(self.scanner.tip))

    # -- entering the mempool ------------------------------------------------

    def _prevouts(self, txs: list[dict], mempool: set[str]) -> dict[tuple[str, int], str]:
        """Script hex of every input of these transactions that can be found."""
        parents, coins = set(), []
        for tx in txs:
            for vin in tx["vin"]:
                if vin["txid"] in mempool:
                    parents.add(vin["txid"])
                else:
                    coins.append((vin["txid"], vin["vout"]))
        scripts: dict[tuple[str, int], str] = {}
        for chunk in _chunks(sorted(parents)):
            for parent in self.core.call_many("getrawtransaction", [[t, 1] for t in chunk]):
                if parent:
                    for out in parent["vout"]:
                        scripts[(parent["txid"], out["n"])] = out["scriptPubKey"]["hex"]
        for chunk in _chunks(coins):
            for outpoint, coin in zip(chunk, self.core.call_many(
                    "gettxout", [[t, v, False] for t, v in chunk])):
                if coin:
                    scripts[outpoint] = coin["scriptPubKey"]["hex"]
        return scripts

    def _scan(self, txids: list[str], mempool: set[str]) -> None:
        """Check new mempool transactions, adding each one checked to known."""
        ours = {(o.txid, o.vout) for o in self.store.outputs(unspent_only=True)}
        ours |= {(o.txid, o.vout) for o in self.store.mempool_outputs()}
        for chunk in _chunks(txids):
            txs = [tx for tx in self.core.call_many("getrawtransaction", [[t, 1] for t in chunk])
                   if tx]
            taproot = [tx for tx in txs if any(
                len(spk := out["scriptPubKey"]["hex"]) == 68 and spk.startswith("5120")
                for out in tx["vout"])]
            scripts = self._prevouts(taproot, mempool)
            taproot_txids = {tx["txid"] for tx in taproot}
            for tx in txs:
                inputs = [(vin["txid"], vin["vout"]) for vin in tx["vin"]]
                found: list[MempoolOutput] = []
                if tx["txid"] in taproot_txids:
                    if not all(i in scripts for i in inputs):
                        continue  # a parent came or went meanwhile: next poll

                    for vin in tx["vin"]:
                        script = scripts[(vin["txid"], vin["vout"])]
                        vin["prevout"] = {"scriptPubKey": {"hex": script}}
                    found = self._match(tx)
                spends = [i for i in inputs if i in ours]
                if found or spends:
                    with self.store.transaction():
                        self.store.add_mempool_tx(tx["txid"], inputs, int(time.time()),
                                                  found, spends)
                    ours |= {(o.txid, o.vout) for o in found}
                    self._announce(tx["txid"], found, spends)
                self.known.add(tx["txid"])

    def _match(self, tx: dict) -> list[MempoolOutput]:
        group = scan_group(tx)
        if group is None:
            return []
        by_key: dict[bytes, list] = {}
        for out in group.outputs:
            by_key.setdefault(out.key, []).append(out)
        found = []
        for _, match in self.scanner.receiver.scan_group(group.tweaks,
                                                         [o.key for o in group.outputs]):
            for out in by_key[match.xonly]:
                found.append(MempoolOutput(out.txid, out.vout, out.amount, out.key.hex(),
                                           f"{match.tweak:064x}", match.label))
        return found

    def _announce(self, txid: str, found: list[MempoolOutput], spends) -> None:
        for output in found:
            log.info("unconfirmed: %d sat in %s:%d (label %s)", output.amount, output.txid,
                     output.vout, output.label)
            self.scanner.emit("output.unconfirmed", output.as_dict())
        confirmed = {(o.txid, o.vout): o for o in self.store.outputs(unspent_only=True)}
        for outpoint in spends:
            log.info("unconfirmed spend of %s:%d in %s", *outpoint, txid)
            if outpoint in confirmed:
                data = confirmed[outpoint].as_dict(self.scanner.tip)
                data["pending_spent_txid"] = txid
                self.scanner.emit("output.spending", data)

