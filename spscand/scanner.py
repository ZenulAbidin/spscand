"""Scan blocks for a receiver, following reorgs and spends."""

from __future__ import annotations

import logging
import threading

from . import native
from .bip352 import Receiver
from .store import Output, Store

log = logging.getLogger("spscand")

# BlindBit does not report a block's parent. Within this many blocks of the
# tip it is fetched separately, to catch a reorg between two block fetches;
# deeper blocks are not reorged in practice and the fetch would add ~15%.
PARENT_CHECK_DEPTH = 100


class ReorgTooDeep(RuntimeError):
    pass


class Scanner:
    def __init__(self, store: Store, receiver: Receiver, backend, *,
                 emit=None) -> None:
        self.store = store
        self.receiver = receiver
        self.backend = backend
        self.emit = emit or (lambda event, data: None)
        self.tip: int | None = None
        if hasattr(backend, "set_matcher"):
            backend.set_matcher(self._may_concern_us)

    def _may_concern_us(self, block_hash: str, tweaks, filter_data: bytes) -> bool:
        """Does a block's BIP158 filter possibly hold a payment to us or a spend of ours?"""
        key = bytes.fromhex(block_hash)[::-1]
        if tweaks and self.receiver.filter_check(tweaks, filter_data, key):
            return True
        # Basic filters include the scripts spent by the block's inputs.
        scripts = [bytes.fromhex("5120" + o.pubkey) for o in self.store.outputs(unspent_only=True)]
        return bool(scripts) and native.gcs_match_any(filter_data, key, scripts)

    def start_height(self) -> int:
        scanned = self.store.scanned_height()
        if scanned is not None:
            return scanned + 1
        return int(self.store.get_meta("birthday") or 0)

    def sync(self, stop: threading.Event | None = None) -> int:
        """Scan to the backend's tip; returns the number of blocks scanned."""
        self._check_reorg()
        self.tip = self.backend.tip()
        scanned = retries = 0
        height = self.start_height()
        while height <= self.tip and not (stop and stop.is_set()):
            block = self.backend.block(height)
            expected_prev = self.store.block_hash(height - 1)
            prev = block.prev_hash
            if prev is None and expected_prev is not None and height > self.tip - PARENT_CHECK_DEPTH:
                prev = self.backend.block_hash(height - 1)
            if expected_prev is not None and prev is not None and prev != expected_prev:
                retries += 1
                if retries > 5:
                    raise RuntimeError(f"block {height} keeps disagreeing with block {height - 1}")
                log.warning("block %d does not build on our block %d; reorg", height, height - 1)
                self._check_reorg()
                height = self.start_height()
                continue
            retries = 0
            self._apply(block)
            scanned += 1
            height += 1
        return scanned

    def _check_reorg(self) -> None:
        height = self.store.scanned_height()
        if height is None:
            return
        fork = height
        while True:
            ours = self.store.block_hash(fork)
            if ours is None:
                oldest = self.store.oldest_block()
                if fork == height or oldest is None:
                    return  # just rewound by a rescan: no hashes kept yet
                raise ReorgTooDeep(f"chain differs below height {oldest}; run 'spscand rescan'")
            if self.backend.block_hash(fork) == ours:
                break
            fork -= 1
        if fork == height:
            return
        log.warning("reorg: rewinding from %d to %d", height, fork)
        with self.store.transaction():
            removed, unspent = self.store.rewind(fork)
        for output in removed:
            self.emit("output.reorged", output.as_dict())
        for output in unspent:
            self.emit("output.unspent", output.as_dict(self.tip))

    def _apply(self, block) -> None:
        received: list[Output] = []
        spent: list[Output] = []
        with self.store.transaction():
            # Every output in the block carrying a found key is ours, including
            # one paid to it outside BIP352 (address reuse).
            by_key: dict[bytes, list] = {}
            for group in block.groups:
                for out in group.outputs:
                    by_key.setdefault(out.key, []).append(out)
            for group in block.groups:
                keys = [o.key for o in group.outputs]
                for _, match in self.receiver.scan_group(group.tweaks, keys):
                    for out in by_key[match.xonly]:
                        output = Output(
                            txid=out.txid, vout=out.vout, amount=out.amount,
                            pubkey=out.key.hex(), tweak=f"{match.tweak:064x}",
                            label=match.label, height=block.height,
                            block_hash=block.hash, spent_txid=None, spent_height=None,
                        )
                        if self.store.add_output(output):
                            received.append(output)
            for output in self.store.outputs(unspent_only=True):
                spender = block.spent_outpoints.get((output.txid, output.vout))
                if spender is None and bytes.fromhex(output.pubkey[:16]) in block.spent_prefixes:
                    spender = ""  # BlindBit reports spent keys, not the spending txid
                if spender is not None:
                    self.store.mark_spent(output.txid, output.vout, spender or None, block.height)
                    spent.append(output)
            self.store.record_block(block.height, block.hash)
        for output in received:
            log.info("received %d sat in %s:%d (label %s) at height %d", output.amount,
                     output.txid, output.vout, output.label, output.height)
            self.emit("output.received", output.as_dict(self.tip))
        for output in spent:
            log.info("spent %s:%d at height %d", output.txid, output.vout, block.height)
            data = output.as_dict(self.tip)
            data["spent_height"] = block.height
            data["spent_txid"] = block.spent_outpoints.get((output.txid, output.vout))
            self.emit("output.spent", data)
