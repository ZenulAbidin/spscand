"""SQLite wallet store: keys, labels, scan progress and found outputs."""

from __future__ import annotations

import os
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

SCHEMA_VERSION = 1
REORG_WINDOW = 1000  # recent block hashes kept to find the fork point of a reorg

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS labels (m INTEGER PRIMARY KEY, comment TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS blocks (height INTEGER PRIMARY KEY, hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS outputs (
    txid TEXT NOT NULL,
    vout INTEGER NOT NULL,
    amount INTEGER NOT NULL,
    pubkey TEXT NOT NULL,
    tweak TEXT NOT NULL,
    label INTEGER,
    height INTEGER NOT NULL,
    block_hash TEXT NOT NULL,
    spent_txid TEXT,
    spent_height INTEGER,
    PRIMARY KEY (txid, vout)
);
CREATE INDEX IF NOT EXISTS outputs_unspent ON outputs (spent_height) WHERE spent_height IS NULL;
"""


@dataclass(frozen=True)
class Output:
    txid: str
    vout: int
    amount: int
    pubkey: str
    tweak: str
    label: int | None
    height: int
    block_hash: str
    spent_txid: str | None
    spent_height: int | None

    def as_dict(self, tip: int | None = None) -> dict:
        data = dict(self.__dict__)
        if tip is not None:
            data["confirmations"] = max(0, tip - self.height + 1)
        return data


class Store:
    def __init__(self, path: Path, *, create: bool = False) -> None:
        self.path = Path(path)
        if not create and not self.path.exists():
            raise FileNotFoundError(f"no wallet at {self.path} (run 'spscand init')")
        if create:
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            # The file holds the scan secret: create it private before SQLite opens it.
            os.close(os.open(self.path, os.O_CREAT | os.O_WRONLY, 0o600))
        self.db = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        self.db.execute("PRAGMA journal_mode=WAL")
        # WAL + NORMAL never corrupts the file; a crash can only lose the last
        # few scanned blocks, which are scanned again.
        self.db.execute("PRAGMA synchronous=NORMAL")
        self.db.executescript(_SCHEMA)
        version = self.get_meta("schema_version")
        if version is None:
            self.set_meta("schema_version", str(SCHEMA_VERSION))
        elif int(version) != SCHEMA_VERSION:
            raise RuntimeError(f"unsupported wallet schema version {version}")

    def close(self) -> None:
        self.db.close()

    @contextmanager
    def transaction(self) -> Iterator[None]:
        self.db.execute("BEGIN IMMEDIATE")
        try:
            yield
        except BaseException:
            self.db.execute("ROLLBACK")
            raise
        self.db.execute("COMMIT")

    def get_meta(self, key: str) -> str | None:
        row = self.db.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row[0] if row else None

    def set_meta(self, key: str, value: str) -> None:
        self.db.execute(
            "INSERT INTO meta (key, value) VALUES (?, ?) "
            "ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            (key, value),
        )

    def labels(self) -> dict[int, str]:
        return dict(self.db.execute("SELECT m, comment FROM labels ORDER BY m"))

    def add_label(self, m: int, comment: str = "") -> None:
        self.db.execute(
            "INSERT INTO labels (m, comment) VALUES (?, ?) "
            "ON CONFLICT (m) DO UPDATE SET comment = excluded.comment",
            (m, comment),
        )

    def scanned_height(self) -> int | None:
        value = self.get_meta("scanned_height")
        return int(value) if value is not None else None

    def block_hash(self, height: int) -> str | None:
        row = self.db.execute("SELECT hash FROM blocks WHERE height = ?", (height,)).fetchone()
        return row[0] if row else None

    def record_block(self, height: int, block_hash: str) -> None:
        self.db.execute("INSERT OR REPLACE INTO blocks (height, hash) VALUES (?, ?)",
                        (height, block_hash))
        self.db.execute("DELETE FROM blocks WHERE height <= ?", (height - REORG_WINDOW,))
        self.set_meta("scanned_height", str(height))

    def oldest_block(self) -> int | None:
        row = self.db.execute("SELECT MIN(height) FROM blocks").fetchone()
        return row[0]

    def rewind(self, height: int) -> tuple[list[Output], list[Output]]:
        """Forget everything above `height`. Returns (removed, unspent_again)."""
        removed = self._outputs("WHERE height > ?", (height,))
        unspent = self._outputs("WHERE height <= ? AND spent_height > ?", (height, height))
        self.db.execute("DELETE FROM outputs WHERE height > ?", (height,))
        self.db.execute(
            "UPDATE outputs SET spent_txid = NULL, spent_height = NULL WHERE spent_height > ?",
            (height,),
        )
        self.db.execute("DELETE FROM blocks WHERE height > ?", (height,))
        self.set_meta("scanned_height", str(height))
        return removed, unspent

    def add_output(self, output: Output) -> bool:
        cursor = self.db.execute(
            "INSERT OR IGNORE INTO outputs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                output.txid, output.vout, output.amount, output.pubkey, output.tweak,
                output.label, output.height, output.block_hash,
                output.spent_txid, output.spent_height,
            ),
        )
        return cursor.rowcount == 1

    def mark_spent(self, txid: str, vout: int, spent_txid: str | None, height: int) -> None:
        self.db.execute(
            "UPDATE outputs SET spent_txid = ?, spent_height = ? WHERE txid = ? AND vout = ?",
            (spent_txid, height, txid, vout),
        )

    def _outputs(self, where: str, params: tuple = ()) -> list[Output]:
        rows = self.db.execute(f"SELECT * FROM outputs {where} ORDER BY height, txid, vout", params)
        return [Output(*row) for row in rows]

    def outputs(self, *, unspent_only: bool = False) -> list[Output]:
        return self._outputs("WHERE spent_height IS NULL" if unspent_only else "")
