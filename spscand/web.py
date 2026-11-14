"""spscand web: a public silent payments scanning service.

Anyone can scan their own wallet, in one of two ways:

* In the browser (web/): the page downloads each block's tweaks and a compact
  filter of its taproot outputs from /v1/blocks, checks them with libspscan
  compiled to WebAssembly, and asks /v1/outputs only for blocks that may pay
  it, mixed with decoys. The scan key never leaves the browser.
* On the server (/v1/jobs): the visitor sends an address, scan key and start
  height; a worker scans the same data with the native library. The key is
  held in memory only, and a job and its results are dropped a day later.

Block data comes from a local BlindBit Oracle v2 (/full-block: every
transaction's tweak and taproot outputs). A cache keeps each block's tweaks
and filter; a background thread follows the tip and fills in history back to
taproot activation. Spent status for server scans comes from Bitcoin Core's
gettxout.

Nothing about visitors is logged.
"""

from __future__ import annotations

import hashlib
import json
import logging
import mimetypes
import secrets
import sqlite3
import struct
import threading
import time
import urllib.error
import urllib.request
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from decimal import Decimal
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from . import __version__, native
from .backends import BackendError, CoreBackend
from .bip352 import decode_address
from .secp import N

log = logging.getLogger("spscand.web")

TAPROOT_HEIGHT = 709632
MAX_BLOCKS = 2016           # per /v1/blocks response
MAX_RESPONSE = 8 << 20      # bytes per /v1/blocks response (at least one block)
MAX_ON_DEMAND = 64          # uncached blocks fetched while answering one request
MAX_OUTPUT_HEIGHTS = 32     # per /v1/outputs request
MAX_LABELS = 100
JOB_TTL = 24 * 3600
P2TR = b"\x51\x20"


def _hash_internal(display_hex: str) -> bytes:
    return bytes.fromhex(display_hex)[::-1]


@dataclass
class CachedBlock:
    height: int
    hash: bytes      # internal byte order
    tweaks: bytes    # 33 bytes each
    filter: bytes    # BIP158-style GCS over 0x5120 || x-only key, keyed by the block hash


class BlindBit:
    """The few BlindBit Oracle v2 calls this service needs."""

    def __init__(self, url: str, timeout: float = 60) -> None:
        self.url = url.rstrip("/")
        self.timeout = timeout

    def _get(self, path: str):
        try:
            with urllib.request.urlopen(self.url + path, timeout=self.timeout) as response:
                return json.loads(response.read(), parse_float=Decimal)
        except (OSError, ValueError) as exc:
            raise BackendError(f"BlindBit {path}: {exc}") from None

    def tip(self) -> int:
        info = self._get("/info")
        if info.get("network") != "main" or not info.get("tweaks_full_basic"):
            raise BackendError("BlindBit must be a mainnet server with a full tweak index")
        return int(info["height"])

    def block_hash(self, height: int) -> str:
        return self._get(f"/spent-outputs/{height}")["block_identifier"]["block_hash"]

    def full_block(self, height: int) -> tuple[str, list[dict]]:
        """(block hash, [{txid, tweak, outputs: [(vout, amount, x-only key)]}])."""
        body = self._get(f"/full-block/{height}")
        ident = body.get("block_identifier") or {}
        if ident.get("block_height") != height:
            raise BackendError(f"BlindBit /full-block/{height}: wrong block")
        txs = []
        for tx in body.get("index") or []:
            tweak = bytes.fromhex(tx["tweak"])
            if len(tweak) != 33 or not tweak.strip(b"\0"):
                continue
            outputs = [(int(u["vout"]), int(u["amount"]), bytes.fromhex(u["pubkey"]))
                       for u in tx.get("utxos") or []]
            txs.append({"txid": tx["txid"], "tweak": tweak, "outputs": outputs})
        return ident["block_hash"], txs


def build_block(height: int, block_hash: str, txs: list[dict]) -> CachedBlock:
    internal = _hash_internal(block_hash)
    keys = [P2TR + key for tx in txs for _vout, _amount, key in tx["outputs"] if len(key) == 32]
    return CachedBlock(height, internal, b"".join(tx["tweak"] for tx in txs),
                       native.gcs_build(internal, keys))


class BlockCache:
    def __init__(self, path: Path) -> None:
        self.db = sqlite3.connect(path, check_same_thread=False, timeout=60)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("CREATE TABLE IF NOT EXISTS blocks (height INTEGER PRIMARY KEY, "
                        "hash BLOB NOT NULL, tweaks BLOB NOT NULL, filter BLOB NOT NULL)")
        self.db.commit()
        self.lock = threading.Lock()

    def put(self, block: CachedBlock) -> None:
        with self.lock:
            self.db.execute("INSERT OR REPLACE INTO blocks VALUES (?, ?, ?, ?)",
                            (block.height, block.hash, block.tweaks, block.filter))
            self.db.commit()

    def get(self, start: int, count: int) -> dict[int, CachedBlock]:
        with self.lock:
            rows = self.db.execute("SELECT * FROM blocks WHERE height >= ? AND height < ?",
                                   (start, start + count)).fetchall()
        return {row[0]: CachedBlock(*row) for row in rows}

    def heights(self, start: int, end: int) -> set[int]:
        with self.lock:
            rows = self.db.execute("SELECT height FROM blocks WHERE height BETWEEN ? AND ?",
                                   (start, end)).fetchall()
        return {row[0] for row in rows}

    def hash_at(self, height: int) -> bytes | None:
        with self.lock:
            row = self.db.execute("SELECT hash FROM blocks WHERE height = ?", (height,)).fetchone()
        return row[0] if row else None

    def count(self) -> int:
        with self.lock:
            return self.db.execute("SELECT COUNT(*) FROM blocks").fetchone()[0]


class Chain:
    """The cache, kept at the tip and filled in backwards by a background thread."""

    def __init__(self, source: BlindBit, cache: BlockCache, workers: int = 3,
                 floor: int = TAPROOT_HEIGHT) -> None:
        self.source = source
        self.cache = cache
        self.floor = max(TAPROOT_HEIGHT, floor)  # the background fill stops here
        self.tip = 0
        self.workers = workers
        self.stop = threading.Event()

    def fetch(self, height: int) -> CachedBlock:
        block = build_block(height, *self.source.full_block(height))
        self.cache.put(block)
        return block

    def blocks(self, start: int, count: int, *, on_demand: int = MAX_ON_DEMAND
               ) -> list[CachedBlock]:
        """Blocks start.. (at most count, contiguous, none above the tip); uncached ones
        are fetched, up to on_demand of them, after which the list ends early."""
        count = max(0, min(count, self.tip - start + 1))
        have = self.cache.get(start, count)
        result = []
        for height in range(start, start + count):
            block = have.get(height)
            if block is None:
                if on_demand <= 0:
                    break
                on_demand -= 1
                block = self.fetch(height)
            result.append(block)
        return result

    def _check_recent(self) -> None:
        """Refetch the last few cached blocks if the chain changed under them."""
        for height in range(max(TAPROOT_HEIGHT, self.tip - 6), self.tip + 1):
            cached = self.cache.hash_at(height)
            if cached is not None and cached != _hash_internal(self.source.block_hash(height)):
                log.warning("block %d changed (reorg); refetching", height)
                self.fetch(height)

    def _fill(self, heights: list[int]) -> None:
        with ThreadPoolExecutor(self.workers) as pool:
            for _ in pool.map(self.fetch, heights):
                if self.stop.is_set():
                    break

    def run(self) -> None:
        """Follow the tip, then fill history backwards in batches."""
        while not self.stop.is_set():
            try:
                tip = self.source.tip()
                self.tip = tip
                self._check_recent()
                low = max(self.floor, self.tip - 2015)
                missing = sorted(set(range(low, self.tip + 1)) - self.cache.heights(low, self.tip),
                                 reverse=True)
                if not missing:
                    for top in range(low - 1, self.floor - 1, -2016):
                        bottom = max(self.floor, top - 2015)
                        gap = set(range(bottom, top + 1)) - self.cache.heights(bottom, top)
                        if gap:
                            missing = sorted(gap, reverse=True)[:200]
                            break
                if missing:
                    self._fill(missing[:200])
                    continue
            except (BackendError, sqlite3.Error, native.NativeError) as exc:
                log.warning("block sync: %s", exc)
            self.stop.wait(20)


@dataclass
class Payment:
    height: int
    txid: str
    vout: int
    amount: int
    label: int | None
    spent: bool | None = None

    def as_dict(self) -> dict:
        return {"height": self.height, "txid": self.txid, "vout": self.vout,
                "amount": self.amount, "label": self.label, "spent": self.spent}


@dataclass
class Job:
    id: str
    client: str
    receiver: native.Receiver | None
    start: int
    end: int
    created: float = field(default_factory=time.time)
    status: str = "queued"
    scanned: int | None = None
    payments: list[Payment] = field(default_factory=list)
    error: str | None = None
    finished: float | None = None
    cancelled: bool = False

    def as_dict(self, position: int | None) -> dict:
        done = (self.scanned - self.start + 1) if self.scanned is not None else 0
        return {"status": self.status, "position": position, "from": self.start, "to": self.end,
                "scanned_to": self.scanned, "progress": round(done / (self.end - self.start + 1), 4),
                "payments": [p.as_dict() for p in self.payments], "error": self.error}


class JobLimitError(Exception):
    pass


def scan_block(receiver: native.Receiver, block: CachedBlock, txs_for) -> list[Payment]:
    """Payments to receiver in block; txs_for(height) fetches the transactions."""
    tweaks = [block.tweaks[i:i + 33] for i in range(0, len(block.tweaks), 33)]
    if not tweaks or not receiver.filter_check(tweaks, block.filter, block.hash):
        return []
    found = []
    for tx in txs_for(block.height):
        if not tx["outputs"]:
            continue
        keys = [key for _vout, _amount, key in tx["outputs"]]
        for _t, index, _tweak, label in receiver.scan([tx["tweak"]], keys):
            vout, amount, _key = tx["outputs"][index]
            found.append(Payment(block.height, tx["txid"], vout, amount, label))
    return found


class Jobs:
    def __init__(self, chain: Chain, core: CoreBackend | None, *, workers: int = 2,
                 threads_per_job: int = 4, max_queued: int = 30, per_client: int = 2) -> None:
        self.chain = chain
        self.threads_per_job = threads_per_job
        self.core = core
        self.max_queued = max_queued
        self.per_client = per_client
        self.jobs: dict[str, Job] = {}
        self.queue: deque[Job] = deque()
        self.cond = threading.Condition()
        self.threads = [threading.Thread(target=self._worker, name=f"job-{i}", daemon=True)
                        for i in range(workers)]

    def start(self) -> None:
        for thread in self.threads:
            thread.start()
        threading.Thread(target=self._purge, name="job-purge", daemon=True).start()

    def submit(self, client: str, address: str, scan_key_hex: str, start: int,
               labels: list[int]) -> Job:
        scan_pubkey, spend_pubkey = decode_address(address.strip(), "main")
        text = scan_key_hex.strip().lower()
        if len(text) != 64 or any(c not in "0123456789abcdef" for c in text):
            raise ValueError("the scan key must be 64 hex characters")
        secret = int(text, 16)
        if not 0 < secret < N:
            raise ValueError("invalid scan key")
        receiver = native.Receiver(secret, spend_pubkey.serialize(), labels)
        del secret, text
        if receiver.scan_pubkey() != scan_pubkey.serialize():
            raise ValueError("this scan key does not belong to this address")
        end = self.chain.tip
        if not TAPROOT_HEIGHT <= start <= end:
            raise ValueError(f"the start height must be between {TAPROOT_HEIGHT} and {end}")
        with self.cond:
            active = [j for j in self.jobs.values() if j.status in ("queued", "running")]
            if sum(1 for j in active if j.client == client) >= self.per_client:
                raise JobLimitError("you already have scans running; wait for them to finish")
            if len(self.queue) >= self.max_queued:
                raise JobLimitError("the server is busy; try again later or scan in your browser")
            job = Job(secrets.token_urlsafe(24), client, receiver, start, end)
            self.jobs[job.id] = job
            self.queue.append(job)
            self.cond.notify()
        return job

    def get(self, job_id: str) -> tuple[Job, int | None] | None:
        with self.cond:
            job = self.jobs.get(job_id)
            if job is None:
                return None
            position = self.queue.index(job) + 1 if job in self.queue else None
            return job, position

    def delete(self, job_id: str) -> bool:
        with self.cond:
            job = self.jobs.pop(job_id, None)
            if job is None:
                return False
            job.cancelled = True
            if job in self.queue:
                self.queue.remove(job)
            if job.status != "running":
                job.receiver = None
            return True

    def counts(self) -> dict:
        with self.cond:
            running = sum(1 for j in self.jobs.values() if j.status == "running")
            return {"queued": len(self.queue), "running": running}

    def _worker(self) -> None:
        while True:
            with self.cond:
                while not self.queue:
                    self.cond.wait()
                job = self.queue.popleft()
                job.status = "running"
            try:
                self._run(job)
                job.status = "cancelled" if job.cancelled else "done"
            except Exception as exc:  # report, never log the job's details
                job.status, job.error = "failed", "scan failed; please try again"
                log.warning("a scan job failed: %s", type(exc).__name__)
            finally:
                job.receiver = None  # the native receiver wipes the key when freed
                job.finished = time.time()

    def _run(self, job: Job) -> None:
        receiver = job.receiver

        def txs_for(height: int) -> list[dict]:
            return self.chain.source.full_block(height)[1]

        def scan(block: CachedBlock) -> list[Payment]:
            return [] if job.cancelled else scan_block(receiver, block, txs_for)

        height = job.start
        with ThreadPoolExecutor(self.threads_per_job) as pool:
            while height <= job.end and not job.cancelled:
                blocks = self.chain.blocks(height, min(500, job.end - height + 1))
                if not blocks:
                    raise BackendError("no block data")
                for block, found in zip(blocks, pool.map(scan, blocks)):
                    job.payments += found
                    job.scanned = block.height
                height = blocks[-1].height + 1
        if job.cancelled:
            return
        if self.core is not None:
            for payment in job.payments:
                try:
                    payment.spent = self.core.call("gettxout", payment.txid, payment.vout,
                                                   True) is None
                except BackendError:
                    payment.spent = None

    def _purge(self) -> None:
        while True:
            time.sleep(300)
            now = time.time()
            with self.cond:
                for job_id, job in list(self.jobs.items()):
                    if (job.finished and now - job.finished > JOB_TTL) or now - job.created > 3 * JOB_TTL:
                        job.cancelled = True
                        del self.jobs[job_id]


def encode_blocks(blocks: list[CachedBlock]) -> bytes:
    """b"SPB1", u32 count, then per block: u32 height, 32-byte hash (internal order),
    u32 tweak count, tweaks, u32 filter length, filter. Little-endian."""
    parts = [b"SPB1", struct.pack("<I", len(blocks))]
    for block in blocks:
        parts += [struct.pack("<I", block.height), block.hash,
                  struct.pack("<I", len(block.tweaks) // 33), block.tweaks,
                  struct.pack("<I", len(block.filter)), block.filter]
    return b"".join(parts)


STATIC = {"/": "index.html", "/index.html": "index.html", "/app.js": "app.js",
          "/worker.js": "worker.js", "/scanner.js": "scanner.js", "/spscan.js": "spscan.js",
          "/spscan.wasm": "spscan.wasm",
          "/style.css": "style.css", "/favicon.svg": "favicon.svg"}
CSP = ("default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self'; "
       "connect-src 'self'; style-src 'self'; img-src 'self' data:; base-uri 'none'; "
       "form-action 'none'; frame-ancestors 'none'")


def serve(listen: str, chain: Chain, jobs: Jobs, static_dir: Path) -> ThreadingHTTPServer:
    host, _, port = listen.rpartition(":")
    files: dict[str, tuple[bytes, str, str]] = {}
    for path, name in STATIC.items():
        file = static_dir / name
        if name == "spscan.wasm" and not file.exists():  # a source checkout: make -C libspscan wasm
            file = static_dir.parent / "libspscan" / name
        if file.exists():
            body = file.read_bytes()
            kind = "application/wasm" if name.endswith(".wasm") else \
                (mimetypes.guess_type(name)[0] or "application/octet-stream")
            if kind.startswith("text/") or kind.endswith(("javascript", "svg+xml")):
                kind += "; charset=utf-8"
            files[path] = (body, kind, '"' + hashlib.sha256(body).hexdigest()[:32] + '"')

    class Handler(BaseHTTPRequestHandler):
        server_version = "spscan"
        sys_version = ""
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args) -> None:
            pass  # no visitor logs

        def _client(self) -> str:
            return self.headers.get("CF-Connecting-IP") or self.client_address[0]

        def _send(self, status: int, body: bytes, kind: str, extra: dict | None = None) -> None:
            self.send_response(status)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            for key, value in (extra or {}).items():
                self.send_header(key, value)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _json(self, status: int, payload) -> None:
            self._send(status, json.dumps(payload).encode(), "application/json",
                       {"Cache-Control": "no-store"})

        def _query(self) -> tuple[str, dict]:
            url = urlsplit(self.path)
            return url.path, {k: v[-1] for k, v in parse_qs(url.query).items()}

        def do_HEAD(self) -> None:
            self.do_GET()

        def do_GET(self) -> None:
            path, query = self._query()
            try:
                if path in files:
                    body, kind, etag = files[path]
                    headers = {"ETag": etag, "Cache-Control": "no-cache"}
                    if kind.startswith("text/html"):
                        headers["Content-Security-Policy"] = CSP
                        headers["X-Frame-Options"] = "DENY"
                    if self.headers.get("If-None-Match") == etag:
                        self.send_response(304)
                        for key, value in headers.items():
                            self.send_header(key, value)
                        self.send_header("Content-Length", "0")
                        self.end_headers()
                        return
                    self._send(200, body, kind, headers)
                elif path == "/v1/info":
                    self._json(200, {"network": "main", "version": __version__, "tip": chain.tip,
                                     "taproot_height": TAPROOT_HEIGHT, "max_blocks": MAX_BLOCKS,
                                     "max_output_heights": MAX_OUTPUT_HEIGHTS,
                                     "jobs": jobs.counts()})
                elif path == "/v1/blocks":
                    self._blocks(query)
                elif path == "/v1/outputs":
                    self._outputs(query)
                elif path.startswith("/v1/jobs/"):
                    found = jobs.get(path[len("/v1/jobs/"):])
                    if found is None:
                        self._json(404, {"error": "no such scan (scans are kept for a day)"})
                    else:
                        self._json(200, found[0].as_dict(found[1]))
                else:
                    self._json(404, {"error": "not found"})
            except ValueError as exc:
                self._json(400, {"error": str(exc)})
            except (BackendError, native.NativeError, sqlite3.Error) as exc:
                log.warning("request failed: %s", exc)
                self._json(503, {"error": "block data unavailable; try again shortly"})

        def _blocks(self, query: dict) -> None:
            start = int(query.get("from", ""))
            count = min(int(query.get("count", MAX_BLOCKS)), MAX_BLOCKS)
            if start < TAPROOT_HEIGHT or count < 1:
                raise ValueError(f"from must be at least {TAPROOT_HEIGHT}, count at least 1")
            blocks, size = [], 0
            for block in chain.blocks(start, count):
                size += 44 + len(block.tweaks) + len(block.filter)
                if blocks and size > MAX_RESPONSE:
                    break
                blocks.append(block)
            self._send(200, encode_blocks(blocks), "application/octet-stream",
                       {"Cache-Control": "no-store"})

        def _outputs(self, query: dict) -> None:
            heights = sorted({int(h) for h in query.get("heights", "").split(",") if h})
            if not heights or len(heights) > MAX_OUTPUT_HEIGHTS:
                raise ValueError(f"give 1 to {MAX_OUTPUT_HEIGHTS} heights")
            if heights[0] < TAPROOT_HEIGHT or heights[-1] > chain.tip:
                raise ValueError("height out of range")
            result = {}
            for height in heights:
                block_hash, txs = chain.source.full_block(height)
                result[str(height)] = {"hash": block_hash, "txs": [
                    {"txid": tx["txid"], "tweak": tx["tweak"].hex(),
                     "outputs": [[vout, amount, key.hex()] for vout, amount, key in tx["outputs"]]}
                    for tx in txs]}
            self._json(200, result)

        def do_POST(self) -> None:
            path, _ = self._query()
            if path != "/v1/jobs":
                self._json(404, {"error": "not found"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 4096:
                    raise ValueError("bad request size")
                body = json.loads(self.rfile.read(length))
                labels = body.get("labels") or []
                if (not isinstance(labels, list) or len(labels) > MAX_LABELS or
                        not all(isinstance(m, int) and 0 < m < 2**31 for m in labels)):
                    raise ValueError(f"labels: up to {MAX_LABELS} numbers from 1")
                job = jobs.submit(self._client(), str(body.get("address", "")),
                                  str(body.get("scan_key", "")), int(body.get("from", 0)), labels)
                body = None
                self._json(202, {"id": job.id})
            except JobLimitError as exc:
                self._json(429, {"error": str(exc)})
            except (ValueError, TypeError, AttributeError) as exc:
                message = str(exc) if isinstance(exc, ValueError) else "bad request"
                if "Expecting" in message or "JSON" in message:
                    message = "bad request"
                self._json(400, {"error": message})

        def do_DELETE(self) -> None:
            path, _ = self._query()
            if path.startswith("/v1/jobs/") and jobs.delete(path[len("/v1/jobs/"):]):
                self._json(200, {"deleted": True})
            else:
                self._json(404, {"error": "no such scan"})

    server = ThreadingHTTPServer((host, int(port)), Handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, name="http", daemon=True).start()
    return server


def run(args) -> None:
    if not native.available():
        raise SystemExit("spscand web needs libspscan (make -C libspscan)")
    cache_path = Path(args.cache).expanduser()
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    chain = Chain(BlindBit(args.blindbit_url), BlockCache(cache_path), workers=args.sync_workers,
                  floor=args.fill_from)
    chain.tip = chain.source.tip()
    core = CoreBackend(args.rpc_url, cookie=args.rpc_cookie) if args.rpc_cookie else None
    jobs = Jobs(chain, core, workers=args.job_workers, threads_per_job=args.job_threads)
    jobs.start()
    static_dir = Path(args.static).expanduser()
    serve(args.listen, chain, jobs, static_dir)
    log.info("spscand web %s on %s; tip %d; %d blocks cached", __version__, args.listen,
             chain.tip, chain.cache.count())
    try:
        chain.run()
    except KeyboardInterrupt:
        pass
