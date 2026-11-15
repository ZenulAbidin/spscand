"""Read-only local JSON API."""

from __future__ import annotations

import hmac
import json
import logging
import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from . import __version__
from .store import Output

log = logging.getLogger("spscand")


class State:
    """Values the scanner thread publishes for the API."""

    def __init__(self, network: str, backend: str, addresses: list[dict]) -> None:
        self.network = network
        self.backend = backend
        self.addresses = addresses
        self.tip: int | None = None
        self.error: str | None = None
        self.lock = threading.Lock()


def _read(path: Path, unspent_only: bool | None) -> tuple[list[Output], int | None]:
    """(outputs, scanned height); outputs are skipped if unspent_only is None."""
    db = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=30)
    try:
        outputs = []
        if unspent_only is not None:
            where = "WHERE spent_height IS NULL" if unspent_only else ""
            rows = db.execute(f"SELECT * FROM outputs {where} ORDER BY height, txid, vout")
            outputs = [Output(*row) for row in rows]
        row = db.execute("SELECT value FROM meta WHERE key = 'scanned_height'").fetchone()
        return outputs, int(row[0]) if row else None
    finally:
        db.close()


def serve(listen: str, db_path: Path, state: State, token: str = "") -> ThreadingHTTPServer:
    host, _, port = listen.rpartition(":")
    host = host.strip("[]") or "127.0.0.1"
    if not token and host not in ("127.0.0.1", "::1", "localhost"):
        raise ValueError(f"the API on {host} needs a token: set [api] token, or listen on "
                         "127.0.0.1")

    class Handler(BaseHTTPRequestHandler):
        server_version = "spscand"

        def log_message(self, fmt, *args) -> None:
            log.debug("api: " + fmt, *args)

        def _send(self, status: int, payload) -> None:
            body = json.dumps(payload, indent=1).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            if token:
                given = self.headers.get("Authorization", "")
                if not hmac.compare_digest(given.encode(), f"Bearer {token}".encode()):
                    self._send(401, {"error": "unauthorized"})
                    return
            url = urlsplit(self.path)
            query = {k: v[-1] for k, v in parse_qs(url.query).items()}
            try:
                payload = self._route(url.path, query)
            except ValueError as exc:
                self._send(400, {"error": str(exc)})
                return
            if payload is None:
                self._send(404, {"error": "not found"})
            else:
                self._send(200, payload)

        def _route(self, path: str, query: dict):
            if path == "/v1/status":
                _, scanned = _read(db_path, None)
                with state.lock:
                    tip, error = state.tip, state.error
                return {
                    "version": __version__,
                    "network": state.network,
                    "backend": state.backend,
                    "scanned_height": scanned,
                    "tip": tip,
                    "synced": tip is not None and scanned == tip,
                    "error": error,
                }
            if path == "/v1/addresses":
                return state.addresses
            if path in ("/v1/outputs", "/v1/balance"):
                min_conf = int(query.get("min_conf", "1"))
                unspent_only = path == "/v1/balance" or query.get("unspent") in ("1", "true")
                outputs, scanned = _read(db_path, unspent_only)
                tip = state.tip if state.tip is not None else scanned
                rows = [o.as_dict(tip) for o in outputs]
                if path == "/v1/outputs":
                    return rows
                return {
                    "balance": sum(r["amount"] for r in rows if r["confirmations"] >= min_conf),
                    "outputs": sum(1 for r in rows if r["confirmations"] >= min_conf),
                    "min_conf": min_conf,
                }
            return None

    server = ThreadingHTTPServer((host, int(port)), Handler)
    threading.Thread(target=server.serve_forever, name="api", daemon=True).start()
    log.info("API listening on %s", listen)
    return server
