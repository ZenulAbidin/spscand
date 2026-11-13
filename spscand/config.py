"""spscand.toml: backend, API and webhook settings."""

from __future__ import annotations

import logging
import tomllib
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from .socks import parse_proxy

log = logging.getLogger("spscand")

TEMPLATE = """\
# spscand configuration. Restart spscand after editing.

[backend]
# "core": a local Bitcoin Core node (>= 25). Tweaks are computed locally.
# "blindbit": a BlindBit Oracle v2 tweak server. It never sees your keys,
# but it learns which blocks you fetch and could withhold data.
type = {backend}

# Bitcoin Core JSON-RPC
rpc_url = {rpc_url}
rpc_cookie = {rpc_cookie}
# rpc_user = ""
# rpc_password = ""

# BlindBit Oracle v2
blindbit_url = {blindbit_url}

# SOCKS5 proxy for the backend, e.g. Tor: "socks5h://127.0.0.1:9050".
# Host names (including .onion) are resolved by the proxy.
proxy = {proxy}

[scan]
poll_seconds = 30

[api]
# Read-only JSON API. Keep it on loopback; set a token if other local users exist.
listen = "127.0.0.1:7352"
token = ""

[webhook]
# POSTed on output.received, output.spent, output.reorged and output.unspent.
url = ""
secret = ""
"""


@dataclass
class Config:
    backend: str = "core"
    rpc_url: str = "http://127.0.0.1:8332"
    rpc_cookie: str = "~/.bitcoin/.cookie"
    rpc_user: str = ""
    rpc_password: str = ""
    blindbit_url: str = "http://127.0.0.1:8000"
    proxy: str = ""
    poll_seconds: float = 30
    api_listen: str = "127.0.0.1:7352"
    api_token: str = ""
    webhook_url: str = ""
    webhook_secret: str = ""

    @classmethod
    def load(cls, path: Path) -> "Config":
        data = tomllib.loads(path.read_text()) if path.exists() else {}
        backend = data.get("backend", {})
        scan = data.get("scan", {})
        api = data.get("api", {})
        webhook = data.get("webhook", {})
        config = cls(
            backend=backend.get("type", cls.backend),
            rpc_url=backend.get("rpc_url", cls.rpc_url),
            rpc_cookie=backend.get("rpc_cookie", cls.rpc_cookie),
            rpc_user=backend.get("rpc_user", ""),
            rpc_password=backend.get("rpc_password", ""),
            blindbit_url=backend.get("blindbit_url", cls.blindbit_url),
            proxy=backend.get("proxy", ""),
            poll_seconds=float(scan.get("poll_seconds", cls.poll_seconds)),
            api_listen=api.get("listen", cls.api_listen),
            api_token=api.get("token", ""),
            webhook_url=webhook.get("url", ""),
            webhook_secret=webhook.get("secret", ""),
        )
        if config.backend not in ("core", "blindbit"):
            raise ValueError(f"unknown backend type {config.backend!r}")
        if config.proxy:
            parse_proxy(config.proxy)
        return config

    def make_backend(self):
        from .backends import BlindBitBackend, CoreBackend

        if self.backend == "blindbit":
            host = urlsplit(self.blindbit_url).hostname
            if not self.proxy and host not in ("127.0.0.1", "::1", "localhost"):
                log.warning("the BlindBit server %s sees your IP address; set [backend] "
                            "proxy to reach it over Tor", host)
            return BlindBitBackend(self.blindbit_url, proxy=self.proxy)
        if self.rpc_user:
            return CoreBackend(self.rpc_url, user=self.rpc_user, password=self.rpc_password,
                               proxy=self.proxy)
        return CoreBackend(self.rpc_url, cookie=self.rpc_cookie, proxy=self.proxy)
