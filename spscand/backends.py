"""Block sources: a Bitcoin Core node, or a BlindBit Oracle v2 tweak server."""

from __future__ import annotations

import base64
import gzip
import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from decimal import Decimal
from pathlib import Path

from .bip352 import InvalidScalarError, TxInput, tweak_point
from .secp import Point
from .socks import socks_opener

# Chain names as reported by Core's getblockchaininfo.
NETWORKS = {"main", "test", "testnet4", "signet", "regtest"}
_BLINDBIT_NETWORKS = {"main": "main", "mainnet": "main", "testnet": "test",
                      "testnet3": "test", "testnet4": "testnet4",
                      "signet": "signet", "regtest": "regtest"}


class BackendError(RuntimeError):
    pass


@dataclass(frozen=True)
class TaprootOutput:
    txid: str
    vout: int
    amount: int
    key: bytes  # x-only


@dataclass
class ScanGroup:
    """Tweaks to try against a set of taproot outputs.

    Core gives one group per transaction. BlindBit's /tweaks does not say which
    transaction a tweak belongs to, so there every tweak of the block is tried
    against every output of the block (a match with another transaction's
    output would need a hash collision). That costs one point addition per
    tweak and label, so many labels are much slower with BlindBit.
    """

    tweaks: list[Point]
    outputs: list[TaprootOutput]


@dataclass
class Block:
    height: int
    hash: str
    prev_hash: str | None  # None if the backend does not report it
    groups: list[ScanGroup]
    # Spends in this block, by outpoint (Core) or by 8-byte x-only key prefix (BlindBit).
    spent_outpoints: dict[tuple[str, int], str] = field(default_factory=dict)
    spent_prefixes: set[bytes] = field(default_factory=set)


class _Http:
    def __init__(self, proxy: str, timeout: float) -> None:
        self.opener = socks_opener(proxy) if proxy else urllib.request.build_opener()
        self.timeout = timeout

    def json(self, request: urllib.request.Request):
        request.add_header("Accept-Encoding", "gzip")
        status = None
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                body, headers = response.read(), response.headers
        except urllib.error.HTTPError as exc:  # error bodies are JSON too
            body, headers, status = exc.read(), exc.headers, exc.code
        except OSError as exc:
            raise BackendError(f"cannot reach {request.full_url}: {exc}") from None
        if headers.get("Content-Encoding") == "gzip":
            body = gzip.decompress(body)
        try:
            return json.loads(body, parse_float=Decimal)
        except ValueError:
            problem = f"HTTP {status}" if status else "non-JSON response"
            raise BackendError(f"{problem} from {request.full_url}") from None


class CoreBackend:
    """Bitcoin Core JSON-RPC (>= 25, for getblock verbosity 3). Computes tweaks locally."""

    name = "core"

    def __init__(self, url: str, *, cookie: str | None = None, user: str | None = None,
                 password: str | None = None, proxy: str = "", timeout: float = 120) -> None:
        self.url = url
        self.cookie = Path(cookie).expanduser() if cookie else None
        self.user, self.password = user, password
        self.http = _Http(proxy, timeout)
        self._id = 0

    def _auth(self) -> str:
        if self.cookie is not None:
            try:
                credentials = self.cookie.read_text().strip()
            except OSError as exc:
                raise BackendError(f"cannot read RPC cookie {self.cookie}: {exc}") from None
        elif self.user is not None:
            credentials = f"{self.user}:{self.password or ''}"
        else:
            raise BackendError("no RPC credentials configured")
        return "Basic " + base64.b64encode(credentials.encode()).decode()

    def call(self, method: str, *params):
        self._id += 1
        request = urllib.request.Request(
            self.url,
            data=json.dumps({"jsonrpc": "1.0", "id": self._id, "method": method,
                             "params": list(params)}).encode(),
            headers={"Content-Type": "application/json", "Authorization": self._auth()},
        )
        reply = self.http.json(request)
        if not isinstance(reply, dict):
            raise BackendError(f"bad RPC reply to {method}")
        if reply.get("error"):
            raise BackendError(f"{method}: {reply['error'].get('message', reply['error'])}")
        return reply["result"]

    def network(self) -> str:
        version = self.call("getnetworkinfo")["version"]
        if version < 250000:
            raise BackendError("Bitcoin Core 25.0 or newer is required")
        chain = self.call("getblockchaininfo")["chain"]
        if chain not in NETWORKS:
            raise BackendError(f"unknown chain {chain!r}")
        return chain

    def tip(self) -> int:
        return self.call("getblockcount")

    def block_hash(self, height: int) -> str:
        return self.call("getblockhash", height)

    def block(self, height: int) -> Block:
        data = self.call("getblock", self.block_hash(height), 3)
        block = Block(height, data["hash"], data.get("previousblockhash"), [])
        for tx in data["tx"]:
            if "coinbase" in tx["vin"][0]:
                continue
            for vin in tx["vin"]:
                block.spent_outpoints[(vin["txid"], vin["vout"])] = tx["txid"]
            outputs = [
                TaprootOutput(tx["txid"], out["n"], int(out["value"] * 100_000_000),
                              bytes.fromhex(spk[4:]))
                for out in tx["vout"]
                if len(spk := out["scriptPubKey"]["hex"]) == 68 and spk.startswith("5120")
            ]
            if not outputs:
                continue
            try:
                inputs = [
                    TxInput(
                        txid=vin["txid"],
                        vout=vin["vout"],
                        script_sig=bytes.fromhex(vin["scriptSig"]["hex"]),
                        witness=tuple(bytes.fromhex(w) for w in vin.get("txinwitness", ())),
                        prevout_script=bytes.fromhex(vin["prevout"]["scriptPubKey"]["hex"]),
                    )
                    for vin in tx["vin"]
                ]
            except KeyError:
                raise BackendError(
                    f"block {height} lacks prevout data (is the node pruned below it?)"
                ) from None
            try:
                tweak = tweak_point(inputs)
            except InvalidScalarError:
                tweak = None
            if tweak is not None:
                block.groups.append(ScanGroup([tweak], outputs))
        return block


class BlindBitBackend:
    """BlindBit Oracle v2 HTTP API.

    Every block from the birthday on is fetched whole (/tweaks, /utxos and
    /spent-outputs), so the server learns nothing about which outputs are ours.
    """

    name = "blindbit"

    def __init__(self, url: str, *, proxy: str = "", timeout: float = 120) -> None:
        self.url = url.rstrip("/")
        self.http = _Http(proxy, timeout)

    def _get(self, path: str):
        body = self.http.json(urllib.request.Request(self.url + path))
        if not isinstance(body, dict):
            raise BackendError(f"{path}: unexpected response")
        if body.get("success") is False:  # {"success": false, "data": {"error": ...}}
            raise BackendError(f"{path}: {(body.get('data') or {}).get('error', 'error')}")
        if "error" in body:
            raise BackendError(f"{path}: {body['error']}")
        return body

    def _indexed(self, path: str, height: int) -> tuple[str, list]:
        body = self._get(f"{path}/{height}")
        ident = body.get("block_identifier") or {}
        if ident.get("block_height") != height or not isinstance(ident.get("block_hash"), str):
            raise BackendError(f"bad block_identifier in {path}/{height}")
        return ident["block_hash"], body.get("index") or []

    def network(self) -> str:
        info = self._get("/info")
        name = info.get("network")
        if name not in _BLINDBIT_NETWORKS:
            raise BackendError(f"unknown network {name!r}")
        # A cut-through index drops spent outputs, which would hide payments
        # that were spent before we scanned their block.
        if not (info.get("tweaks_full_basic") or info.get("tweaks_full_with_dust_filter")):
            raise BackendError("the BlindBit server keeps no full tweak index "
                               "(enable tweaks_full_basic)")
        return _BLINDBIT_NETWORKS[name]

    def tip(self) -> int:
        height = self._get("/info").get("height")
        if not isinstance(height, int):
            raise BackendError("/info has no height")
        return height

    def block_hash(self, height: int) -> str:
        return self._indexed("/spent-outputs", height)[0]

    def block(self, height: int) -> Block:
        tweaks_hash, tweaks = self._indexed("/tweaks", height)
        utxos_hash, utxos = self._indexed("/utxos", height)
        spent_hash, spent = self._indexed("/spent-outputs", height)
        if not tweaks_hash == utxos_hash == spent_hash:
            raise BackendError(f"block {height} changed while fetching it")
        points = []
        for tweak in tweaks:
            if not tweak.strip("0"):
                continue
            try:
                points.append(Point.parse(bytes.fromhex(tweak)))
            except ValueError:
                raise BackendError(f"invalid tweak in block {height}") from None
        outputs = [TaprootOutput(u["txid"], u["vout"], u["amount"], bytes.fromhex(u["pubkey"]))
                   for u in utxos]
        return Block(height, tweaks_hash, None, [ScanGroup(points, outputs)],
                     spent_prefixes={bytes.fromhex(p) for p in spent})
