"""Block sources: a Bitcoin Core node, a BlindBit Oracle v2 tweak server, or a
BlindBit server for tweaks plus P2P peers for compact filters and blocks."""

from __future__ import annotations

import base64
import gzip
import json
import secrets
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from decimal import Decimal
from pathlib import Path

from . import p2p
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

    def call_many(self, method: str, params: list[list]) -> list:
        """One JSON-RPC batch of the same method; None where a call failed
        (for example a transaction that just left the mempool)."""
        if not params:
            return []
        first = self._id + 1
        self._id += len(params)
        request = urllib.request.Request(
            self.url,
            data=json.dumps([{"jsonrpc": "1.0", "id": first + i, "method": method,
                              "params": list(p)} for i, p in enumerate(params)]).encode(),
            headers={"Content-Type": "application/json", "Authorization": self._auth()},
        )
        replies = self.http.json(request)
        if not isinstance(replies, list):
            raise BackendError(f"bad RPC batch reply to {method}")
        by_id = {r.get("id"): r for r in replies if isinstance(r, dict)}
        return [by_id.get(first + i, {}).get("result") for i in range(len(params))]

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
            try:
                group = scan_group(tx)
            except KeyError:
                raise BackendError(
                    f"block {height} lacks prevout data (is the node pruned below it?)"
                ) from None
            if group is not None:
                block.groups.append(group)
        return block


def scan_group(tx: dict) -> ScanGroup | None:
    """The tweak and taproot outputs of a transaction in Core's verbose JSON
    (getblock verbosity 3, getrawtransaction verbosity 2), or None if it
    cannot pay a silent payment. KeyError if the prevouts are missing."""
    outputs = [
        TaprootOutput(tx["txid"], out["n"], int(out["value"] * 100_000_000),
                      bytes.fromhex(spk[4:]))
        for out in tx["vout"]
        if len(spk := out["scriptPubKey"]["hex"]) == 68 and spk.startswith("5120")
    ]
    if not outputs:
        return None
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
    try:
        tweak = tweak_point(inputs)
    except InvalidScalarError:
        return None
    return ScanGroup([tweak], outputs) if tweak is not None else None


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

    def tweaks(self, height: int) -> tuple[str, list[Point]]:
        block_hash, tweaks = self._indexed("/tweaks", height)
        points = []
        for tweak in tweaks:
            if not tweak.strip("0"):
                continue
            try:
                points.append(Point.parse(bytes.fromhex(tweak)))
            except ValueError:
                raise BackendError(f"invalid tweak in block {height}") from None
        return block_hash, points

    def block(self, height: int) -> Block:
        tweaks_hash, points = self.tweaks(height)
        utxos_hash, utxos = self._indexed("/utxos", height)
        spent_hash, spent = self._indexed("/spent-outputs", height)
        if not tweaks_hash == utxos_hash == spent_hash:
            raise BackendError(f"block {height} changed while fetching it")
        outputs = [TaprootOutput(u["txid"], u["vout"], u["amount"], bytes.fromhex(u["pubkey"]))
                   for u in utxos]
        return Block(height, tweaks_hash, None, [ScanGroup(points, outputs)],
                     spent_prefixes={bytes.fromhex(p) for p in spent})


class FilterBackend:
    """Tweaks from a BlindBit server; BIP158 filters, and only the blocks whose
    filter matches, from Bitcoin P2P peers (BIP157).

    The tweak server sees every block requested, as with the blindbit backend.
    A peer serving a block learns that the block interested us, so each block
    is fetched from a randomly chosen peer over a connection (and Tor circuit)
    of its own. Filter headers are compared between all reachable peers, so a
    peer serving a false filter is caught unless every peer lies.
    """

    name = "filters"
    BATCH = 1000  # BIP157 allows 1000 filters per request

    def __init__(self, tweak_url: str, peers: list[str], *, proxy: str = "",
                 timeout: float = 120) -> None:
        if not peers:
            raise BackendError("the filters backend needs at least one peer")
        self.tweak_server = BlindBitBackend(tweak_url, proxy=proxy, timeout=timeout)
        self.peer_specs = list(peers)
        self.proxy, self.timeout = proxy, timeout
        self.chain: str | None = None
        self.matcher = None
        self._peers: dict[tuple[str, int], p2p.Peer] = {}
        self._filters: dict[int, tuple[str, bytes]] = {}
        self._last_header: tuple[int, bytes] | None = None

    def set_matcher(self, matcher) -> None:
        """matcher(block_hash, tweaks, filter) -> True if the block may concern us."""
        self.matcher = matcher

    def close(self) -> None:
        for address in list(self._peers):
            self._drop(address)

    def network(self) -> str:
        self.chain = self.tweak_server.network()
        self.addresses = [p2p.parse_peer(p, self.chain) for p in self.peer_specs]
        return self.chain

    def tip(self) -> int:
        return self.tweak_server.tip()

    def block_hash(self, height: int) -> str:
        return self.tweak_server.block_hash(height)

    def _connect(self, address: tuple[str, int]) -> p2p.Peer:
        return p2p.Peer(*address, self.chain, proxy=self.proxy, timeout=self.timeout)

    def _peer(self, address: tuple[str, int]) -> p2p.Peer:
        if address not in self._peers:
            self._peers[address] = self._connect(address)
        return self._peers[address]

    def _drop(self, address: tuple[str, int]) -> None:
        peer = self._peers.pop(address, None)
        if peer is not None:
            peer.close()

    def _fetch_filters(self, start: int) -> None:
        if self.chain is None:
            self.network()
        stop = min(start + self.BATCH - 1, self.tip())
        if stop < start:
            raise BackendError(f"block {start} is beyond the tip")
        stop_hash = self.tweak_server.block_hash(stop)
        headers, errors = {}, []
        for address in self.addresses:
            try:
                headers[address] = self._peer(address).cfheaders(start, stop_hash)
            except OSError as exc:
                self._drop(address)
                errors.append(f"{address[0]}:{address[1]}: {exc}")
        if not headers:
            raise BackendError("no peer served filter headers: " + "; ".join(errors))
        if len(set(map(repr, headers.values()))) > 1:
            raise BackendError(f"peers disagree on the filters of blocks {start}-{stop}: "
                               "one of them is lying, or a reorg is under way")
        address = secrets.choice(sorted(headers))
        prev, hashes = headers[address]
        if len(hashes) != stop - start + 1:
            raise BackendError(f"{address[0]} sent {len(hashes)} filter headers, not {stop - start + 1}")
        if self._last_header and self._last_header[0] == start - 1 and self._last_header[1] != prev:
            raise BackendError(f"filter header chain broken at block {start}")
        try:
            filters = self._peer(address).cfilters(start, stop_hash, len(hashes))
        except OSError as exc:
            self._drop(address)
            raise BackendError(f"fetching filters from {address[0]}: {exc}") from None
        header = prev
        for offset, ((block_hash, data), want) in enumerate(zip(filters, hashes)):
            if p2p.dsha256(data) != want:
                raise BackendError(f"{address[0]} sent a filter for block {start + offset} "
                                   "that does not match its header")
            header = p2p.filter_header(want, header)
            self._filters[start + offset] = (block_hash, data)
        if filters[-1][0] != stop_hash:
            raise BackendError(f"{address[0]} served filters for another chain")
        self._last_header = (stop, header)

    def _filter(self, height: int, block_hash: str) -> bytes:
        for attempt in range(2):
            if height not in self._filters:
                self._fetch_filters(height)
            filter_hash, data = self._filters.pop(height)
            if filter_hash == block_hash:
                return data
            self._filters.clear()  # the chain changed under us
            self._last_header = None
        raise BackendError(f"the tweak server and the peers disagree on block {height}")

    def _download(self, block_hash: str) -> list[p2p.Tx]:
        errors = []
        for address in secrets.SystemRandom().sample(self.addresses, len(self.addresses)):
            try:
                peer = self._connect(address)
                try:
                    raw = peer.block(block_hash)
                finally:
                    peer.close()
                return p2p.parse_block(raw, block_hash)[1]
            except OSError as exc:
                errors.append(f"{address[0]}:{address[1]}: {exc}")
        raise BackendError(f"no peer served block {block_hash}: " + "; ".join(errors))

    def block(self, height: int) -> Block:
        block_hash, tweaks = self.tweak_server.tweaks(height)
        data = self._filter(height, block_hash)
        if self.matcher is None or not self.matcher(block_hash, tweaks, data):
            return Block(height, block_hash, None, [])
        outputs, spent = [], {}
        for tx in self._download(block_hash):
            if tx.coinbase:
                continue
            for outpoint in tx.inputs:
                spent[outpoint] = tx.txid
            outputs += [TaprootOutput(tx.txid, n, value, script[2:])
                        for n, (value, script) in enumerate(tx.outputs)
                        if len(script) == 34 and script[:2] == b"\x51\x20"]
        return Block(height, block_hash, None, [ScanGroup(tweaks, outputs)], spent_outpoints=spent)
