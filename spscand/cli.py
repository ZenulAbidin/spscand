"""spscand command line."""

from __future__ import annotations

import argparse
import getpass
import json
import logging
import os
import signal
import sys
import threading
import time
from pathlib import Path

from . import __version__
from .backends import NETWORKS, BackendError
from .bip352 import Receiver, decode_address
from .config import BACKENDS, TEMPLATE, Config
from .secp import N, Point
from .socks import parse_proxy
from .store import Store

log = logging.getLogger("spscand")

# No silent payment output can predate taproot activation on mainnet.
DEFAULT_BIRTHDAY = {"main": 709632}


def _paths(args) -> tuple[Path, Path]:
    datadir = Path(args.datadir).expanduser()
    return datadir / "wallet.sqlite", datadir / "spscand.toml"


def _open(args) -> tuple[Store, Receiver, str]:
    db_path, _ = _paths(args)
    store = Store(db_path)
    network = store.get_meta("network")
    receiver = Receiver(
        int(store.get_meta("scan_secret"), 16),
        Point.parse(bytes.fromhex(store.get_meta("spend_pubkey"))),
        labels=list(store.labels()),
    )
    return store, receiver, network


def _read_scan_key() -> int:
    if sys.stdin.isatty():
        text = getpass.getpass("Scan private key (hex): ")
    else:
        text = sys.stdin.readline()
    try:
        value = int(text.strip(), 16)
    except ValueError:
        raise SystemExit("the scan private key must be 64 hex characters") from None
    if len(text.strip()) != 64 or not 0 < value < N:
        raise SystemExit("the scan private key must be 64 hex characters")
    return value


def cmd_init(args) -> None:
    db_path, config_path = _paths(args)
    if db_path.exists():
        raise SystemExit(f"{db_path} already exists")
    if bool(args.address) == bool(args.spend_pubkey):
        raise SystemExit("give exactly one of --address or --spend-pubkey")
    if args.proxy:
        parse_proxy(args.proxy)
    scan_secret = _read_scan_key()
    if args.address:
        scan_pubkey, spend_pubkey = decode_address(args.address, args.network)
        if scan_pubkey != Point.from_secret(scan_secret):
            raise SystemExit("the scan private key does not belong to this address")
    else:
        spend_pubkey = Point.parse(bytes.fromhex(args.spend_pubkey))
    birthday = args.birthday if args.birthday is not None else DEFAULT_BIRTHDAY.get(args.network, 0)
    store = Store(db_path, create=True)
    with store.transaction():
        store.set_meta("network", args.network)
        store.set_meta("scan_secret", f"{scan_secret:064x}")
        store.set_meta("spend_pubkey", spend_pubkey.serialize().hex())
        store.set_meta("birthday", str(birthday))
    if not config_path.exists():
        config_path.write_text(TEMPLATE.format(**{
            key: json.dumps(value) for key, value in (
                ("backend", args.backend), ("rpc_url", args.rpc_url),
                ("rpc_cookie", args.rpc_cookie), ("blindbit_url", args.blindbit_url),
                ("peers", args.peers), ("proxy", args.proxy),
            )
        }))
        config_path.chmod(0o600)
    receiver = Receiver(scan_secret, spend_pubkey)
    print(f"wallet created in {db_path.parent}, scanning from height {birthday}")
    print(receiver.address(args.network))


def cmd_address(args) -> None:
    store, receiver, network = _open(args)
    if args.label is not None and args.label not in store.labels():
        raise SystemExit(f"label {args.label} is not registered; run 'spscand label add {args.label}'")
    print(receiver.address(network, args.label))


def cmd_label(args) -> None:
    store, receiver, network = _open(args)
    if args.action == "add":
        if not 1 <= args.m < 2**32:
            raise SystemExit("label numbers start at 1 (0 is the change label)")
        store.add_label(args.m, args.comment)
        print(receiver.address(network, args.m))
        if (store.scanned_height() or 0) > int(store.get_meta("birthday")):
            print("note: past blocks were scanned without this label; run "
                  "'spscand rescan' if it was already given out", file=sys.stderr)
    else:
        for m, comment in store.labels().items():
            print(m, receiver.address(network, m), comment)


def cmd_outputs(args) -> None:
    store, _, _ = _open(args)
    tip = store.scanned_height()
    outputs = store.outputs(unspent_only=not args.all)
    print(json.dumps([o.as_dict(tip) for o in outputs], indent=1))
    if not args.all:
        print(f"unspent: {sum(o.amount for o in outputs)} sat", file=sys.stderr)


def cmd_rescan(args) -> None:
    store, _, _ = _open(args)
    height = args.from_height if args.from_height is not None else int(store.get_meta("birthday"))
    with store.transaction():
        store.rewind(height - 1)
    print(f"will rescan from height {height}")


def _close(backend) -> None:
    if hasattr(backend, "close"):
        backend.close()


def _scanner(args, emit=None):
    from .scanner import Scanner

    store, receiver, network = _open(args)
    _, config_path = _paths(args)
    config = Config.load(config_path)
    backend = config.make_backend()
    chain = backend.network()
    if chain != network:
        raise SystemExit(f"the {backend.name} backend is on {chain}, the wallet on {network}")
    return Scanner(store, receiver, backend, emit=emit), config, network


def cmd_sync(args) -> None:
    scanner, _, _ = _scanner(args)
    try:
        count = scanner.sync()
    finally:
        _close(scanner.backend)
    print(f"scanned {count} blocks, now at height {scanner.store.scanned_height()}")


def cmd_run(args) -> None:
    from .api import State, serve
    from .mempool import MempoolWatcher
    from .webhook import Webhook

    db_path, _ = _paths(args)
    scanner, config, network = _scanner(args)
    webhook = None
    if config.webhook_url:
        webhook = Webhook(config.webhook_url, network, secret=config.webhook_secret)
        scanner.emit = webhook

    def addresses():
        labels = scanner.store.labels()
        return [{"label": None, "address": scanner.receiver.address(network)}] + [
            {"label": m, "comment": c, "address": scanner.receiver.address(network, m)}
            for m, c in labels.items()
        ]

    state = State(network, config.backend, addresses())
    state.address_for = lambda m: scanner.receiver.address(network, m)
    watcher = None
    mempool_core = config.make_mempool_source(scanner.backend)
    if mempool_core is not None:
        if mempool_core is not scanner.backend and mempool_core.network() != network:
            raise SystemExit(f"the mempool node is not on {network}")
        watcher = MempoolWatcher(mempool_core, scanner)
        state.mempool = {"source": "core", "transactions": 0, "error": None}
    server = serve(config.api_listen, db_path, state, config.api_token) if config.api_listen else None

    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    log.info("spscand %s watching %s on %s via %s%s", __version__,
             scanner.receiver.address(network), network, config.backend,
             " and the mempool" if watcher else "")
    delay = config.poll_seconds
    next_sync = 0.0
    node_tip = None
    while not stop.is_set():
        labels = sorted(scanner.store.labels())
        if labels != sorted(set(scanner.receiver.labels)):
            scanner.receiver = Receiver(scanner.receiver.scan_secret,
                                        scanner.receiver.spend_pubkey, labels=labels)
            state.addresses = addresses()
        new_block = False
        # Scan a new block at once only when the mempool node is also the block
        # source: a BlindBit server or filter peers may not have indexed it yet.
        if watcher and mempool_core is scanner.backend:
            try:
                tip = watcher.core.call("getblockcount")
                new_block, node_tip = tip != node_tip, tip
            except BackendError:
                pass  # reported by the poll below
        if new_block or time.monotonic() >= next_sync:
            try:
                scanner.sync(stop)
                with state.lock:
                    state.tip, state.error = scanner.tip, None
                delay = config.poll_seconds
            except BackendError as exc:
                log.error("%s", exc)
                with state.lock:
                    state.error = str(exc)
                delay = min(max(delay * 2, 5), 300)
            next_sync = time.monotonic() + delay
        if watcher and not stop.is_set():
            try:
                watcher.poll()
                with state.lock:
                    state.mempool = {"source": "core", "transactions": len(watcher.known),
                                     "error": None}
            except BackendError as exc:
                log.error("mempool: %s", exc)
                with state.lock:
                    state.mempool = dict(state.mempool, error=str(exc))
        wait = next_sync - time.monotonic()
        stop.wait(max(0.0, min(wait, config.mempool_poll_seconds) if watcher else wait))
    _close(scanner.backend)
    if mempool_core is not None and mempool_core is not scanner.backend:
        _close(mempool_core)
    if server:
        server.shutdown()
    if webhook:
        webhook.close()
    log.info("stopped")


def cmd_web(args) -> None:
    from . import web
    web.run(args)


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(prog="spscand", description="Watch-only BIP352 scanner")
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--datadir", default=os.environ.get("SPSCAND_DATADIR", "~/.spscand"),
                        help="default: $SPSCAND_DATADIR or ~/.spscand")
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init", help="create the wallet (scan key from a prompt or stdin)")
    p.add_argument("--network", required=True, choices=sorted(NETWORKS))
    p.add_argument("--address", help="your silent payment address")
    p.add_argument("--spend-pubkey", help="spend public key, 33-byte hex")
    p.add_argument("--birthday", type=int, help="first block height to scan")
    p.add_argument("--backend", choices=BACKENDS, default="core")
    p.add_argument("--rpc-url", default="http://127.0.0.1:8332")
    p.add_argument("--rpc-cookie", default="~/.bitcoin/.cookie")
    p.add_argument("--blindbit-url", default="http://127.0.0.1:8000")
    p.add_argument("--peer", action="append", default=[], dest="peers", metavar="HOST:PORT",
                   help="P2P peer for the filters backend, host:port (repeatable)")
    p.add_argument("--proxy", default="", help="SOCKS5 proxy, e.g. socks5h://127.0.0.1:9050")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("run", help="scan continuously and serve the API")
    p.set_defaults(func=cmd_run)
    p = sub.add_parser("sync", help="scan to the current tip and exit")
    p.set_defaults(func=cmd_sync)

    p = sub.add_parser("address", help="print the receiving address")
    p.add_argument("--label", type=int)
    p.set_defaults(func=cmd_address)

    p = sub.add_parser("label", help="add or list labels")
    labels = p.add_subparsers(dest="action", required=True)
    add = labels.add_parser("add")
    add.add_argument("m", type=int)
    add.add_argument("--comment", default="")
    labels.add_parser("list")
    p.set_defaults(func=cmd_label)

    p = sub.add_parser("outputs", help="list found outputs (unspent by default)")
    p.add_argument("--all", action="store_true")
    p.set_defaults(func=cmd_outputs)

    p = sub.add_parser("rescan", help="scan again from a height (default: the birthday)")
    p.add_argument("--from", dest="from_height", type=int)
    p.set_defaults(func=cmd_rescan)

    p = sub.add_parser("web", help="public scanning service: web page, block data, scan jobs")
    p.add_argument("--listen", default="127.0.0.1:7352")
    p.add_argument("--blindbit-url", default="http://127.0.0.1:8000",
                   help="BlindBit Oracle v2 with a full tweak index (mainnet)")
    p.add_argument("--cache", default="~/.spscand/blocks.sqlite", help="block cache (SQLite)")
    p.add_argument("--static", default=str(Path(__file__).resolve().parent.parent / "web"),
                   help="directory with the web page")
    p.add_argument("--rpc-url", default="http://127.0.0.1:8332")
    p.add_argument("--rpc-cookie", default="", help="Bitcoin Core cookie, for spent status")
    p.add_argument("--sync-workers", type=int, default=3)
    p.add_argument("--fill-from", type=int, default=709632,
                   help="lowest height the cache fills in the background (default: taproot "
                        "activation); older blocks are fetched when asked for")
    p.add_argument("--job-workers", type=int, default=2, help="server scans run at once")
    p.add_argument("--job-threads", type=int, default=4, help="threads per server scan")
    p.set_defaults(func=cmd_web)

    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    try:
        args.func(args)
    except (BackendError, OSError, ValueError) as exc:
        raise SystemExit(f"spscand: {exc}") from None
