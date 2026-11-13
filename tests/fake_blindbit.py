#!/usr/bin/env python3
"""A stand-in for BlindBit Oracle v2 on regtest, for tests only.

Serves /info, /tweaks/:height, /utxos/:height and /spent-outputs/:height in
the shapes of blindbit-oracle's internal/server (commit bd17922), computed from a regtest
Bitcoin Core node. Its tweaks come from spscand's own code, so it tests the
HTTP backend, spend and reorg handling, not tweak derivation (the mainnet
fixture test covers that against real BlindBit output).

    python3 tests/fake_blindbit.py --bitcoin-conf ~/regtest/bitcoin.conf --port 18900
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from regtest_e2e import Node  # noqa: E402

from spscand.backends import CoreBackend  # noqa: E402


def tweaks_and_utxos(core: CoreBackend, height: int) -> tuple[dict, dict]:
    block = core.block(height)
    ident = {"block_hash": block.hash, "block_height": height}
    tweaks = [t.serialize().hex() for g in block.groups for t in g.tweaks]
    utxos = [{"txid": o.txid, "vout": o.vout, "amount": o.amount, "pubkey": o.key.hex()}
             for g in block.groups for o in g.outputs]
    return {"block_identifier": ident, "index": tweaks}, {"block_identifier": ident, "index": utxos}


def spent_outputs(core: CoreBackend, height: int) -> dict:
    data = core.call("getblock", core.block_hash(height), 3)
    prefixes = [
        vin["prevout"]["scriptPubKey"]["hex"][4:20]
        for tx in data["tx"] for vin in tx["vin"]
        if "prevout" in vin and len(vin["prevout"]["scriptPubKey"]["hex"]) == 68
        and vin["prevout"]["scriptPubKey"]["hex"].startswith("5120")
    ]
    return {"block_identifier": {"block_hash": data["hash"], "block_height": height},
            "index": prefixes}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bitcoin-conf", type=Path, required=True)
    parser.add_argument("--port", type=int, default=18900)
    args = parser.parse_args()
    core = Node(args.bitcoin_conf).rpc()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            try:
                if self.path == "/info":
                    body = {"network": "regtest", "height": core.tip(), "tweaks_only": False,
                            "tweaks_full_basic": True, "tweaks_full_with_dust_filter": False,
                            "tweaks_cut_through_with_dust_filter": False}
                elif m := re.fullmatch(r"/(tweaks|utxos)/(\d+)", self.path):
                    body = tweaks_and_utxos(core, int(m[2]))[m[1] == "utxos"]
                elif m := re.fullmatch(r"/spent-outputs/(\d+)", self.path):
                    body = spent_outputs(core, int(m[1]))
                else:
                    self.send_error(404)
                    return
                status = 200
            except Exception as exc:  # BlindBit's error shape
                body, status = {"success": False, "data": {"error": str(exc)}}, 500
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    ThreadingHTTPServer(("127.0.0.1", args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
