#!/usr/bin/env python3
"""End-to-end test of spscand against a regtest Bitcoin Core node.

Payments are built with the BIP352 reference implementation (tests/reference),
signed by Core's wallet, mined, and then found by spscand run as a subprocess.

Needs a regtest bitcoind (>= 25) with a funded wallet (default: "miner"):

    python3 tests/regtest_e2e.py --bitcoin-conf ~/regtest/bitcoin.conf \
        --workdir ~/spscand-e2e [--backend blindbit --blindbit-url URL] [--via-socks]

--backend filters starts a second regtest node with blockfilterindex and
peerblockfilters, peered with the first, plus tests/fake_blindbit.py reading
from it; spscand then gets tweaks from that and filters and blocks over P2P.

--via-socks sends spscand's backend traffic through a local SOCKS5 server under
.onion names, and checks that no request bypassed it.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import re
import secrets
import shutil
import subprocess
import sys
import threading
import time
import urllib.request
from decimal import Decimal
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests" / "reference"))

import reference  # noqa: E402  (BIP352 reference sender)
from bitcoin_utils import COutPoint, deser_txid  # noqa: E402
from secp256k1lab.secp256k1 import Scalar  # noqa: E402

from socks_server import SocksServer  # noqa: E402
from spscand import bech32  # noqa: E402
from spscand.backends import CoreBackend  # noqa: E402
from spscand.bip352 import Receiver, label_tweak, tagged_hash  # noqa: E402
from spscand.secp import N, Point  # noqa: E402

COIN = Decimal(100_000_000)
FEE = Decimal("0.0001")
PAY = Decimal("0.1")


def wif(secret: int) -> str:
    payload = b"\xef" + secret.to_bytes(32, "big") + b"\x01"
    data = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    value, out = int.from_bytes(data, "big"), ""
    while value:
        value, rem = divmod(value, 58)
        out = alphabet[rem] + out
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + out


def p2tr_address(xonly: bytes) -> str:
    return bech32.encode("bcrt", 1, xonly)


def taproot_output_secret(secret: int) -> int:
    """Secret of the BIP86-style key-path output key for internal key secret*G."""
    point = Point.from_secret(secret)
    if point.serialize()[0] == 3:
        secret = N - secret
    tweak = int.from_bytes(tagged_hash("TapTweak", point.xonly()), "big")
    return (secret + tweak) % N


class Node:
    def __init__(self, conf: Path) -> None:
        values = {}
        for line in conf.read_text().splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                key, _, value = line.partition("=")
                values[key.strip()] = value.strip()
        self.user, self.password = values["rpcuser"], values["rpcpassword"]
        self.base = f"http://127.0.0.1:{values.get('rpcport', 18443)}"
        self.p2p_port = int(values.get("port", 18444))

    def rpc(self, wallet: str | None = None) -> CoreBackend:
        url = self.base + (f"/wallet/{wallet}" if wallet else "")
        return CoreBackend(url, user=self.user, password=self.password)


class FilterNode:
    """A second regtest node serving BIP157 filters, following the first, and a
    fake BlindBit reading from it (so the tweak server is never ahead of it)."""

    def __init__(self, workdir: Path, node: Node) -> None:
        self.dir = workdir / "filternode"
        shutil.rmtree(self.dir, ignore_errors=True)
        self.dir.mkdir(parents=True)
        self.p2p_port = 19000 + secrets.randbelow(1000)
        rpc_port = 20000 + secrets.randbelow(1000)
        self.conf = self.dir / "bitcoin.conf"
        self.conf.write_text(
            "regtest=1\nserver=1\nblockfilterindex=1\npeerblockfilters=1\ndebug=net\n"
            f"[regtest]\nrpcuser=sp\nrpcpassword={secrets.token_hex(8)}\nrpcport={rpc_port}\n"
            f"port={self.p2p_port}\nbind=127.0.0.1\nrpcbind=127.0.0.1\nrpcallowip=127.0.0.1\n"
            f"connect=127.0.0.1:{node.p2p_port}\nlisten=1\n")
        self.proc = subprocess.Popen(["bitcoind", f"-conf={self.conf}", f"-datadir={self.dir}"],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
        self.node = Node(self.conf)
        self.blindbit_port = 18950 + secrets.randbelow(40)
        self.blindbit = None

    def wait(self, best_hash: str, timeout: float = 60) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                rpc = self.node.rpc()
                info = rpc.call("getindexinfo").get("basic block filter index", {})
                if rpc.call("getbestblockhash") == best_hash and info.get("synced"):
                    return
            except Exception:  # still starting
                pass
            time.sleep(0.3)
        raise AssertionError("filter node did not catch up")

    def start_blindbit(self) -> str:
        self.blindbit = subprocess.Popen(
            [sys.executable, str(ROOT / "tests" / "fake_blindbit.py"), "--bitcoin-conf",
             str(self.conf), "--port", str(self.blindbit_port)],
            stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
        url = f"http://127.0.0.1:{self.blindbit_port}"
        deadline = time.time() + 30
        while time.time() < deadline:
            try:
                urllib.request.urlopen(url + "/info", timeout=2).read()
                return url
            except OSError:
                time.sleep(0.2)
        raise AssertionError("fake BlindBit did not start")

    def blocks_served(self) -> list[str]:
        log = (self.dir / "regtest" / "debug.log").read_text()
        return re.findall(r"received getdata for: (?:witness-)?block ([0-9a-f]{64})", log)

    def stop(self) -> None:
        if self.blindbit:
            self.blindbit.terminate()
            self.blindbit.wait(10)
        try:
            self.node.rpc().call("stop")
        except Exception:
            self.proc.terminate()
        self.proc.wait(60)


class Sender:
    """A Core descriptor wallet holding keys whose secrets the test knows."""

    KINDS = {
        "p2wpkh": "wpkh({})",
        "p2sh-p2wpkh": "sh(wpkh({}))",
        "p2pkh": "pkh({})",
        "p2tr": "tr({})",
    }

    def __init__(self, node: Node, miner: str) -> None:
        self.name = "spsend-" + secrets.token_hex(4)
        node.rpc().call("createwallet", self.name, False, True, "", False, True)
        self.wallet = node.rpc(self.name)
        self.miner = node.rpc(miner)
        self.mine_to = self.miner.call("getnewaddress")
        self.secrets: dict[str, int] = {}

    def fund(self, kind: str, amount: Decimal) -> dict:
        secret = secrets.randbelow(N - 1) + 1
        desc = self.wallet.call("getdescriptorinfo", self.KINDS[kind].format(wif(secret)))
        result = self.wallet.call("importdescriptors", [{
            "desc": self.KINDS[kind].format(wif(secret)) + "#" + desc["checksum"],
            "timestamp": "now",
        }])
        assert result[0]["success"], result
        address = self.wallet.call("deriveaddresses", desc["descriptor"])[0]
        txid = self.miner.call("sendtoaddress", address, str(amount))
        vout = next(
            o["n"] for o in self.miner.call("getrawtransaction", txid, True)["vout"]
            if o["scriptPubKey"].get("address") == address
        )
        spend_secret = taproot_output_secret(secret) if kind == "p2tr" else secret
        return {"txid": txid, "vout": vout, "amount": amount, "secret": spend_secret,
                "xonly": kind == "p2tr", "kind": kind}

    def mine(self, count: int = 1) -> list[str]:
        return self.miner.call("generatetoaddress", count, self.mine_to)

    def pay(self, coins: list[dict], recipients: list[dict]) -> str:
        """Pay PAY to each silent payment recipient from exactly these coins."""
        keys = reference.create_outputs(
            [(Scalar(c["secret"]), c["xonly"]) for c in coins],
            [COutPoint(deser_txid(c["txid"]), c["vout"]) for c in coins],
            recipients,
        )
        assert len(keys) == len(recipients), "reference sender produced no outputs"
        outputs = [{p2tr_address(bytes.fromhex(k)): str(PAY)} for k in keys]
        change = sum(c["amount"] for c in coins) - PAY * len(keys) - FEE
        outputs.append({self.mine_to: str(change)})
        raw = self.wallet.call(
            "createrawtransaction",
            [{"txid": c["txid"], "vout": c["vout"]} for c in coins], outputs,
        )
        signed = self.wallet.call("signrawtransactionwithwallet", raw)
        assert signed["complete"], signed
        return self.wallet.call("sendrawtransaction", signed["hex"])


def recipient(receiver: Receiver, label: int | None = None) -> dict:
    spend = receiver.spend_pubkey
    if label is not None:
        spend = spend.add_generator(label_tweak(receiver.scan_secret, label))
    return {
        "address": receiver.address("regtest", label),
        "scan_pub_key": receiver.scan_pubkey.serialize().hex(),
        "spend_pub_key": spend.serialize().hex(),
    }


class Hooks:
    """Collects webhook deliveries and checks their signatures."""

    def __init__(self, secret: str) -> None:
        self.events: list[dict] = []
        hooks = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                want = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
                assert self.headers["X-Spscand-Signature"] == want, "bad webhook signature"
                hooks.events.append(json.loads(body))
                self.send_response(204)
                self.end_headers()

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/hook"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def wait(self, event: str, txid: str, timeout: float = 60) -> dict:
        deadline = time.time() + timeout
        while time.time() < deadline:
            for item in self.events:
                if item["event"] == event and item["data"]["txid"] == txid:
                    return item
            time.sleep(0.2)
        raise AssertionError(f"no {event} webhook for {txid}; got {self.events}")


class Daemon:
    def __init__(self, workdir: Path, args, node: Node, receiver: Receiver, hooks: Hooks,
                 birthday: int, proxy: str = "") -> None:
        self.datadir = workdir / "spscand"
        shutil.rmtree(self.datadir, ignore_errors=True)
        self.datadir.mkdir(parents=True)
        self.port = 17352 + secrets.randbelow(1000)
        self.token = secrets.token_hex(16)
        if args.backend == "blindbit":
            backend = f'type = "blindbit"\nblindbit_url = "{args.blindbit_url}"\n'
        elif args.backend == "filters":
            backend = (f'type = "filters"\nblindbit_url = "{args.blindbit_url}"\n'
                       f"peers = {json.dumps(args.peers)}\n")
        else:
            backend = (f'type = "core"\nrpc_url = "{args.rpc_url or node.base}"\n'
                       f'rpc_user = "{node.user}"\nrpc_password = "{node.password}"\n')
        if proxy:
            backend += f'proxy = "{proxy}"\n'
        (self.datadir / "spscand.toml").write_text(
            f"[backend]\n{backend}\n[scan]\npoll_seconds = 1\n\n"
            f'[api]\nlisten = "127.0.0.1:{self.port}"\ntoken = "{self.token}"\n\n'
            f'[webhook]\nurl = "{hooks.url}"\nsecret = "e2e-secret"\n'
        )
        self.cli("init", "--network", "regtest", "--birthday", str(birthday),
                 "--address", receiver.address("regtest"),
                 stdin=f"{receiver.scan_secret:064x}\n")
        self.cli("label", "add", "1", "--comment", "donations")
        self.log = open(workdir / "spscand.log", "w")
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "spscand", "--datadir", str(self.datadir), "run"],
            cwd=ROOT, stdout=self.log, stderr=subprocess.STDOUT,
        )

    def cli(self, *argv: str, stdin: str | None = None) -> str:
        result = subprocess.run(
            [sys.executable, "-m", "spscand", "--datadir", str(self.datadir), *argv],
            cwd=ROOT, input=stdin, capture_output=True, text=True,
        )
        if result.returncode:
            raise AssertionError(f"spscand {argv[0]} failed: {result.stderr}")
        return result.stdout

    def api(self, path: str):
        request = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}",
            headers={"Authorization": f"Bearer {self.token}"},
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            return json.loads(response.read())

    def wait_synced(self, height: int, timeout: float = 60) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise AssertionError("spscand exited; see spscand.log")
            try:
                status = self.api("/v1/status")
                if status["scanned_height"] == height and status["synced"]:
                    return
            except OSError:
                pass
            time.sleep(0.3)
        raise AssertionError(f"spscand did not reach height {height}")

    def stop(self) -> None:
        self.proc.terminate()
        self.proc.wait(20)
        self.log.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bitcoin-conf", type=Path, required=True)
    parser.add_argument("--workdir", type=Path, required=True)
    parser.add_argument("--miner-wallet", default="miner")
    parser.add_argument("--backend", choices=("core", "blindbit", "filters"), default="core")
    parser.add_argument("--blindbit-url", default="http://127.0.0.1:8000")
    parser.add_argument("--via-socks", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    args.workdir.mkdir(parents=True, exist_ok=True)

    node = Node(args.bitcoin_conf)
    chain = node.rpc()
    assert chain.call("getblockchaininfo")["chain"] == "regtest"
    sender = Sender(node, args.miner_wallet)
    receiver = Receiver(secrets.randbelow(N - 1) + 1,
                        Point.from_secret(spend_secret := secrets.randbelow(N - 1) + 1))
    stranger = Receiver(secrets.randbelow(N - 1) + 1, Point.from_secret(5))
    hooks = Hooks("e2e-secret")
    results: dict = {"backend": args.backend, "via_socks": args.via_socks, "checks": []}
    args.rpc_url = None
    filter_node = None
    if args.backend == "filters":
        filter_node = FilterNode(args.workdir, node)
        filter_node.wait(chain.call("getbestblockhash"))
        args.blindbit_url = filter_node.start_blindbit()
        args.peers = [f"127.0.0.1:{filter_node.p2p_port}"]
    socks = None
    onions = set()
    if args.via_socks:
        onion = "spscande2e" + "x" * 46 + ".onion"
        real = urlsplit(args.blindbit_url if args.backend != "core" else node.base)
        names = {onion: (real.hostname, real.port)}
        if args.backend == "blindbit":
            args.blindbit_url = f"http://{onion}:{real.port}"
        elif args.backend == "filters":
            args.blindbit_url = f"http://{onion}:{real.port}"
            peer_onion = "spscandpeer" + "x" * 45 + ".onion"
            names[peer_onion] = ("127.0.0.1", filter_node.p2p_port)
            args.peers = [f"{peer_onion}:{filter_node.p2p_port}"]
        else:
            args.rpc_url = f"http://{onion}:{real.port}"
        socks = SocksServer(names)
        onions = set(names)

    def check(name: str, condition: bool, detail="") -> None:
        results["checks"].append({"check": name, "ok": bool(condition)})
        print(("PASS " if condition else "FAIL ") + name, detail if not condition else "")
        if not condition:
            raise SystemExit(1)

    coins = {kind: sender.fund(kind, Decimal(1)) for kind in Sender.KINDS}
    extra = sender.fund("p2wpkh", Decimal(1))
    sender.mine()
    birthday = chain.tip()  # payments start in the next block
    daemon = Daemon(args.workdir, args, node, receiver, hooks, birthday,
                    socks.url if socks else "")
    try:
        payments = {
            "p2wpkh to address": sender.pay([coins["p2wpkh"]], [recipient(receiver)]),
            "p2tr to label 1": sender.pay([coins["p2tr"]], [recipient(receiver, 1)]),
            "p2pkh + p2sh-p2wpkh, two outputs + change label":
                sender.pay([coins["p2pkh"], coins["p2sh-p2wpkh"]],
                           [recipient(receiver), recipient(receiver), recipient(receiver, 0)]),
            "someone else": sender.pay([extra], [recipient(stranger)]),
        }
        sender.mine()
        height = chain.tip()
        daemon.wait_synced(height)
        payment_block = chain.block_hash(height)
        outputs = daemon.api("/v1/outputs")
        by_tx: dict[str, list] = {}
        for o in outputs:
            by_tx.setdefault(o["txid"], []).append(o)
        pay_sat = int(PAY * COIN)
        check("p2wpkh input found", [o["label"] for o in by_tx.get(payments["p2wpkh to address"], [])] == [None])
        check("p2tr input, label 1 found", [o["label"] for o in by_tx.get(payments["p2tr to label 1"], [])] == [1])
        multi = by_tx.get(payments["p2pkh + p2sh-p2wpkh, two outputs + change label"], [])
        check("p2pkh + p2sh-p2wpkh: three outputs incl. change label",
              sorted(str(o["label"]) for o in multi) == ["0", "None", "None"], multi)
        check("other receiver's payment ignored", payments["someone else"] not in by_tx)
        check("amounts", all(o["amount"] == pay_sat for o in outputs), outputs)
        check("tweaks spend", all(
            Point.from_secret((spend_secret + int(o["tweak"], 16)) % N).xonly().hex() == o["pubkey"]
            for o in outputs))
        balance = daemon.api("/v1/balance")
        check("balance", balance["balance"] == 5 * pay_sat, balance)
        for txid in payments.values():
            if txid != payments["someone else"]:
                hooks.wait("output.received", txid)
        check("webhooks signed and delivered", True)

        # An offline Core signs with the derived key alone.
        other = by_tx[payments["p2wpkh to address"]][0]
        raw = chain.call(
            "createrawtransaction", [{"txid": other["txid"], "vout": other["vout"]}],
            [{sender.mine_to: str(PAY - FEE)}],
        )
        signed = chain.call("signrawtransactionwithkey", raw,
                            [wif((spend_secret + int(other["tweak"], 16)) % N)],
                            [{"txid": other["txid"], "vout": other["vout"],
                              "scriptPubKey": "5120" + other["pubkey"],
                              "amount": float(PAY)}])
        check("signrawtransactionwithkey signs a found output",
              signed["complete"]
              and chain.call("testmempoolaccept", [signed["hex"]])[0]["allowed"], signed)

        # Spend one output with the key a spending wallet would derive.
        target = by_tx[payments["p2tr to label 1"]][0]
        spend_key = (spend_secret + int(target["tweak"], 16)) % N
        spender = sender.wallet
        desc = spender.call("getdescriptorinfo", f"rawtr({wif(spend_key)})")
        spender.call("importdescriptors", [{
            "desc": f"rawtr({wif(spend_key)})#{desc['checksum']}", "timestamp": 0}])
        raw = spender.call(
            "createrawtransaction", [{"txid": target["txid"], "vout": target["vout"]}],
            [{sender.mine_to: str(PAY - FEE)}],
        )
        signed = spender.call("signrawtransactionwithwallet", raw)
        check("found output is spendable", signed["complete"], signed)
        spend_txid = spender.call("sendrawtransaction", signed["hex"])
        sender.mine()
        daemon.wait_synced(chain.tip())
        spent = next(o for o in daemon.api("/v1/outputs") if o["txid"] == target["txid"])
        expected_spender = None if args.backend == "blindbit" else spend_txid
        check("spend detected", spent["spent_height"] == chain.tip()
              and spent["spent_txid"] == expected_spender, spent)
        hooks.wait("output.spent", target["txid"])

        # Reorg: a payment's block is replaced by an empty one, then re-mined.
        reorg_txid = sender.pay([sender.fund("p2wpkh", Decimal(1))], [recipient(receiver)])
        if not chain.call("getrawmempool"):
            raise AssertionError("payment not in mempool")
        sender.mine()  # mines both the funding and the payment
        reorg_height = chain.tip()
        daemon.wait_synced(reorg_height)
        check("payment before reorg", any(o["txid"] == reorg_txid for o in daemon.api("/v1/outputs")))
        reorged = {chain.block_hash(reorg_height)}
        chain.call("invalidateblock", chain.block_hash(reorg_height))
        chain.call("generateblock", sender.mine_to, [])
        chain.call("generateblock", sender.mine_to, [])
        daemon.wait_synced(reorg_height + 1)
        hooks.wait("output.reorged", reorg_txid)
        check("reorged payment removed",
              all(o["txid"] != reorg_txid for o in daemon.api("/v1/outputs")))
        sender.mine()
        daemon.wait_synced(reorg_height + 2)
        again = [o for o in daemon.api("/v1/outputs") if o["txid"] == reorg_txid]
        check("payment found again after reorg",
              len(again) == 1 and again[0]["height"] == reorg_height + 2, again)

        # Rescan from the birthday reproduces the same wallet.
        before = sorted((o["txid"], o["vout"], o["spent_height"]) for o in daemon.api("/v1/outputs"))
        daemon.stop()
        daemon.cli("rescan")
        daemon.cli("sync")
        after = json.loads(daemon.cli("outputs", "--all"))
        check("rescan reproduces wallet",
              sorted((o["txid"], o["vout"], o["spent_height"]) for o in after) == before)
        if filter_node:
            wanted = {payment_block, chain.block_hash(spent["spent_height"]),
                      chain.block_hash(reorg_height + 2)} | reorged
            served = filter_node.blocks_served()
            check("only blocks paying or spending ours were downloaded",
                  served and set(served) <= wanted, (sorted(set(served)), sorted(wanted)))
        if socks:
            check("all backend traffic went through SOCKS by name",
                  socks.requests and all(r["kind"] == 3 and r["host"] in onions
                                         for r in socks.requests), socks.requests[:3])
    finally:
        if daemon.proc.poll() is None:
            daemon.stop()
        node.rpc().call("unloadwallet", sender.name)
        if filter_node:
            filter_node.stop()
    print(f"all {len(results['checks'])} checks passed")
    if args.output:
        args.output.write_text(json.dumps(results, indent=1) + "\n")


if __name__ == "__main__":
    main()
