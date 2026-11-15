# spscand

A watch-only scanner for [BIP352](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki)
silent payments (version 1.1.2). It finds payments to your `sp1` address, tracks their spends and
reorgs, and reports them through a local JSON API and a webhook. It holds the scan private key and the
spend public key, so it can see payments but not spend them.

Not audited. Try it with small amounts first.

## Requirements

- Python 3.11+. No Python packages are needed.
- libsecp256k1: `apt install libsecp256k1-1` or `brew install secp256k1`. If it is not found, set
  `SPSCAND_LIBSECP256K1` to its path.
- Recommended: [libspscan](libspscan/), the C scanning library in this repository. Build it with
  `make -C libspscan` (a C compiler is all it needs); spscand finds it in the checkout, after
  `make -C libspscan install`, or at `SPSCAND_LIBSPSCAN`. Without it spscand uses its Python code,
  which is much slower with labels, and the filters backend is unavailable.
- One block source:
  - **Bitcoin Core 25+** with RPC. It needs block undo data, so a pruned node works only above its
    prune height.
  - **A BlindBit Oracle v2 server** with a full tweak index (`tweaks_full_basic = 1`). For Bitcoin
    Core 31 it must be blindbit-oracle at `f9ab7fd` or later.
  - **Filters**: a BlindBit server for tweaks, and Bitcoin P2P peers serving compact filters (Core
    with `blockfilterindex=1` and `peerblockfilters=1`) for filters and blocks.

## Setup

```bash
pip install .
spscand init --network main --address sp1q... --birthday 870000
```

`init` reads the scan private key (64 hex characters, derived at `m/352'/0'/0'/1'/0`) from a prompt or
stdin. Set `--birthday` to the height of your first payment; the default is taproot activation. Then
choose the backend in `~/.spscand/spscand.toml` (or pass `--backend`, `--blindbit-url` and, for
filters, `--peer host:port` once per peer to `init`) and start the scanner:

```bash
spscand run
```

| Command | |
|---|---|
| `init` | create the wallet |
| `run` | scan continuously, serve the API, send webhooks |
| `sync` | scan to the tip once and exit |
| `address [--label M]` | print the address |
| `label add M` / `label list` | register a label and print its address |
| `outputs [--all]` | list unspent (or all) found outputs as JSON |
| `rescan [--from H]` | forget results from height H on and scan again |

`--datadir` or `SPSCAND_DATADIR` sets the data directory (default `~/.spscand`).

## Privacy

With the Core backend, nothing leaves your machine.

With BlindBit, spscand downloads every block from your birthday to the tip in full (`/tweaks`, `/utxos`
and `/spent-outputs`) and matches them locally. It never asks about an address, output or transaction,
so the server cannot tell which payments are yours. It does learn your IP address (unless you use Tor),
your birthday, and when you are online or rescan. It could hide payments by serving incomplete data, so
run your own server if you can.

With filters (BIP157/158, the strategy in BIP352's appendix), spscand takes only `/tweaks` from
BlindBit, again for every block, and the block's basic filter from P2P peers. It computes your possible
output keys, checks them against the filter, and downloads the whole block only on a match, or when the
filter shows one of your outputs being spent. That peer learns that the block interested you, so each
block comes from a randomly chosen peer over a connection of its own. Filter headers are compared
across all reachable peers, so list at least two: a single peer could hide a payment by serving a false
filter. The P2P connection is unencrypted (no BIP324 yet), so prefer `.onion` peers when you use Tor.

To use Tor, set `proxy = "socks5h://127.0.0.1:9050"` under `[backend]` (or `init --proxy`); it also works
for a remote Core node. Tor resolves host names, including `.onion`, and proxy environment variables
are ignored. Each process, and with filters each P2P connection, uses random SOCKS credentials, so Tor
gives it circuits of its own (`IsolateSOCKSAuth`).

Cost per block, measured on mainnet block 833044 (721 eligible transactions, 2105 taproot outputs):

| | Download | CPU with libspscan | CPU in Python |
|---|---|---|---|
| Core | (local) | 0.06 s; 0.08 s with 1000 labels | 0.04 s; 0.10 s |
| BlindBit | 135 kB (about 0.6 GB a month) | 0.05 s; 0.16 s with 1000 labels | 0.07 s; 7.5 s |
| Filters | 28 kB of tweaks + 31 kB of filter (about 0.26 GB a month), plus each matching block | 0.05 s; 0.22 s | not available |

BlindBit does not say which transaction a tweak belongs to, so each label is tried against every
output of the block. With filters, each label also adds items to test, and so false matches: on this
block a needless download (about 1 MB, without witness data) happens with probability 0.2% with no
labels, 1% with 10 and 9% with 100. With hundreds of labels, filters save little. The Core figures are
for matching; computing the tweaks from the block takes another 0.07 s.

## Keys and backups

`wallet.sqlite` is readable only by you, because the scan key it holds reveals every payment to you. To
restore, you need the scan key, your address, the birthday and your label numbers; found outputs can
always be rescanned.

An output's private key is `d = (spend_private_key + tweak) mod n`, and its output key is `d·G` with no
BIP341 tweak. Bitcoin Core, offline if you like, signs with `signrawtransactionwithkey` given the WIF of
`d` and the prevout (`5120<pubkey>`, amount), or from a wallet holding `rawtr(<WIF of d>)`.

The change label (0) is always scanned. Adding a label does not rescan old blocks, so run `rescan` if
its address was already given out. An output paid to one of your found keys outside BIP352 in the same
block (address reuse) is recorded too.

## API

Read-only HTTP on `127.0.0.1:7352`. If `[api] token` is set, send `Authorization: Bearer <token>`.

| Endpoint | |
|---|---|
| `GET /v1/status` | spscand version, network, backend, scanned height, tip, last error, and the mempool watcher (`null` without one) |
| `GET /v1/addresses` | the address and each label's address |
| `GET /v1/outputs[?unspent=1][&since_height=H]` | found outputs with confirmations; with `since_height`, only those received or spent at height H or later (after a reorg, fetch all again) |
| `GET /v1/balance[?min_conf=N]` | unspent total in satoshis, plus `pending_in` and `pending_out` |

Each output has a `status`. A `confirmed` one has a height and confirmations. An `unconfirmed` one
pays us from a transaction still in the mempool: it has `confirmations: 0` and no height, is listed
with every `since_height`, and is not counted in `balance` but in `pending_in`. When its
transaction is mined it is listed again as confirmed; if the transaction leaves the mempool unmined
(replaced, evicted or conflicted) it is no longer listed. `pending_spent_txid` is set while an
unconfirmed transaction spends the output, and `pending_out` sums confirmed outputs spent that way.

## Webhook

With `[webhook] url` set, spscand POSTs `{"event", "network", "time", "data"}` for `output.received`,
`output.spent`, `output.reorged` (its block was reorged out) and `output.unspent` (its spend was reorged
out); `data` is the output. With a `secret`, the body is signed in `X-Spscand-Signature: sha256=<HMAC-SHA256 hex>`. Failed
deliveries are retried for about 6 minutes.

## Public scanning service

`spscand web` runs a public site where anyone can scan their own wallet (it runs
[spscan.bitmixlist.org](https://spscan.bitmixlist.org)). It reads blocks from a BlindBit Oracle v2
server with a full tweak index (`/full-block`), keeps each block's tweaks and a compact filter of its
taproot outputs in a SQLite cache, and serves:

| | |
|---|---|
| `GET /` | the page in [web/](web/) |
| `GET /v1/info` | tip, limits, queue length |
| `GET /v1/blocks?from=H&count=N` | tweaks and output filters for up to 2016 blocks, binary (format in `spscand/web.py`) |
| `GET /v1/outputs?heights=H1,H2,…` | each transaction's tweak and taproot outputs, for up to 32 blocks |
| `POST /v1/jobs` | `{"address", "scan_key", "from", "labels"}`: scan on the server; returns `{"id"}` |
| `GET /v1/jobs/ID`, `DELETE /v1/jobs/ID` | progress and payments (with spent status), or delete them |

The page scans in one of two ways:

- **In the browser** (the default): libspscan compiled to WebAssembly checks every block's tweaks
  against its filter in web workers, and the page asks `/v1/outputs` only for blocks that may pay it,
  each mixed with three decoys. The scan key never leaves the browser. The server learns the start
  height, and roughly which blocks may be interesting among their decoys. About 9 kB of downloads and
  50 ms of CPU per block (1.3 MB and a few seconds per day of history, split across cores).
- **On the server**: the visitor sends the scan key, and a worker scans with the native library. The
  key is kept in memory only (Python cannot promise to wipe its copy), the job and its results are
  dropped within a day, and nothing about visitors is logged. The operator, and a TLS-terminating proxy
  in front, can see the key and so the payments, but never spend them. Spent status comes from Bitcoin
  Core (`--rpc-cookie`).

```bash
make -C libspscan all wasm   # spscan.wasm: needs clang and wasm-ld (LLVM 15 or later)
spscand web --blindbit-url http://127.0.0.1:8000 --cache /var/lib/spscan/blocks.sqlite \
    --rpc-cookie /var/lib/bitcoind/.cookie
```

The cache fills in the background from the tip back to taproot activation (`--fill-from` sets where
it stops; older blocks are fetched when asked for). It needs about 3 GB for all of mainnet. Put a
reverse proxy with TLS and rate limits in front; `contrib/spscan-web.service` is a systemd unit.

## Limits

- Confirmed blocks only: mempool payments are not reported.
- With BlindBit, spends are matched by an 8-byte key prefix, and the spending txid is unknown.
- BlindBit has deprecated its JSON API in favour of gRPC, but spscand uses the JSON API.
- The filters backend still needs BlindBit for tweaks; peers serve only filters and blocks. With it,
  amounts and spends come from the downloaded blocks, so spends report the spending txid.
- A reorg deeper than 1000 blocks stops the scanner until you run `rescan`.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

These run the BIP352 vectors, the WebAssembly build against the native library and the web service
against a fake BlindBit (both need `make -C libspscan wasm` and Node.js; they are skipped otherwise), Core's BIP158 filter vectors, a check of mainnet block 833044 against a
real BlindBit index (also over SOCKS5 under a `.onion` name), the scanner logic, the filters backend
against fake peers (including lying ones), and libspscan against the Python code. They use libspscan
when it is built; `SPSCAND_PURE_PYTHON=1` runs them without it. The end-to-end test pays spscand on
regtest from the BIP352 reference sender with P2WPKH, P2SH-P2WPKH, P2PKH and P2TR inputs, then checks
labels, spending, spend detection, reorgs, rescans, the API and the webhook:

```bash
python3 tests/regtest_e2e.py --bitcoin-conf /path/to/regtest/bitcoin.conf --workdir ~/spscand-e2e
```

`--backend blindbit --blindbit-url URL` runs it against a BlindBit server (`tests/fake_blindbit.py`
serves BlindBit's JSON from the regtest node). `--backend filters` starts a second regtest node serving
filters, and checks that only blocks paying or spending your outputs were downloaded. `--via-socks`
routes the backend through a test SOCKS5 server and checks that nothing bypassed it.

## License

MIT. `tests/reference` holds unmodified files from bitcoin/bips and bitcoin/bitcoin, and
`libspscan/secp256k1` an unmodified libsecp256k1 v0.8.0 (see their READMEs).
