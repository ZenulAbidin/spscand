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
- One block source:
  - **Bitcoin Core 25+** with RPC. It needs block undo data, so a pruned node works only above its
    prune height.
  - **A BlindBit Oracle v2 server** with a full tweak index (`tweaks_full_basic = 1`). For Bitcoin
    Core 31 it must be blindbit-oracle at `f9ab7fd` or later.

## Setup

```bash
pip install .
spscand init --network main --address sp1q... --birthday 870000
```

`init` reads the scan private key (64 hex characters, derived at `m/352'/0'/0'/1'/0`) from a prompt or
stdin. Set `--birthday` to the height of your first payment; the default is taproot activation. Then
choose the backend in `~/.spscand/spscand.toml` and start the scanner:

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

To use Tor, set `proxy = "socks5h://127.0.0.1:9050"` under `[backend]` (or `init --proxy`); it also works
for a remote Core node. Tor resolves host names, including `.onion`, and proxy environment variables
are ignored. Each process uses random SOCKS credentials, so Tor gives it circuits of its own
(`IsolateSOCKSAuth`).

Cost with BlindBit, measured on mainnet block 833044 (721 eligible transactions): about 135 kB gzipped
per block (roughly 0.6 GB a month) and 0.07 s of CPU, or 0.15 s with 10 labels. BlindBit does not say
which transaction a tweak belongs to, so each label costs a point addition per tweak: 1000 labels take
about 7 s per block, against 0.14 s with Core.

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
| `GET /v1/status` | network, backend, scanned height, tip, last error |
| `GET /v1/addresses` | the address and each label's address |
| `GET /v1/outputs[?unspent=1]` | found outputs with confirmations |
| `GET /v1/balance[?min_conf=N]` | unspent total in satoshis |

## Webhook

With `[webhook] url` set, spscand POSTs `{"event", "network", "time", "data"}` for `output.received`,
`output.spent`, `output.reorged` (its block was reorged out) and `output.unspent` (its spend was reorged
out); `data` is the output. With a `secret`, the body is signed in `X-Spscand-Signature: sha256=<HMAC-SHA256 hex>`. Failed
deliveries are retried for about 6 minutes.

## Limits

- Confirmed blocks only: mempool payments are not reported.
- With BlindBit, spends are matched by an 8-byte key prefix, and the spending txid is unknown.
- BlindBit has deprecated its JSON API in favour of gRPC, but spscand uses the JSON API.
- There is no BIP157/158 mode. BlindBit serves no filters, and fetching only the blocks that match one
  would tell the server which blocks pay you.
- A reorg deeper than 1000 blocks stops the scanner until you run `rescan`.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

These run the official vectors, a check of mainnet block 833044 against a real BlindBit index (also over
SOCKS5 under a `.onion` name), and the scanner logic. The end-to-end test pays spscand on regtest from
the BIP352 reference sender with P2WPKH, P2SH-P2WPKH, P2PKH and P2TR inputs, then checks labels,
spending, spend detection, reorgs, rescans, the API and the webhook:

```bash
python3 tests/regtest_e2e.py --bitcoin-conf /path/to/regtest/bitcoin.conf --workdir ~/spscand-e2e
```

`--backend blindbit --blindbit-url URL` runs it against a BlindBit server (`tests/fake_blindbit.py`
serves BlindBit's JSON from the regtest node). `--via-socks` routes the backend through a test SOCKS5
server and checks that nothing bypassed it.

## License

MIT. `tests/reference` holds unmodified files from bitcoin/bips (see its README).
