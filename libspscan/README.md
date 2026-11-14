# libspscan

A C library for receiving [BIP352](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki)
silent payments (version 1.1.2): it finds a wallet's outputs in block data and checks
[BIP158](https://github.com/bitcoin/bips/blob/master/bip-0158.mediawiki) compact filters
for the light-client strategy in BIP352's appendix. It does no I/O, holds no spend
private key, and has no dependencies beyond the C standard library, so it can sit under
a daemon, a wallet or an indexer in any language. spscand uses it through ctypes.

Not audited.

## Build

```bash
make            # libspscan.so and libspscan.a
make check      # internal checks, built with libsecp256k1's VERIFY assertions
make install    # PREFIX=/usr/local; installs spscan.h and libspscan.pc
make wasm       # spscan.wasm, for browsers (clang and wasm-ld, LLVM 15 or later)
```

`spscan.wasm` is a freestanding wasm32 build with no imports: [`wasm/libc.c`](wasm/libc.c)
supplies the few C library functions it needs (a small allocator, `mem*`, `qsort`).
[`../web/spscan.js`](../web/spscan.js) is a JavaScript binding for browsers and Node.js, and
`tests/test_wasm.py` checks it against the native library. On wasm32 the field arithmetic uses
libsecp256k1's 32-bit code (`USE_FORCE_WIDEMUL_INT64`), which is about three times faster
there than its emulated 128-bit code: roughly 0.2 ms per tweak in a current browser.

The API is in [`include/spscan.h`](include/spscan.h):

| Function | |
|---|---|
| `spscan_receiver_create` | scan key, spend public key and labels; the change label is added unless `SPSCAN_NO_CHANGE_LABEL` |
| `spscan_receiver_scan_pubkey` | the receiver's scan public key, to check a scan key against an address |
| `spscan_scan` | try tweaks against a set of taproot outputs; one transaction or a whole block |
| `spscan_tweak_from_inputs` | `input_hash·A` from a transaction's inputs and prevouts, for full nodes and indexers |
| `spscan_filter_check` | may a block with this basic filter pay the receiver? |
| `spscan_gcs_match_any`, `spscan_gcs_build` | BIP158 basic filters |

The BIP352 receiving vectors and Core's BIP158 vectors run from spscand's
`tests/test_native.py` and `tests/test_filters.py`, which also compare every result with
spscand's Python implementation.

## Design notes

- **Bundled libsecp256k1.** `secp256k1/` is libsecp256k1 v0.8.0 (tag signed by Sebastian
  Falbesoner, commit `6e2c8bc4ecdc6e71dbe7a368f360d8d453ce435d`), unmodified; check it with
  `git clone -b v0.8.0 https://github.com/bitcoin-core/secp256k1 && diff -r --exclude=.git
  secp256k1 libspscan/secp256k1`. It is compiled into the same translation unit
  (`src/spscan.c`), so label matching can use its field arithmetic, and the library exports
  only `spscan_*` symbols, so it does not clash with another libsecp256k1 in the process.
  Shared secrets, output tweaks and labels come from its silentpayments module.
- **Labels.** Tweak servers do not say which transaction a tweak belongs to, so a block's
  700 tweaks are tried against all its outputs, and every label adds a candidate
  `x(P_k + L)` per tweak. Candidates are added in affine coordinates with one field
  inversion per batch of 1024 (Montgomery's trick), which costs about five field
  multiplications each. When labels outnumber twice the outputs, `±output − P_k` is
  looked up among the labels instead, as BIP352 suggests. On mainnet block 833044
  (721 tweaks, 2105 taproot outputs) a block-wide scan takes 0.05 s with no labels and
  0.16 s with 1000 (spscand's Python code takes 7.5 s).
- **Constant time.** The shared secret `b_scan·(input_hash·A)` is computed in constant
  time. Matching after that branches on public output keys and on `P_k`, as libsecp256k1's
  own scanner does; a local attacker timing it could learn whether a candidate matched.
- **Tables keyed by a secret.** Output and label lookups hash keys with SipHash under a key
  derived from the scan key, so a sender choosing output keys cannot make them collide and
  slow scanning down.
- **Filters and labels.** `spscan_filter_check` tests the k = 0 key with no label and with
  each label, `tweaks × (1 + labels)` items at about 1/784931 each. On block 833044 the
  chance of fetching a block for nothing is 0.2% with no labels, 1% with 10 and 9% with
  100; with 1000 labels most blocks match, and filters save nothing.

## License

MIT, like libsecp256k1 (`secp256k1/COPYING`).
