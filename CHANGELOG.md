# Changelog

## 0.1.1

- Show payments still in the mempool. With a Bitcoin Core node, `spscand run` checks every
  mempool transaction; payments are listed as unconfirmed and counted in `pending_in`, never in the
  balance, and dropped with a reason (`replaced`, `conflicted` or `evicted`) if they leave the
  mempool unmined. BlindBit and filters can use a Core node for this with `[mempool] source = "core"`.
- API: the version in `/v1/status`; `/v1/outputs?since_height=`; `POST /v1/labels`;
  `POST /v1/rescan`; `GET /v1/events`, which waits for the next event. Changes need the token.
- Refuse to listen beyond loopback without an API token (0.1.0 only warned).
- `spscand pair` prints a pairing string for a wallet, creating an API token if there is none.
- Fix: with the filters backend, an unanswered filter request (a block the peer had not indexed
  yet) could stall the scan for minutes; it now gives up after 30 seconds and asks again.

## 0.1.0

- First release: spscand, libspscan and `spscand web`.
