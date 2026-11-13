/* libspscan: BIP352 silent payment scanning and BIP158 filter matching.
 *
 * The library does no I/O. It takes block data (tweaks, taproot outputs,
 * transaction inputs, compact filters) from the caller and never sees a spend
 * private key. It bundles libsecp256k1 and exports only spscan_* symbols.
 *
 * Byte conventions: points are 33-byte compressed keys, taproot outputs are
 * 32-byte x-only keys, block hashes and outpoint txids are in internal byte
 * order (as in blocks and P2P messages, the reverse of how they are displayed).
 *
 * Functions return SPSCAN_OK (0) or a negative SPSCAN_ERR_* code, except where
 * noted. A spscan_receiver can be used from several threads at once.
 */
#ifndef SPSCAN_H
#define SPSCAN_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__GNUC__)
#define SPSCAN_API extern __attribute__((visibility("default")))
#else
#define SPSCAN_API extern
#endif

#define SPSCAN_OK 0
#define SPSCAN_ERR_ARG (-1)      /* malformed key, point or argument */
#define SPSCAN_ERR_NOMEM (-2)
#define SPSCAN_ERR_SCALAR (-3)   /* a BIP352 hash is 0 or >= n; BIP352 says to fail */
#define SPSCAN_ERR_INFINITY (-4) /* B_spend + t_k*G is the point at infinity */
#define SPSCAN_ERR_FILTER (-5)   /* malformed compact filter */
#define SPSCAN_ERR_SPACE (-6)    /* output buffer too small; the needed size is returned */

/* BIP352 limits the outputs per recipient group to this many. */
#define SPSCAN_K_MAX 2323

SPSCAN_API const char *spscan_version(void);

/* ---- Receiver ---------------------------------------------------------- */

typedef struct spscan_receiver spscan_receiver;

/* Do not scan for the change label (m = 0). By default it is always scanned,
 * so that a wallet restored from backup finds its change. */
#define SPSCAN_NO_CHANGE_LABEL 1u
/* Force one label-matching strategy (for tests); by default the cheaper one
 * is chosen per group. */
#define SPSCAN_LABELS_BY_ADDITION 2u
#define SPSCAN_LABELS_BY_SUBTRACTION 4u

/* scan_key: the 32-byte scan private key. spend_pubkey: the 33-byte spend
 * public key. labels: the label numbers m to scan for (duplicates allowed).
 * seed: 32 random bytes to blind the secp256k1 context, or NULL. */
SPSCAN_API int spscan_receiver_create(spscan_receiver **receiver,
                                      const unsigned char scan_key[32],
                                      const unsigned char spend_pubkey[33],
                                      const uint32_t *labels, size_t n_labels,
                                      unsigned int flags,
                                      const unsigned char seed[32]);

SPSCAN_API void spscan_receiver_destroy(spscan_receiver *receiver);

/* ---- Scanning ---------------------------------------------------------- */

typedef struct {
    uint32_t tweak;   /* index into the tweaks passed to spscan_scan */
    uint32_t output;  /* index into the outputs */
    uint32_t k;
    int64_t label;    /* label number m, or -1 for an unlabelled output */
    /* The output's private key is (spend private key + key_tweak) mod n, and
     * its public key is that times G, with no BIP341 tweak. */
    unsigned char key_tweak[32];
} spscan_match;

/* Try every tweak against the same set of taproot outputs.
 *
 * tweaks: n_tweaks 33-byte points, each input_hash*A for one transaction (as
 * served by tweak indexes, or from spscan_tweak_from_inputs).
 * outputs: n_outputs 32-byte x-only keys.
 *
 * Pass one transaction's tweak and outputs, or a whole block's tweaks and
 * taproot outputs when the source does not say which tweak belongs to which
 * transaction. A match against another transaction's output would need a hash
 * collision, so both give the same result; a whole block costs more per label.
 *
 * matches: room for *n_matches entries. On return *n_matches is the number of
 * matches; if that exceeds the room given, SPSCAN_ERR_SPACE is returned and the
 * first entries are filled. Matches are ordered by tweak, then k.
 */
SPSCAN_API int spscan_scan(const spscan_receiver *receiver,
                           const unsigned char *tweaks, size_t n_tweaks,
                           const unsigned char *outputs, size_t n_outputs,
                           spscan_match *matches, size_t *n_matches);

/* ---- Tweaks from transaction inputs (full nodes and indexers) ----------- */

typedef struct {
    const unsigned char *outpoint;        /* 36 bytes: txid, then vout little-endian */
    const unsigned char *script_sig;
    size_t script_sig_len;
    const unsigned char *const *witness;  /* n_witness stack items */
    const size_t *witness_lens;
    size_t n_witness;
    const unsigned char *prevout_script;  /* scriptPubKey of the coin being spent */
    size_t prevout_script_len;
} spscan_input;

/* Compute input_hash*A for a transaction with at least one taproot output.
 * Returns 1 and writes tweak if the transaction is eligible, 0 if it is not
 * (no usable input key, keys sum to infinity, or an input spends witness
 * version 2-16), or a negative error. The caller checks for a taproot output. */
SPSCAN_API int spscan_tweak_from_inputs(const spscan_input *inputs, size_t n_inputs,
                                        unsigned char tweak[33]);

/* ---- BIP158 compact block filters --------------------------------------- */

/* The basic filter (P = 19, M = 784931) keyed by the block hash. */

/* Sets *match to 1 if any item may be in the filter (false positive rate
 * about 1/784931 per item), else 0. */
SPSCAN_API int spscan_gcs_match_any(const unsigned char *filter, size_t filter_len,
                                    const unsigned char block_hash[32],
                                    const unsigned char *const *items, const size_t *item_lens,
                                    size_t n_items, int *match);

/* Build a filter from a block's elements (duplicates are removed). out holds
 * *out_len bytes; 9 + 3 * n_items + 8 is always enough. On return *out_len is
 * the filter's length. */
SPSCAN_API int spscan_gcs_build(const unsigned char block_hash[32],
                                const unsigned char *const *items, const size_t *item_lens,
                                size_t n_items, unsigned char *out, size_t *out_len);

/* BIP352 light-client check: may the block pay this receiver? For each tweak
 * the k = 0 output key, unlabelled and with every label, is tested against the
 * filter; outputs with k > 0 exist only next to the k = 0 one. Sets *match.
 * Each tweak adds (1 + labels) items, each a 1/784931 chance of a false
 * positive. */
SPSCAN_API int spscan_filter_check(const spscan_receiver *receiver,
                                   const unsigned char *tweaks, size_t n_tweaks,
                                   const unsigned char *filter, size_t filter_len,
                                   const unsigned char block_hash[32], int *match);

#ifdef __cplusplus
}
#endif

#endif
