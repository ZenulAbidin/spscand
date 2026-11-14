/* libspscan: see include/spscan.h.
 *
 * Built as one translation unit with the bundled libsecp256k1, so that label
 * matching can use its field arithmetic directly. With labels, every candidate
 * x(P + L) costs a point addition and a field inversion; the inversions are
 * batched with Montgomery's trick, which makes a candidate about as cheap as
 * five field multiplications. That matters when a whole block's tweaks are
 * tried against its outputs (tweak servers do not say which transaction a
 * tweak belongs to): 700 tweaks and 1000 labels are 700,000 candidates. */

#define ENABLE_MODULE_EXTRAKEYS 1
#define ENABLE_MODULE_SILENTPAYMENTS 1
#define SECP256K1_NO_API_VISIBILITY_ATTRIBUTES 1
#include "../secp256k1/src/secp256k1.c"

#include <stdlib.h>
#include <string.h>

#include "../include/spscan.h"

#define BATCH 1024
#define NONE UINT32_MAX
#define GCS_P 19
#define GCS_M 784931ULL

/* BIP341 NUMS point H (x-only). A script-path spend with this internal key has
 * no key-path signer, so BIP352 skips the input. */
static const unsigned char NUMS_H[32] = {
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
};

const char *spscan_version(void) {
    return "0.1.0";
}

/* ---- Hashes -------------------------------------------------------------- */

static uint64_t le64(const unsigned char *p) {
    uint64_t v = 0;
    int i;
    for (i = 7; i >= 0; i--) v = (v << 8) | p[i];
    return v;
}

#define ROTL64(x, b) (uint64_t)(((x) << (b)) | ((x) >> (64 - (b))))
#define SIPROUND do { \
    v0 += v1; v1 = ROTL64(v1, 13); v1 ^= v0; v0 = ROTL64(v0, 32); \
    v2 += v3; v3 = ROTL64(v3, 16); v3 ^= v2; \
    v0 += v3; v3 = ROTL64(v3, 21); v3 ^= v0; \
    v2 += v1; v1 = ROTL64(v1, 17); v1 ^= v2; v2 = ROTL64(v2, 32); \
} while (0)

static uint64_t siphash24(uint64_t k0, uint64_t k1, const unsigned char *m, size_t len) {
    uint64_t v0 = 0x736f6d6570736575ULL ^ k0, v1 = 0x646f72616e646f6dULL ^ k1;
    uint64_t v2 = 0x6c7967656e657261ULL ^ k0, v3 = 0x7465646279746573ULL ^ k1;
    uint64_t b = (uint64_t)len << 56;
    size_t i, end = len - (len % 8);
    for (i = 0; i < end; i += 8) {
        uint64_t w = le64(m + i);
        v3 ^= w;
        SIPROUND; SIPROUND;
        v0 ^= w;
    }
    switch (len & 7) {
        case 7: b |= (uint64_t)m[i + 6] << 48; /* fall through */
        case 6: b |= (uint64_t)m[i + 5] << 40; /* fall through */
        case 5: b |= (uint64_t)m[i + 4] << 32; /* fall through */
        case 4: b |= (uint64_t)m[i + 3] << 24; /* fall through */
        case 3: b |= (uint64_t)m[i + 2] << 16; /* fall through */
        case 2: b |= (uint64_t)m[i + 1] << 8;  /* fall through */
        case 1: b |= (uint64_t)m[i];           /* fall through */
        default: break;
    }
    v3 ^= b;
    SIPROUND; SIPROUND;
    v0 ^= b;
    v2 ^= 0xff;
    SIPROUND; SIPROUND; SIPROUND; SIPROUND;
    return v0 ^ v1 ^ v2 ^ v3;
}

static uint64_t mulhi64(uint64_t a, uint64_t b) {
#if defined(__SIZEOF_INT128__) && !defined(__wasm__)  /* wasm32 has no __multi3 */
    return (uint64_t)(((unsigned __int128)a * b) >> 64);
#else
    uint64_t a_lo = (uint32_t)a, a_hi = a >> 32, b_lo = (uint32_t)b, b_hi = b >> 32;
    uint64_t p0 = a_lo * b_lo, p1 = a_lo * b_hi, p2 = a_hi * b_lo, p3 = a_hi * b_hi;
    uint64_t mid = (p0 >> 32) + (uint32_t)p1 + (uint32_t)p2;
    return p3 + (p1 >> 32) + (p2 >> 32) + (mid >> 32);
#endif
}

static uint32_t rol32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

static void ripemd160_block(uint32_t h[5], const unsigned char *p) {
    static const unsigned char RL[80] = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
        3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
        1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
        4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13};
    static const unsigned char RR[80] = {
        5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
        6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
        15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
        8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
        12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11};
    static const unsigned char SL[80] = {
        11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
        7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
        11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
        11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
        9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6};
    static const unsigned char SR[80] = {
        8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
        9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
        9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
        15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
        8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11};
    static const uint32_t KL[5] = {0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E};
    static const uint32_t KR[5] = {0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000};
    uint32_t x[16], al = h[0], bl = h[1], cl = h[2], dl = h[3], el = h[4];
    uint32_t ar = al, br = bl, cr = cl, dr = dl, er = el, t;
    int j;
    for (j = 0; j < 16; j++) {
        x[j] = (uint32_t)p[4 * j] | (uint32_t)p[4 * j + 1] << 8 |
               (uint32_t)p[4 * j + 2] << 16 | (uint32_t)p[4 * j + 3] << 24;
    }
    for (j = 0; j < 80; j++) {
        uint32_t fl, fr;
        switch (j / 16) {
            case 0: fl = bl ^ cl ^ dl; fr = br ^ (cr | ~dr); break;
            case 1: fl = (bl & cl) | (~bl & dl); fr = (br & dr) | (cr & ~dr); break;
            case 2: fl = (bl | ~cl) ^ dl; fr = (br | ~cr) ^ dr; break;
            case 3: fl = (bl & dl) | (cl & ~dl); fr = (br & cr) | (~br & dr); break;
            default: fl = bl ^ (cl | ~dl); fr = br ^ cr ^ dr; break;
        }
        t = rol32(al + fl + x[RL[j]] + KL[j / 16], SL[j]) + el;
        al = el; el = dl; dl = rol32(cl, 10); cl = bl; bl = t;
        t = rol32(ar + fr + x[RR[j]] + KR[j / 16], SR[j]) + er;
        ar = er; er = dr; dr = rol32(cr, 10); cr = br; br = t;
    }
    t = h[1] + cl + dr;
    h[1] = h[2] + dl + er;
    h[2] = h[3] + el + ar;
    h[3] = h[4] + al + br;
    h[4] = h[0] + bl + cr;
    h[0] = t;
}

static void ripemd160(unsigned char out[20], const unsigned char *data, size_t len) {
    uint32_t h[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
    unsigned char block[64];
    uint64_t bits = (uint64_t)len * 8;
    size_t i, rest;
    int j;
    for (; len >= 64; data += 64, len -= 64) ripemd160_block(h, data);
    memset(block, 0, 64);
    memcpy(block, data, len);
    block[len] = 0x80;
    rest = len + 1;
    if (rest > 56) {
        ripemd160_block(h, block);
        memset(block, 0, 64);
    }
    for (i = 0; i < 8; i++) block[56 + i] = (unsigned char)(bits >> (8 * i));
    ripemd160_block(h, block);
    for (j = 0; j < 5; j++) {
        out[4 * j] = (unsigned char)h[j];
        out[4 * j + 1] = (unsigned char)(h[j] >> 8);
        out[4 * j + 2] = (unsigned char)(h[j] >> 16);
        out[4 * j + 3] = (unsigned char)(h[j] >> 24);
    }
}

static void hash160(unsigned char out[20], const unsigned char *data, size_t len) {
    const secp256k1_hash_ctx *hash_ctx = secp256k1_get_hash_context(secp256k1_context_static);
    secp256k1_sha256 sha;
    unsigned char digest[32];
    secp256k1_sha256_initialize(&sha);
    secp256k1_sha256_write(hash_ctx, &sha, data, len);
    secp256k1_sha256_finalize(hash_ctx, &sha, digest);
    ripemd160(out, digest, 32);
}

/* ---- Point helpers -------------------------------------------------------- */

/* An affine point with its negated coordinates cached for the batch formulas. */
typedef struct {
    secp256k1_ge p;     /* x and y normalized */
    secp256k1_fe negx;  /* -x, magnitude 2 */
    secp256k1_fe negy;  /* -y, magnitude 2 */
} point;

static void point_set(point *r, const secp256k1_ge *p) {
    r->p = *p;
    secp256k1_fe_normalize_var(&r->p.x);
    secp256k1_fe_normalize_var(&r->p.y);
    secp256k1_fe_negate(&r->negx, &r->p.x, 1);
    secp256k1_fe_negate(&r->negy, &r->p.y, 1);
}

/* a + b by the general formulas, for the cases the batch formulas exclude
 * (equal x). Returns 0 for the point at infinity. */
static int add_slow(secp256k1_ge *r, const secp256k1_ge *a, const secp256k1_ge *b) {
    secp256k1_gej aj, rj;
    secp256k1_gej_set_ge(&aj, a);
    secp256k1_gej_add_ge_var(&rj, &aj, b, NULL);
    if (secp256k1_gej_is_infinity(&rj)) return 0;
    secp256k1_ge_set_gej_var(r, &rj);
    secp256k1_fe_normalize_var(&r->x);
    secp256k1_fe_normalize_var(&r->y);
    return 1;
}

/* inv[i] = 1/d[i] for n nonzero elements, with one field inversion. */
static void batch_inverse(secp256k1_fe *inv, const secp256k1_fe *d, size_t n, secp256k1_fe *acc) {
    secp256k1_fe u;
    size_t i;
    if (n == 0) return;
    acc[0] = d[0];
    for (i = 1; i < n; i++) secp256k1_fe_mul(&acc[i], &acc[i - 1], &d[i]);
    secp256k1_fe_inv_var(&u, &acc[n - 1]);
    for (i = n - 1; i > 0; i--) {
        secp256k1_fe_mul(&inv[i], &u, &acc[i - 1]);
        secp256k1_fe_mul(&u, &u, &d[i]);
    }
    inv[0] = u;
}

/* ---- Hash table of 32-byte keys -------------------------------------------- */

/* Keys are hashed with SipHash under a secret key, so that someone choosing
 * output keys cannot make them collide in the table and slow scanning down. */
typedef struct {
    uint64_t k0, k1;
    uint32_t *slots;  /* index + 1 of an entry, 0 if empty */
    size_t mask;
    const unsigned char *keys;
} table;

static int table_init(table *t, uint64_t k0, uint64_t k1, const unsigned char *keys, size_t n) {
    size_t size = 16;
    while (size < 2 * n) size <<= 1;
    t->k0 = k0;
    t->k1 = k1;
    t->keys = keys;
    t->mask = size - 1;
    t->slots = calloc(size, sizeof(uint32_t));
    return t->slots != NULL;
}

static uint32_t *table_slot(const table *t, const unsigned char *key) {
    size_t i = (size_t)siphash24(t->k0, t->k1, key, 32) & t->mask;
    while (t->slots[i] && memcmp(t->keys + 32 * (size_t)(t->slots[i] - 1), key, 32) != 0) {
        i = (i + 1) & t->mask;
    }
    return &t->slots[i];
}

/* ---- Receiver ----------------------------------------------------------------- */

struct spscan_receiver {
    secp256k1_context *ctx;
    secp256k1_scalar scan_key;
    secp256k1_ge spend;
    unsigned int flags;
    uint64_t k0, k1;
    size_t n_labels;
    uint32_t *label_m;
    point *label_pt;
    secp256k1_scalar *label_tweak;
    unsigned char *label_x;  /* 32 bytes per label */
    table label_table;
};

static int cmp_u32(const void *a, const void *b) {
    uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b;
    return (x > y) - (x < y);
}

int spscan_receiver_scan_pubkey(const spscan_receiver *r, unsigned char out[33]) {
    secp256k1_ge p;
    if (r == NULL || out == NULL) return SPSCAN_ERR_ARG;
    secp256k1_ecmult_gen_ge(&r->ctx->ecmult_gen_ctx, &p, &r->scan_key);
    secp256k1_eckey_pubkey_serialize33(&p, out);
    return SPSCAN_OK;
}

void spscan_receiver_destroy(spscan_receiver *r) {
    if (r == NULL) return;
    if (r->ctx) secp256k1_context_destroy(r->ctx);
    secp256k1_scalar_clear(&r->scan_key);
    if (r->label_tweak) {
        secp256k1_memclear_explicit(r->label_tweak, r->n_labels * sizeof(secp256k1_scalar));
    }
    free(r->label_m);
    free(r->label_pt);
    free(r->label_tweak);
    free(r->label_x);
    free(r->label_table.slots);
    secp256k1_memclear_explicit(r, sizeof(*r));
    free(r);
}

int spscan_receiver_create(spscan_receiver **out, const unsigned char scan_key[32],
                           const unsigned char spend_pubkey[33], const uint32_t *labels,
                           size_t n_labels, unsigned int flags, const unsigned char seed[32]) {
    spscan_receiver *r;
    secp256k1_sha256 sha;
    unsigned char digest[32];
    size_t i, n;
    int ret = SPSCAN_ERR_NOMEM;

    if (out == NULL) return SPSCAN_ERR_ARG;
    *out = NULL;
    if (scan_key == NULL || spend_pubkey == NULL || (n_labels && labels == NULL) ||
        n_labels >= NONE) {
        return SPSCAN_ERR_ARG;
    }
    r = calloc(1, sizeof(*r));
    if (r == NULL) return SPSCAN_ERR_NOMEM;
    r->flags = flags;
    r->ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    if (r->ctx == NULL) goto fail;
    if (seed != NULL && !secp256k1_context_randomize(r->ctx, seed)) {
        ret = SPSCAN_ERR_ARG;
        goto fail;
    }
    ret = SPSCAN_ERR_ARG;
    if (!secp256k1_scalar_set_b32_seckey(&r->scan_key, scan_key)) goto fail;
    if (!secp256k1_eckey_pubkey_parse(&r->spend, spend_pubkey, 33)) goto fail;
    secp256k1_fe_normalize_var(&r->spend.x);
    secp256k1_fe_normalize_var(&r->spend.y);

    /* The table key is derived from the scan key: secret, and stable. */
    secp256k1_sha256_initialize(&sha);
    secp256k1_sha256_write(secp256k1_get_hash_context(r->ctx), &sha,
                           (const unsigned char *)"spscan/table", 12);
    secp256k1_sha256_write(secp256k1_get_hash_context(r->ctx), &sha, scan_key, 32);
    secp256k1_sha256_finalize(secp256k1_get_hash_context(r->ctx), &sha, digest);
    r->k0 = le64(digest);
    r->k1 = le64(digest + 8);

    ret = SPSCAN_ERR_NOMEM;
    r->label_m = malloc((n_labels + 1) * sizeof(uint32_t));
    if (r->label_m == NULL) goto fail;
    if (n_labels) memcpy(r->label_m, labels, n_labels * sizeof(uint32_t));
    n = n_labels;
    /* BIP352 reserves m = 0 for change; a wallet restored from backup must find it. */
    if (!(flags & SPSCAN_NO_CHANGE_LABEL)) r->label_m[n++] = 0;
    qsort(r->label_m, n, sizeof(uint32_t), cmp_u32);
    for (i = 0, r->n_labels = 0; i < n; i++) {
        if (r->n_labels == 0 || r->label_m[r->n_labels - 1] != r->label_m[i]) {
            r->label_m[r->n_labels++] = r->label_m[i];
        }
    }
    n = r->n_labels;
    r->label_pt = malloc((n + 1) * sizeof(point));
    r->label_tweak = malloc((n + 1) * sizeof(secp256k1_scalar));
    r->label_x = malloc((n + 1) * 32);
    if (!r->label_pt || !r->label_tweak || !r->label_x) goto fail;
    for (i = 0; i < n; i++) {
        secp256k1_silentpayments_label label;
        secp256k1_ge ge;
        unsigned char tweak32[32];
        if (!secp256k1_silentpayments_recipient_label_create(r->ctx, &label, tweak32, scan_key,
                                                              r->label_m[i])) {
            ret = SPSCAN_ERR_SCALAR;
            goto fail;
        }
        secp256k1_silentpayments_label_load(r->ctx, &ge, &label);
        point_set(&r->label_pt[i], &ge);
        secp256k1_scalar_set_b32(&r->label_tweak[i], tweak32, NULL);
        secp256k1_memclear_explicit(tweak32, 32);
        secp256k1_fe_get_b32(r->label_x + 32 * i, &r->label_pt[i].p.x);
    }
    if (!table_init(&r->label_table, r->k0, r->k1, r->label_x, n)) goto fail;
    for (i = 0; i < n; i++) *table_slot(&r->label_table, r->label_x + 32 * i) = (uint32_t)i + 1;
    *out = r;
    return SPSCAN_OK;
fail:
    spscan_receiver_destroy(r);
    return ret;
}

static uint32_t label_by_x(const spscan_receiver *r, const unsigned char *x) {
    return *table_slot(&r->label_table, x) - 1;  /* NONE if absent */
}

/* ---- Label candidates ----------------------------------------------------------- */

typedef struct {
    size_t cap;
    secp256k1_fe *d, *acc, *inv;
    uint32_t *idx;
} batch;

static void batch_free(batch *b) {
    free(b->d);
    free(b->acc);
    free(b->inv);
    free(b->idx);
}

/* Room for min(BATCH, n) candidates at a time. */
static int batch_init(batch *b, size_t n) {
    b->cap = n < 1 ? 1 : n > BATCH ? BATCH : n;
    b->d = malloc(b->cap * sizeof(secp256k1_fe));
    b->acc = malloc(b->cap * sizeof(secp256k1_fe));
    b->inv = malloc(b->cap * sizeof(secp256k1_fe));
    b->idx = malloc(b->cap * sizeof(uint32_t));
    if (b->d && b->acc && b->inv && b->idx) return 1;
    batch_free(b);
    return 0;
}

/* Calls hit(arg, x) with x(P + L) for each label L in ascending order of m,
 * one batch at a time, and stops after the first batch with a hit. Returns
 * the index of the first label that hit, or NONE. *found is what hit set. */
static uint32_t labels_by_addition(const spscan_receiver *r, batch *b, const point *P,
                                   uint32_t (*hit)(void *, const unsigned char *), void *arg,
                                   uint32_t *found) {
    uint32_t best = NONE;
    size_t start, j, t, m;
    unsigned char x[32];
    for (start = 0; start < r->n_labels && best == NONE; start += b->cap) {
        size_t end = start + b->cap < r->n_labels ? start + b->cap : r->n_labels;
        for (j = start, m = 0; j < end; j++) {
            const point *L = &r->label_pt[j];
            secp256k1_fe d = L->p.x;
            secp256k1_fe_add(&d, &P->negx);
            if (secp256k1_fe_normalizes_to_zero_var(&d)) {
                secp256k1_ge sum;
                uint32_t h;
                if (add_slow(&sum, &P->p, &L->p)) {
                    secp256k1_fe_get_b32(x, &sum.x);
                    if ((h = hit(arg, x)) != NONE && j < best) {
                        best = (uint32_t)j;
                        *found = h;
                    }
                }
                continue;
            }
            b->d[m] = d;
            b->idx[m++] = (uint32_t)j;
        }
        batch_inverse(b->inv, b->d, m, b->acc);
        for (t = 0; t < m; t++) {
            const point *L = &r->label_pt[b->idx[t]];
            secp256k1_fe lam = L->p.y, x3;
            uint32_t h;
            secp256k1_fe_add(&lam, &P->negy);
            secp256k1_fe_mul(&lam, &lam, &b->inv[t]);
            secp256k1_fe_sqr(&x3, &lam);
            secp256k1_fe_add(&x3, &P->negx);
            secp256k1_fe_add(&x3, &L->negx);
            secp256k1_fe_normalize_var(&x3);
            secp256k1_fe_get_b32(x, &x3);
            if ((h = hit(arg, x)) != NONE && b->idx[t] < best) {
                best = b->idx[t];
                *found = h;
            }
        }
    }
    return best;
}

/* ---- Scanning --------------------------------------------------------------------- */

typedef struct {
    const spscan_receiver *r;
    const unsigned char *outputs;
    size_t n_outputs;
    table table;
    uint32_t *next;          /* next output with the same key, ascending */
    unsigned char *taken;
    uint32_t *taken_list;
    point *lifted;
    unsigned char *lift_state;  /* 0 not yet, 1 valid, 2 not a valid x */
    batch b;
} work;

static uint32_t first_untaken(void *arg, const unsigned char *x) {
    work *w = arg;
    uint32_t i = *table_slot(&w->table, x);
    if (i == 0) return NONE;
    for (i = i - 1; i != NONE && w->taken[i]; i = w->next[i]) {}
    return i;
}

static int lift(work *w, uint32_t i) {
    if (w->lift_state[i] == 0) {
        secp256k1_fe x;
        secp256k1_ge ge;
        w->lift_state[i] = 2;
        if (secp256k1_fe_set_b32_limit(&x, w->outputs + 32 * (size_t)i) &&
            secp256k1_ge_set_xo_var(&ge, &x, 0)) {
            point_set(&w->lifted[i], &ge);
            w->lift_state[i] = 1;
        }
    }
    return w->lift_state[i] == 1;
}

/* With more labels than outputs: (+-output - P) for each untaken output, in
 * output order, looked up among the labels. Returns the output index or NONE
 * and sets *label. */
static uint32_t labels_by_subtraction(work *w, const point *P, uint32_t *label) {
    const spscan_receiver *r = w->r;
    uint64_t best = UINT64_MAX;  /* 2 * output + (1 if -output) */
    size_t i = 0;
    unsigned char x[32], y[32], ly[32];
    secp256k1_ge negP;
    secp256k1_ge_neg(&negP, &P->p);
    while (i < w->n_outputs && best == UINT64_MAX) {
        size_t m = 0, t;
        for (; i < w->n_outputs && m < w->b.cap; i++) {
            const point *O;
            secp256k1_fe d;
            if (w->taken[i] || !lift(w, (uint32_t)i)) continue;
            O = &w->lifted[i];
            d = O->p.x;
            secp256k1_fe_add(&d, &P->negx);
            if (secp256k1_fe_normalizes_to_zero_var(&d)) {
                int s;
                for (s = 0; s < 2; s++) {
                    secp256k1_ge sO = O->p, D;
                    uint32_t j;
                    if (s) secp256k1_ge_neg(&sO, &O->p);
                    if (!add_slow(&D, &sO, &negP)) continue;
                    secp256k1_fe_get_b32(x, &D.x);
                    if ((j = label_by_x(r, x)) == NONE) continue;
                    secp256k1_fe_get_b32(y, &D.y);
                    secp256k1_fe_get_b32(ly, &r->label_pt[j].p.y);
                    if (memcmp(y, ly, 32) == 0 && 2 * (uint64_t)i + s < best) {
                        best = 2 * (uint64_t)i + s;
                        *label = j;
                    }
                }
                continue;
            }
            w->b.d[m] = d;
            w->b.idx[m++] = (uint32_t)i;
        }
        batch_inverse(w->b.inv, w->b.d, m, w->b.acc);
        for (t = 0; t < m; t++) {
            const point *O = &w->lifted[w->b.idx[t]];
            int s;
            for (s = 0; s < 2; s++) {
                /* D = sO - P: lambda = (s*Oy + Py) / (Ox - Px), x3 = lambda^2 - Ox - Px,
                 * y3 = lambda * (Ox - x3) - s*Oy. */
                secp256k1_fe lam = s ? O->negy : O->p.y, x3, y3, nx3;
                uint32_t j;
                secp256k1_fe_add(&lam, &P->p.y);
                secp256k1_fe_mul(&lam, &lam, &w->b.inv[t]);
                secp256k1_fe_sqr(&x3, &lam);
                secp256k1_fe_add(&x3, &O->negx);
                secp256k1_fe_add(&x3, &P->negx);
                secp256k1_fe_normalize_var(&x3);
                secp256k1_fe_get_b32(x, &x3);
                if ((j = label_by_x(r, x)) == NONE) continue;
                /* Same x: D is the label or its negation. */
                secp256k1_fe_negate(&nx3, &x3, 1);
                secp256k1_fe_add(&nx3, &O->p.x);
                secp256k1_fe_mul(&y3, &lam, &nx3);
                secp256k1_fe_add(&y3, s ? &O->p.y : &O->negy);
                secp256k1_fe_normalize_var(&y3);
                secp256k1_fe_get_b32(y, &y3);
                secp256k1_fe_get_b32(ly, &r->label_pt[j].p.y);
                if (memcmp(y, ly, 32) == 0 && 2 * (uint64_t)w->b.idx[t] + s < best) {
                    best = 2 * (uint64_t)w->b.idx[t] + s;
                    *label = j;
                }
            }
        }
    }
    return best == UINT64_MAX ? NONE : (uint32_t)(best / 2);
}

/* P_k = B_spend + t_k*G. */
static int output_point(const spscan_receiver *r, const unsigned char ss[33], uint32_t k,
                        secp256k1_scalar *t_k, point *P) {
    secp256k1_ge ge = r->spend;
    if (!secp256k1_silentpayments_create_output_tweak(r->ctx, t_k, ss, k)) return SPSCAN_ERR_SCALAR;
    if (!secp256k1_eckey_pubkey_tweak_add(&ge, t_k)) return SPSCAN_ERR_INFINITY;
    point_set(P, &ge);
    return SPSCAN_OK;
}

static int shared_secret(const spscan_receiver *r, const unsigned char *tweak33, unsigned char ss[33]) {
    secp256k1_ge T;
    if (!secp256k1_eckey_pubkey_parse(&T, tweak33, 33)) return SPSCAN_ERR_ARG;
    secp256k1_silentpayments_create_shared_secret(ss, &T, &r->scan_key);
    return SPSCAN_OK;
}

static void work_free(work *w) {
    batch_free(&w->b);
    free(w->table.slots);
    free(w->next);
    free(w->taken);
    free(w->taken_list);
    free(w->lifted);
    free(w->lift_state);
    free(w);
}

static work *work_new(const spscan_receiver *r, const unsigned char *outputs, size_t n) {
    work *w = calloc(1, sizeof(work));
    size_t i;
    if (w == NULL) return NULL;
    w->r = r;
    w->outputs = outputs;
    w->n_outputs = n;
    w->next = malloc(n * sizeof(uint32_t));
    w->taken = calloc(n, 1);
    w->taken_list = malloc(n * sizeof(uint32_t));
    w->lifted = malloc(n * sizeof(point));
    w->lift_state = calloc(n, 1);
    if (!w->next || !w->taken || !w->taken_list || !w->lifted || !w->lift_state ||
        !table_init(&w->table, r->k0, r->k1, outputs, n) ||
        !batch_init(&w->b, r->n_labels > n ? r->n_labels : n)) {
        work_free(w);
        return NULL;
    }
    for (i = n; i-- > 0;) {
        uint32_t *slot = table_slot(&w->table, outputs + 32 * i);
        w->next[i] = *slot ? *slot - 1 : NONE;
        *slot = (uint32_t)i + 1;
    }
    return w;
}

int spscan_scan(const spscan_receiver *r, const unsigned char *tweaks, size_t n_tweaks,
                const unsigned char *outputs, size_t n_outputs, spscan_match *matches,
                size_t *n_matches) {
    size_t cap, count = 0, ti;
    work *w;
    int ret = SPSCAN_OK;

    if (r == NULL || n_matches == NULL) return SPSCAN_ERR_ARG;
    cap = *n_matches;
    *n_matches = 0;
    if ((n_tweaks && tweaks == NULL) || (n_outputs && outputs == NULL) || (cap && matches == NULL) ||
        n_outputs >= NONE || n_tweaks >= NONE) {
        return SPSCAN_ERR_ARG;
    }
    if (n_tweaks == 0 || n_outputs == 0) return SPSCAN_OK;
    w = work_new(r, outputs, n_outputs);
    if (w == NULL) return SPSCAN_ERR_NOMEM;

    for (ti = 0; ti < n_tweaks && ret == SPSCAN_OK; ti++) {
        unsigned char ss[33], x[32];
        size_t n_taken = 0, i;
        uint32_t k;
        if ((ret = shared_secret(r, tweaks + 33 * ti, ss)) != SPSCAN_OK) break;
        for (k = 0; k < SPSCAN_K_MAX; k++) {
            secp256k1_scalar t_k;
            point P;
            uint32_t o, label = NONE;
            if ((ret = output_point(r, ss, k, &t_k, &P)) != SPSCAN_OK) break;
            secp256k1_fe_get_b32(x, &P.p.x);
            /* A direct match is checked first; a sender following BIP352 never
             * produces both a direct and a labelled match for the same k. */
            o = first_untaken(w, x);
            if (o == NONE && r->n_labels) {
                int add = (r->flags & SPSCAN_LABELS_BY_ADDITION) ? 1 :
                          (r->flags & SPSCAN_LABELS_BY_SUBTRACTION) ? 0 :
                          r->n_labels <= 2 * (n_outputs - n_taken);
                if (add) {
                    label = labels_by_addition(r, &w->b, &P, first_untaken, w, &o);
                    if (label == NONE) o = NONE;
                } else {
                    o = labels_by_subtraction(w, &P, &label);
                }
            }
            if (o == NONE) {
                secp256k1_scalar_clear(&t_k);
                break;
            }
            if (count < cap) {
                spscan_match *m = &matches[count];
                m->tweak = (uint32_t)ti;
                m->output = o;
                m->k = k;
                m->label = label == NONE ? -1 : (int64_t)r->label_m[label];
                if (label != NONE) secp256k1_scalar_add(&t_k, &t_k, &r->label_tweak[label]);
                secp256k1_scalar_get_b32(m->key_tweak, &t_k);
            }
            secp256k1_scalar_clear(&t_k);
            count++;
            w->taken[o] = 1;
            w->taken_list[n_taken++] = o;
        }
        for (i = 0; i < n_taken; i++) w->taken[w->taken_list[i]] = 0;
        secp256k1_memclear_explicit(ss, sizeof(ss));
    }
    work_free(w);
    if (ret != SPSCAN_OK) return ret;
    *n_matches = count;
    return count > cap ? SPSCAN_ERR_SPACE : SPSCAN_OK;
}

/* ---- Tweaks from inputs --------------------------------------------------------- */

static int parse_compressed(secp256k1_ge *ge, const unsigned char *data, size_t len) {
    return len == 33 && secp256k1_eckey_pubkey_parse(ge, data, 33);
}

static int is_p2wpkh(const unsigned char *s, size_t n) {
    return n == 22 && s[0] == 0x00 && s[1] == 0x14;
}

/* The key an input contributes; 0 if BIP352 skips it. */
static int input_key(const spscan_input *in, secp256k1_ge *key) {
    const unsigned char *spk = in->prevout_script, *ss = in->script_sig;
    size_t n = in->prevout_script_len, nw = in->n_witness;
    if (n == 25 && spk[0] == 0x76 && spk[1] == 0xa9 && spk[2] == 0x14 && spk[23] == 0x88 &&
        spk[24] == 0xac) {
        /* P2PKH: search the scriptSig from the back for a key matching the
         * hash, so a malleated (non-template) scriptSig still yields the key. */
        size_t end;
        unsigned char h[20];
        for (end = in->script_sig_len; end >= 33; end--) {
            hash160(h, ss + end - 33, 33);
            if (memcmp(h, spk + 3, 20) == 0 && parse_compressed(key, ss + end - 33, 33)) return 1;
        }
        return 0;
    }
    if (n == 23 && spk[0] == 0xa9 && spk[1] == 0x14 && spk[22] == 0x87) {
        /* P2SH: only P2SH-P2WPKH. */
        if (in->script_sig_len >= 1 && is_p2wpkh(ss + 1, in->script_sig_len - 1) && nw) {
            return parse_compressed(key, in->witness[nw - 1], in->witness_lens[nw - 1]);
        }
        return 0;
    }
    if (is_p2wpkh(spk, n)) {
        return nw && parse_compressed(key, in->witness[nw - 1], in->witness_lens[nw - 1]);
    }
    if (n == 34 && spk[0] == 0x51 && spk[1] == 0x20) {
        secp256k1_fe x;
        if (nw == 0) return 0;
        if (nw > 1 && in->witness_lens[nw - 1] && in->witness[nw - 1][0] == 0x50) nw--;  /* annex */
        if (nw > 1 && in->witness_lens[nw - 1] >= 33 &&
            memcmp(in->witness[nw - 1] + 1, NUMS_H, 32) == 0) {
            return 0;
        }
        return secp256k1_fe_set_b32_limit(&x, spk + 2) && secp256k1_ge_set_xo_var(key, &x, 0);
    }
    return 0;
}

int spscan_tweak_from_inputs(const spscan_input *inputs, size_t n_inputs, unsigned char tweak[33]) {
    const secp256k1_hash_ctx *hash_ctx = secp256k1_get_hash_context(secp256k1_context_static);
    const unsigned char *smallest = NULL;
    secp256k1_gej sum;
    secp256k1_ge ge;
    secp256k1_scalar input_hash;
    size_t i;
    int any = 0;

    if ((n_inputs && inputs == NULL) || tweak == NULL) return SPSCAN_ERR_ARG;
    for (i = 0; i < n_inputs; i++) {
        const spscan_input *in = &inputs[i];
        if (in->outpoint == NULL || (in->script_sig_len && in->script_sig == NULL) ||
            (in->n_witness && (in->witness == NULL || in->witness_lens == NULL)) ||
            (in->prevout_script_len && in->prevout_script == NULL)) {
            return SPSCAN_ERR_ARG;
        }
    }
    secp256k1_gej_set_infinity(&sum);
    for (i = 0; i < n_inputs; i++) {
        const spscan_input *in = &inputs[i];
        const unsigned char *spk = in->prevout_script;
        size_t n = in->prevout_script_len;
        /* Witness v2-v16: the transaction is not eligible, so that future
         * output types can define their own rules. */
        if (n >= 4 && n <= 42 && spk[0] >= 0x52 && spk[0] <= 0x60 && spk[1] == n - 2) return 0;
        if (input_key(in, &ge)) {
            secp256k1_gej_add_ge_var(&sum, &sum, &ge, NULL);
            any = 1;
        }
        if (smallest == NULL || memcmp(in->outpoint, smallest, 36) < 0) smallest = in->outpoint;
    }
    if (!any || secp256k1_gej_is_infinity(&sum)) return 0;
    secp256k1_ge_set_gej_var(&ge, &sum);
    if (!secp256k1_silentpayments_calculate_input_hash_scalar(hash_ctx, &input_hash, smallest, &ge)) {
        return SPSCAN_ERR_SCALAR;
    }
    secp256k1_eckey_pubkey_tweak_mul(&ge, &input_hash);
    secp256k1_eckey_pubkey_serialize33(&ge, tweak);
    return 1;
}

/* ---- BIP158 filters ------------------------------------------------------------- */

typedef struct {
    uint64_t *values;  /* sorted */
    uint64_t n;
    uint64_t k0, k1;
} gcs;

static int read_compact(const unsigned char *p, size_t len, uint64_t *v, size_t *used) {
    size_t size, i;
    if (len < 1) return 0;
    if (p[0] < 0xfd) {
        *v = p[0];
        *used = 1;
        return 1;
    }
    size = p[0] == 0xfd ? 2 : p[0] == 0xfe ? 4 : 8;
    if (len < 1 + size) return 0;
    for (*v = 0, i = size; i > 0; i--) *v = (*v << 8) | p[i];
    *used = 1 + size;
    return 1;
}

static int gcs_decode(gcs *g, const unsigned char *f, size_t len, const unsigned char hash[32]) {
    size_t used, bit, nbits, i;
    uint64_t value = 0;
    g->values = NULL;
    g->k0 = le64(hash);
    g->k1 = le64(hash + 8);
    if (f == NULL || !read_compact(f, len, &g->n, &used)) return SPSCAN_ERR_FILTER;
    f += used;
    nbits = (len - used) * 8;
    if (g->n > nbits / (GCS_P + 1)) return SPSCAN_ERR_FILTER;
    g->values = malloc((size_t)(g->n ? g->n : 1) * sizeof(uint64_t));
    if (g->values == NULL) return SPSCAN_ERR_NOMEM;
    for (i = 0, bit = 0; i < g->n; i++) {
        uint64_t q = 0, rem = 0;
        int j;
        for (;;) {
            int b;
            if (bit >= nbits) goto bad;
            b = (f[bit / 8] >> (7 - bit % 8)) & 1;
            bit++;
            if (!b) break;
            q++;
        }
        if (bit + GCS_P > nbits) goto bad;
        for (j = 0; j < GCS_P; j++, bit++) rem = (rem << 1) | ((f[bit / 8] >> (7 - bit % 8)) & 1);
        value += (q << GCS_P) | rem;
        g->values[i] = value;
    }
    return SPSCAN_OK;
bad:
    free(g->values);
    g->values = NULL;
    return SPSCAN_ERR_FILTER;
}

static uint64_t gcs_hash(uint64_t k0, uint64_t k1, uint64_t n, const unsigned char *item, size_t len) {
    return mulhi64(siphash24(k0, k1, item, len), n * GCS_M);
}

static int gcs_contains(const gcs *g, uint64_t v) {
    size_t lo = 0, hi = (size_t)g->n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (g->values[mid] < v) lo = mid + 1;
        else hi = mid;
    }
    return lo < g->n && g->values[lo] == v;
}

int spscan_gcs_match_any(const unsigned char *filter, size_t filter_len,
                         const unsigned char block_hash[32], const unsigned char *const *items,
                         const size_t *item_lens, size_t n_items, int *match) {
    gcs g;
    size_t i;
    int ret;
    if (match == NULL || block_hash == NULL || (n_items && (items == NULL || item_lens == NULL))) {
        return SPSCAN_ERR_ARG;
    }
    *match = 0;
    if ((ret = gcs_decode(&g, filter, filter_len, block_hash)) != SPSCAN_OK) return ret;
    for (i = 0; i < n_items && g.n && !*match; i++) {
        *match = gcs_contains(&g, gcs_hash(g.k0, g.k1, g.n, items[i], item_lens[i]));
    }
    free(g.values);
    return SPSCAN_OK;
}

typedef struct {
    const unsigned char *data;
    size_t len;
} item;

static int cmp_item(const void *a, const void *b) {
    const item *x = a, *y = b;
    int c = memcmp(x->data, y->data, x->len < y->len ? x->len : y->len);
    return c ? c : (x->len > y->len) - (x->len < y->len);
}

static int cmp_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

int spscan_gcs_build(const unsigned char block_hash[32], const unsigned char *const *items,
                     const size_t *item_lens, size_t n_items, unsigned char *out, size_t *out_len) {
    item *order;
    size_t i, n = 0, pos = 0, bit = 0, cap;
    uint64_t *values, k0, k1, prev = 0;
    unsigned char *bits;

    if (block_hash == NULL || out_len == NULL || (n_items && (items == NULL || item_lens == NULL)) ||
        (*out_len && out == NULL)) {
        return SPSCAN_ERR_ARG;
    }
    cap = *out_len;
    order = malloc((n_items ? n_items : 1) * sizeof(item));
    values = malloc((n_items ? n_items : 1) * sizeof(uint64_t));
    if (order == NULL || values == NULL) {
        free(order);
        free(values);
        return SPSCAN_ERR_NOMEM;
    }
    for (i = 0; i < n_items; i++) {
        order[i].data = items[i];
        order[i].len = item_lens[i];
    }
    qsort(order, n_items, sizeof(item), cmp_item);
    for (i = 0; i < n_items; i++) {
        if (n == 0 || cmp_item(&order[n - 1], &order[i]) != 0) order[n++] = order[i];
    }
    k0 = le64(block_hash);
    k1 = le64(block_hash + 8);
    for (i = 0; i < n; i++) values[i] = gcs_hash(k0, k1, n, order[i].data, order[i].len);
    qsort(values, n, sizeof(uint64_t), cmp_u64);

    /* CompactSize count, then Golomb-Rice coded deltas, most significant bit first. */
    {
        unsigned char head[9];
        size_t hl;
        if (n < 0xfd) {
            head[0] = (unsigned char)n;
            hl = 1;
        } else {
            size_t size = n <= 0xffff ? 2 : (uint64_t)n <= 0xffffffffULL ? 4 : 8, b;
            head[0] = size == 2 ? 0xfd : size == 4 ? 0xfe : 0xff;
            for (b = 0; b < size; b++) head[1 + b] = (unsigned char)((uint64_t)n >> (8 * b));
            hl = 1 + size;
        }
        if (hl > cap) goto space;
        memcpy(out, head, hl);
        pos = hl;
    }
    bits = out + pos;
#define PUT_BIT(v) do { \
        if (pos + bit / 8 >= cap) goto space; \
        if (bit % 8 == 0) bits[bit / 8] = 0; \
        if (v) bits[bit / 8] |= (unsigned char)(0x80 >> (bit % 8)); \
        bit++; \
    } while (0)
    for (i = 0; i < n; i++) {
        uint64_t delta = values[i] - prev, q = delta >> GCS_P;
        int j;
        prev = values[i];
        while (q--) PUT_BIT(1);
        PUT_BIT(0);
        for (j = GCS_P - 1; j >= 0; j--) PUT_BIT((delta >> j) & 1);
    }
#undef PUT_BIT
    *out_len = pos + (bit + 7) / 8;
    free(order);
    free(values);
    return SPSCAN_OK;
space:
    *out_len = 9 + 3 * n_items + 8;
    free(order);
    free(values);
    return SPSCAN_ERR_SPACE;
}

static uint32_t filter_hit(void *arg, const unsigned char *x) {
    const gcs *g = arg;
    unsigned char script[34];
    script[0] = 0x51;
    script[1] = 0x20;
    memcpy(script + 2, x, 32);
    return gcs_contains(g, gcs_hash(g->k0, g->k1, g->n, script, 34)) ? 0 : NONE;
}

int spscan_filter_check(const spscan_receiver *r, const unsigned char *tweaks, size_t n_tweaks,
                        const unsigned char *filter, size_t filter_len,
                        const unsigned char block_hash[32], int *match) {
    gcs g;
    batch b;
    size_t ti;
    int ret;
    if (r == NULL || match == NULL || block_hash == NULL || (n_tweaks && tweaks == NULL)) {
        return SPSCAN_ERR_ARG;
    }
    *match = 0;
    if ((ret = gcs_decode(&g, filter, filter_len, block_hash)) != SPSCAN_OK) return ret;
    if (!batch_init(&b, r->n_labels)) {
        free(g.values);
        return SPSCAN_ERR_NOMEM;
    }
    for (ti = 0; ti < n_tweaks && g.n && !*match; ti++) {
        unsigned char ss[33], x[32];
        secp256k1_scalar t0;
        point P;
        uint32_t found;
        if ((ret = shared_secret(r, tweaks + 33 * ti, ss)) != SPSCAN_OK) break;
        ret = output_point(r, ss, 0, &t0, &P);
        secp256k1_scalar_clear(&t0);
        secp256k1_memclear_explicit(ss, sizeof(ss));
        if (ret != SPSCAN_OK) break;
        secp256k1_fe_get_b32(x, &P.p.x);
        *match = filter_hit(&g, x) != NONE ||
                 (r->n_labels && labels_by_addition(r, &b, &P, filter_hit, &g, &found) != NONE);
    }
    batch_free(&b);
    free(g.values);
    if (ret != SPSCAN_OK) *match = 0;
    return ret;
}
