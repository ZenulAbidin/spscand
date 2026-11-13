/* Checks of the internal hashes and of filter coding that the Python tests
 * cannot reach. The BIP352 and BIP158 vectors run from spscand's tests/. */

#include "../src/spscan.c"

#include <stdio.h>

static int failures;

#define T_ASSERT(cond) do { \
        if (!(cond)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #cond); failures++; } \
    } while (0)

static void hex(unsigned char *out, const char *s) {
    size_t i;
    for (i = 0; s[2 * i]; i++) {
        unsigned int b;
        sscanf(s + 2 * i, "%2x", &b);
        out[i] = (unsigned char)b;
    }
}

static void test_ripemd160(void) {
    static const struct { const char *msg, *digest; } v[] = {
        {"", "9c1185a5c5e9fc54612808977ee8f548b2258d31"},
        {"abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"},
        {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
         "12a053384a9c0c88e405a06c27dcf49ada62eb2b"},
        {"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
         "9b752e45573d4b39f4dbd3323cab82bf63326bfb"},
    };
    size_t i;
    for (i = 0; i < sizeof(v) / sizeof(v[0]); i++) {
        unsigned char got[20], want[20];
        ripemd160(got, (const unsigned char *)v[i].msg, strlen(v[i].msg));
        hex(want, v[i].digest);
        T_ASSERT(memcmp(got, want, 20) == 0);
    }
}

static void test_siphash(void) {
    /* Reference vectors: key 00..0f, message 00..0e and the empty message. */
    unsigned char key[16], msg[15];
    size_t i;
    for (i = 0; i < 16; i++) key[i] = (unsigned char)i;
    for (i = 0; i < 15; i++) msg[i] = (unsigned char)i;
    T_ASSERT(siphash24(le64(key), le64(key + 8), msg, 15) == 0xa129ca6149be45e5ULL);
    T_ASSERT(siphash24(le64(key), le64(key + 8), msg, 0) == 0x726fdb47dd0e0e31ULL);
}

static void test_mulhi(void) {
    T_ASSERT(mulhi64(UINT64_MAX, UINT64_MAX) == UINT64_MAX - 1);
    T_ASSERT(mulhi64(1ULL << 63, 4) == 2);
}

static void test_gcs_round_trip(void) {
    unsigned char hash[32], items[300][20], filter[2000];
    const unsigned char *ptrs[301];
    size_t lens[301], len = sizeof(filter), small = 10, i;
    int match;
    for (i = 0; i < 32; i++) hash[i] = (unsigned char)(i * 7);
    for (i = 0; i < 300; i++) {
        memset(items[i], 0, 20);
        items[i][0] = (unsigned char)i;
        items[i][1] = (unsigned char)(i >> 8);
        ptrs[i] = items[i];
        lens[i] = 20;
    }
    ptrs[300] = items[5];  /* a duplicate, which is dropped */
    lens[300] = 20;
    T_ASSERT(spscan_gcs_build(hash, ptrs, lens, 301, filter, &len) == SPSCAN_OK);
    T_ASSERT(filter[0] == 0xfd && filter[1] == 300 % 256 && filter[2] == 1);
    for (i = 0; i < 300; i++) {
        T_ASSERT(spscan_gcs_match_any(filter, len, hash, &ptrs[i], &lens[i], 1, &match) == 0 && match);
    }
    T_ASSERT(spscan_gcs_build(hash, ptrs, lens, 301, filter, &small) == SPSCAN_ERR_SPACE);
    T_ASSERT(small == 9 + 3 * 301 + 8);
    T_ASSERT(spscan_gcs_match_any(filter, 3, hash, ptrs, lens, 1, &match) == SPSCAN_ERR_FILTER);
    len = sizeof(filter);
    T_ASSERT(spscan_gcs_build(hash, NULL, NULL, 0, filter, &len) == SPSCAN_OK && len == 1 && filter[0] == 0);
    T_ASSERT(spscan_gcs_match_any(filter, len, hash, ptrs, lens, 1, &match) == SPSCAN_OK && !match);
}

int main(void) {
    test_ripemd160();
    test_siphash();
    test_mulhi();
    test_gcs_round_trip();
    if (failures) {
        fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    printf("libspscan %s: internal checks passed\n", spscan_version());
    return 0;
}
