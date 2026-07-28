/* Scalar FIPS-202 SHA3-256 and the triple-hash (SHA3-256T) used by
 * Bitcoin III / FJARCODE proof-of-work. */

#include <string.h>

#include "sha3.h"
#include "util.h"

static const uint64_t keccakf_rc[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

static const int keccakf_rotc[24] = {
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
    27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
};

static const int keccakf_piln[24] = {
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
};

#define ROTL64(x, n) (((x) << (n)) | ((x) >> (64 - (n))))

static void keccakf1600(uint64_t st[25])
{
    uint64_t bc[5], t;

    for (int round = 0; round < 24; round++) {
        /* theta */
        for (int i = 0; i < 5; i++)
            bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
        for (int i = 0; i < 5; i++) {
            t = bc[(i + 4) % 5] ^ ROTL64(bc[(i + 1) % 5], 1);
            for (int j = 0; j < 25; j += 5)
                st[j + i] ^= t;
        }
        /* rho + pi */
        t = st[1];
        for (int i = 0; i < 24; i++) {
            int j = keccakf_piln[i];
            bc[0] = st[j];
            st[j] = ROTL64(t, keccakf_rotc[i]);
            t = bc[0];
        }
        /* chi */
        for (int j = 0; j < 25; j += 5) {
            for (int i = 0; i < 5; i++)
                bc[i] = st[j + i];
            for (int i = 0; i < 5; i++)
                st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
        }
        /* iota */
        st[0] ^= keccakf_rc[round];
    }
}

#define SHA3_RATE 136 /* SHA3-256 rate in bytes */

void sha3_256(uint8_t out[32], const uint8_t *in, size_t len)
{
    uint64_t st[25];
    uint8_t block[SHA3_RATE];

    memset(st, 0, sizeof st);

    while (len >= SHA3_RATE) {
        for (int i = 0; i < SHA3_RATE / 8; i++)
            st[i] ^= le64dec(in + 8 * i);
        keccakf1600(st);
        in += SHA3_RATE;
        len -= SHA3_RATE;
    }

    memset(block, 0, sizeof block);
    memcpy(block, in, len);
    block[len] = 0x06;
    block[SHA3_RATE - 1] |= 0x80;
    for (int i = 0; i < SHA3_RATE / 8; i++)
        st[i] ^= le64dec(block + 8 * i);
    keccakf1600(st);

    for (int i = 0; i < 4; i++)
        le64enc(out + 8 * i, st[i]);
}

/* Second/third rounds always take a 32-byte input: state lanes 0..3 carry the
 * previous digest, lane 4 gets the 0x06 domain pad, lane 16 the final bit. */
static inline void sha3_round32(uint64_t st[25])
{
    uint64_t a = st[0], b = st[1], c = st[2], d = st[3];

    memset(st, 0, 25 * sizeof(uint64_t));
    st[0] = a; st[1] = b; st[2] = c; st[3] = d;
    st[4] = 0x06;
    st[16] = 0x8000000000000000ULL;
    keccakf1600(st);
}

static void sha3_256t_lanes(uint64_t st[25], const uint64_t hl[10])
{
    memset(st, 0, 25 * sizeof(uint64_t));
    memcpy(st, hl, 10 * sizeof(uint64_t));
    st[10] = 0x06;
    st[16] = 0x8000000000000000ULL;
    keccakf1600(st);
    sha3_round32(st);
    sha3_round32(st);
}

void sha3_256t_80(uint8_t out[32], const uint8_t hdr[80])
{
    uint64_t hl[10], st[25];

    for (int i = 0; i < 10; i++)
        hl[i] = le64dec(hdr + 8 * i);
    sha3_256t_lanes(st, hl);
    for (int i = 0; i < 4; i++)
        le64enc(out + 8 * i, st[i]);
}

/* Header lane 9 holds bytes 72..79: nbits (low 32 bits) and the nonce field
 * (high 32 bits). The header stores the nonce big-endian, so the lane value
 * carries bswap32(nonce). */
static inline uint64_t lane9_with_nonce(uint64_t lane9, uint32_t nonce)
{
    return (lane9 & 0xffffffffULL) |
           ((uint64_t)__builtin_bswap32(nonce) << 32);
}

static uint32_t sha3t_scan_scalar(const uint8_t hdr[80], uint32_t n0,
                                  uint32_t count, const uint32_t target[8],
                                  uint32_t *found_nonce, int *found_flag)
{
    uint64_t hl[10], st[25];
    uint32_t hash[8];

    for (int i = 0; i < 10; i++)
        hl[i] = le64dec(hdr + 8 * i);

    for (uint32_t i = 0; i < count; i++) {
        hl[9] = lane9_with_nonce(hl[9], n0 + i);
        sha3_256t_lanes(st, hl);
        if ((uint32_t)(st[3] >> 32) > target[7])
            continue;
        for (int k = 0; k < 4; k++) {
            hash[2 * k] = (uint32_t)st[k];
            hash[2 * k + 1] = (uint32_t)(st[k] >> 32);
        }
        if (fulltest(hash, target)) {
            *found_nonce = n0 + i;
            *found_flag = 1;
            return i + 1;
        }
    }
    return count;
}

static void sha3t_hash_scalar(const uint8_t hdr[80], uint32_t n0,
                              uint32_t count, uint8_t *out)
{
    uint8_t h[80];

    memcpy(h, hdr, 80);
    for (uint32_t i = 0; i < count; i++) {
        be32enc(h + 76, n0 + i);
        sha3_256t_80(out + 32 * (size_t)i, h);
    }
}

static int always_available(void)
{
    return 1;
}

static int have_avx2(void)
{
    return __builtin_cpu_supports("avx2");
}

static int have_avx512(void)
{
    return __builtin_cpu_supports("avx512f") &&
           __builtin_cpu_supports("avx512dq") &&
           __builtin_cpu_supports("avx512bw") &&
           __builtin_cpu_supports("avx512vl");
}

/* Ordered worst to best; sha3t_pick() walks it backwards. */
const sha3t_impl_t sha3t_impls[] = {
    { "scalar", 1, always_available, sha3t_scan_scalar, sha3t_hash_scalar },
    { "avx2",   4, have_avx2,        sha3t_scan_avx2,   sha3t_hash_avx2 },
    { "avx512", 8, have_avx512,      sha3t_scan_avx512, sha3t_hash_avx512 },
};
const int sha3t_nimpls = (int)(sizeof sha3t_impls / sizeof sha3t_impls[0]);

const sha3t_impl_t *sha3t_pick(const char *forced)
{
    if (forced) {
        for (int i = 0; i < sha3t_nimpls; i++)
            if (!strcmp(sha3t_impls[i].name, forced))
                return sha3t_impls[i].available() ? &sha3t_impls[i] : NULL;
        return NULL;
    }
    for (int i = sha3t_nimpls - 1; i >= 0; i--)
        if (sha3t_impls[i].available())
            return &sha3t_impls[i];
    return NULL;
}

const char *cpu_brand(void)
{
    static char brand[49];

    if (!brand[0]) {
        unsigned int r[12] = { 0 };
        for (int i = 0; i < 3; i++)
            __asm__ volatile("cpuid"
                             : "=a"(r[4 * i]), "=b"(r[4 * i + 1]),
                               "=c"(r[4 * i + 2]), "=d"(r[4 * i + 3])
                             : "a"(0x80000002u + i), "c"(0));
        memcpy(brand, r, 48);
        brand[48] = '\0';
        /* trim leading spaces some CPUs pad with */
        char *p = brand;
        while (*p == ' ')
            p++;
        if (p != brand)
            memmove(brand, p, strlen(p) + 1);
        if (!brand[0])
            strcpy(brand, "unknown x86_64");
    }
    return brand;
}
