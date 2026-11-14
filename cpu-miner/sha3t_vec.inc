/* Width-generic vectorized SHA3-256T scanner, VLANES nonces in parallel.
 *
 * Included by sha3t_avx2.c (VLANES=4, built with -mavx2) and sha3t_avx512.c
 * (VLANES=8, built with -mavx512f/dq/bw/vl). Uses GCC vector extensions so
 * the same source compiles to 256-bit or 512-bit code; rotates become vprolq
 * on AVX-512 automatically. These files must only be entered after the
 * runtime CPUID check in sha3t_pick() — nothing outside them is compiled
 * with SIMD flags.
 */

#include <stdint.h>
#include <string.h>

#include "sha3.h"
#include "util.h"

#define VCAT_(a, b) a##b
#define VCAT(a, b) VCAT_(a, b)
#define VFN(name) VCAT(name, FN_SUFFIX)

typedef uint64_t vec __attribute__((vector_size(8 * VLANES)));

static inline vec VFN(splat)(uint64_t x)
{
    vec v;
    for (int i = 0; i < VLANES; i++)
        v[i] = x;
    return v;
}

#define VROTL(v, n) (((v) << (n)) | ((v) >> (64 - (n))))

static const uint64_t VFN(rc)[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

static const int VFN(rotc)[24] = {
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
    27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
};

static const int VFN(piln)[24] = {
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
};

static void VFN(keccakf_vec)(vec st[25])
{
    vec bc[5], t;

    for (int round = 0; round < 24; round++) {
        for (int i = 0; i < 5; i++)
            bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
        for (int i = 0; i < 5; i++) {
            t = bc[(i + 4) % 5] ^ VROTL(bc[(i + 1) % 5], 1);
            for (int j = 0; j < 25; j += 5)
                st[j + i] ^= t;
        }
        t = st[1];
        for (int i = 0; i < 24; i++) {
            int j = VFN(piln)[i];
            bc[0] = st[j];
            st[j] = VROTL(t, VFN(rotc)[i]);
            t = bc[0];
        }
        for (int j = 0; j < 25; j += 5) {
            for (int i = 0; i < 5; i++)
                bc[i] = st[j + i];
            for (int i = 0; i < 5; i++)
                st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
        }
        st[0] ^= VFN(splat)(VFN(rc)[round]);
    }
}

static inline void VFN(round32_vec)(vec st[25])
{
    vec a = st[0], b = st[1], c = st[2], d = st[3];
    const vec zero = VFN(splat)(0);

    for (int i = 0; i < 25; i++)
        st[i] = zero;
    st[0] = a; st[1] = b; st[2] = c; st[3] = d;
    st[4] = VFN(splat)(0x06);
    st[16] = VFN(splat)(0x8000000000000000ULL);
    VFN(keccakf_vec)(st);
}

/* Triple-hash VLANES consecutive nonces n0..n0+VLANES-1; digests stay in
 * state lanes 0..3 (one instance per vector element). */
static void VFN(sha3t_batch)(const uint64_t hl[10], uint32_t n0, vec st[25])
{
    const vec zero = VFN(splat)(0);

    for (int i = 0; i < 25; i++)
        st[i] = zero;
    for (int i = 0; i < 9; i++)
        st[i] = VFN(splat)(hl[i]);
    for (int l = 0; l < VLANES; l++)
        st[9][l] = (hl[9] & 0xffffffffULL) |
                   ((uint64_t)__builtin_bswap32(n0 + (uint32_t)l) << 32);
    st[10] = VFN(splat)(0x06);
    st[16] = VFN(splat)(0x8000000000000000ULL);
    VFN(keccakf_vec)(st);
    VFN(round32_vec)(st);
    VFN(round32_vec)(st);
}

uint32_t VFN(sha3t_scan)(const uint8_t hdr[80], uint32_t n0, uint32_t count,
                         const uint32_t target[8], uint32_t *found_nonce,
                         int *found_flag)
{
    uint64_t hl[10];
    vec st[25];
    uint32_t hash[8];
    uint32_t done = 0;

    for (int i = 0; i < 10; i++)
        hl[i] = le64dec(hdr + 8 * i);

    while (done < count) {
        uint32_t batch = count - done;
        if (batch > VLANES)
            batch = VLANES;
        VFN(sha3t_batch)(hl, n0 + done, st);
        for (uint32_t l = 0; l < batch; l++) {
            if ((uint32_t)(st[3][l] >> 32) > target[7])
                continue;
            for (int k = 0; k < 4; k++) {
                hash[2 * k] = (uint32_t)st[k][l];
                hash[2 * k + 1] = (uint32_t)(st[k][l] >> 32);
            }
            if (fulltest(hash, target)) {
                *found_nonce = n0 + done + l;
                *found_flag = 1;
                return done + l + 1;
            }
        }
        done += batch;
    }
    return count;
}

void VFN(sha3t_hash)(const uint8_t hdr[80], uint32_t n0, uint32_t count,
                     uint8_t *out)
{
    uint64_t hl[10];
    vec st[25];
    uint32_t done = 0;

    for (int i = 0; i < 10; i++)
        hl[i] = le64dec(hdr + 8 * i);

    while (done < count) {
        uint32_t batch = count - done;
        if (batch > VLANES)
            batch = VLANES;
        VFN(sha3t_batch)(hl, n0 + done, st);
        for (uint32_t l = 0; l < batch; l++)
            for (int k = 0; k < 4; k++)
                le64enc(out + 32 * (size_t)(done + l) + 8 * k, st[k][l]);
        done += batch;
    }
}
