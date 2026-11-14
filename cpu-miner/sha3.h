#ifndef VECPOOL_SHA3_H
#define VECPOOL_SHA3_H

#include <stdint.h>
#include <stddef.h>

/* FIPS-202 SHA3-256, arbitrary length input */
void sha3_256(uint8_t out[32], const uint8_t *in, size_t len);

/* Triple SHA3-256 of an 80-byte header (nonce already placed at bytes 76..79) */
void sha3_256t_80(uint8_t out[32], const uint8_t hdr[80]);

/*
 * One SIMD implementation of the SHA3-256T nonce scanner.
 *
 * scan: hash `count` nonces n0, n0+1, ... over the 80-byte header template
 *       (bytes 76..79 are overwritten with the big-endian nonce, matching the
 *       cpuminer header convention). Returns the number of nonces consumed.
 *       Stops early when a hash <= target is found: *found_flag is set and
 *       *found_nonce holds the winning nonce; the return value includes it.
 *
 * hash_batch: like scan but writes all `count` raw 32-byte hashes to out
 *       (count * 32 bytes) — used by --selftest to cross-check paths.
 */
typedef struct {
    const char *name;   /* "scalar", "avx2", "avx512" */
    int lanes;          /* nonces hashed per inner iteration */
    int (*available)(void);
    uint32_t (*scan)(const uint8_t hdr[80], uint32_t n0, uint32_t count,
                     const uint32_t target[8], uint32_t *found_nonce,
                     int *found_flag);
    void (*hash_batch)(const uint8_t hdr[80], uint32_t n0, uint32_t count,
                       uint8_t *out);
} sha3t_impl_t;

extern const sha3t_impl_t sha3t_impls[];
extern const int sha3t_nimpls;

/* Pick an implementation: forced name ("scalar"/"avx2"/"avx512") or NULL for
 * the best one this CPU supports. Returns NULL if the forced name is unknown
 * or unsupported on this CPU. */
const sha3t_impl_t *sha3t_pick(const char *forced);

/* CPU brand string via CPUID, e.g. "AMD Ryzen 9 9950X 16-Core Processor" */
const char *cpu_brand(void);

/* provided by sha3t_avx2.c / sha3t_avx512.c (compiled with SIMD flags) */
uint32_t sha3t_scan_avx2(const uint8_t hdr[80], uint32_t n0, uint32_t count,
                         const uint32_t target[8], uint32_t *found_nonce,
                         int *found_flag);
void sha3t_hash_avx2(const uint8_t hdr[80], uint32_t n0, uint32_t count,
                     uint8_t *out);
uint32_t sha3t_scan_avx512(const uint8_t hdr[80], uint32_t n0, uint32_t count,
                           const uint32_t target[8], uint32_t *found_nonce,
                           int *found_flag);
void sha3t_hash_avx512(const uint8_t hdr[80], uint32_t n0, uint32_t count,
                       uint8_t *out);

#endif
