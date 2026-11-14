#ifndef VECPOOL_UTIL_H
#define VECPOOL_UTIL_H

#include <stdint.h>
#include <stddef.h>

static inline uint32_t le32dec(const void *p)
{
    const uint8_t *b = (const uint8_t *)p;
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) |
           ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}

static inline void le32enc(void *p, uint32_t x)
{
    uint8_t *b = (uint8_t *)p;
    b[0] = (uint8_t)x; b[1] = (uint8_t)(x >> 8);
    b[2] = (uint8_t)(x >> 16); b[3] = (uint8_t)(x >> 24);
}

static inline uint32_t be32dec(const void *p)
{
    const uint8_t *b = (const uint8_t *)p;
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
           ((uint32_t)b[2] << 8) | (uint32_t)b[3];
}

static inline void be32enc(void *p, uint32_t x)
{
    uint8_t *b = (uint8_t *)p;
    b[0] = (uint8_t)(x >> 24); b[1] = (uint8_t)(x >> 16);
    b[2] = (uint8_t)(x >> 8); b[3] = (uint8_t)x;
}

static inline uint64_t le64dec(const void *p)
{
    const uint8_t *b = (const uint8_t *)p;
    return (uint64_t)le32dec(b) | ((uint64_t)le32dec(b + 4) << 32);
}

static inline void le64enc(void *p, uint64_t x)
{
    le32enc(p, (uint32_t)x);
    le32enc((uint8_t *)p + 4, (uint32_t)(x >> 32));
}

/* hex string -> bytes; returns 0 on success, -1 on bad input/length */
int hex2bin(uint8_t *out, const char *hex, size_t outlen);
/* bytes -> lowercase hex, NUL-terminated (out must hold 2*len+1) */
void bin2hex(char *out, const uint8_t *in, size_t len);

/* Bitcoin-style share target from a pool difficulty (cpuminer convention). */
void diff_to_target(uint32_t target[8], double diff);
/* hash <= target, both as 8 little-endian uint32 words, word 7 most significant */
int fulltest(const uint32_t hash[8], const uint32_t target[8]);
/* difficulty actually achieved by a hash (for logging) */
double hash_to_diff(const uint32_t hash[8]);

uint64_t now_ms(void);

void applog(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

#endif
