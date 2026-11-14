#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <pthread.h>

#include "util.h"

static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int hex2bin(uint8_t *out, const char *hex, size_t outlen)
{
    for (size_t i = 0; i < outlen; i++) {
        int hi = hexval((unsigned char)hex[2 * i]);
        int lo = hexval((unsigned char)hex[2 * i + 1]);
        if (hi < 0 || lo < 0)
            return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    if (hex[2 * outlen] != '\0')
        return -1;
    return 0;
}

void bin2hex(char *out, const uint8_t *in, size_t len)
{
    static const char d[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[2 * i] = d[in[i] >> 4];
        out[2 * i + 1] = d[in[i] & 0xf];
    }
    out[2 * len] = '\0';
}

void diff_to_target(uint32_t target[8], double diff)
{
    int k;
    uint64_t m;

    for (k = 6; k > 0 && diff > 1.0; k--)
        diff /= 4294967296.0;
    m = (uint64_t)(4294901760.0 / diff);
    if (m == 0 && k == 6) {
        memset(target, 0xff, 32);
    } else {
        memset(target, 0, 32);
        target[k] = (uint32_t)m;
        target[k + 1] = (uint32_t)(m >> 32);
    }
}

int fulltest(const uint32_t hash[8], const uint32_t target[8])
{
    for (int i = 7; i >= 0; i--) {
        if (hash[i] > target[i])
            return 0;
        if (hash[i] < target[i])
            return 1;
    }
    return 1;
}

double hash_to_diff(const uint32_t hash[8])
{
    /* truediffone = 0x00000000ffff0000...0000 as a double */
    static const double truediffone = 2.695953529101131e67;
    double d = 0.0;
    for (int i = 7; i >= 0; i--)
        d = d * 4294967296.0 + hash[i];
    if (d <= 0.0)
        return 0.0;
    return truediffone / d;
}

uint64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)(ts.tv_nsec / 1000000);
}

static pthread_mutex_t log_lock = PTHREAD_MUTEX_INITIALIZER;

void applog(const char *fmt, ...)
{
    va_list ap;
    char stamp[32];
    time_t t = time(NULL);
    struct tm tm;

    localtime_r(&t, &tm);
    strftime(stamp, sizeof stamp, "%H:%M:%S", &tm);

    pthread_mutex_lock(&log_lock);
    printf("[%s] ", stamp);
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf("\n");
    fflush(stdout);
    pthread_mutex_unlock(&log_lock);
}
