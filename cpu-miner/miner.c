/* vecpool-cpu-miner — SHA3-256T (Bitcoin III / FJARCODE) stratum CPU miner
 * with runtime SIMD dispatch: AVX-512 (8-way) / AVX2 (4-way) / scalar.
 *
 * The instruction set is chosen once at startup via CPUID, so one binary
 * runs everywhere: a Ryzen 9 9950X takes the AVX-512 path, a Xeon E5-2699 v4
 * or i7-7700K takes AVX2, and anything older falls back to scalar.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <inttypes.h>
#include <pthread.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netdb.h>

#include <openssl/sha.h>

#include "util.h"
#include "sha3.h"
#include "json.h"

#define VERSION "1.2-cpu"
#define MAX_THREADS 256
#define MAX_BRANCHES 64
#define SCAN_CHUNK (1u << 18)
#define PENDING_SLOTS 128
#define NONCE_SPACE (1ULL << 32)

static struct {
    const char *url, *host, *port;
    const char *user, *pass;
    int threads;
    const char *simd;       /* NULL = auto */
    double diff_factor;
    int time_limit;         /* seconds, 0 = none */
} cfg = { .pass = "x", .diff_factor = 1.0 };

typedef struct submit_entry {
    struct submit_entry *next;
    char job_id[128];
    char xnonce2_hex[65];
    char ntime_hex[16];
    char nonce_hex[9];
    double share_diff;
    int thr;
} submit_entry_t;

static struct {
    pthread_mutex_t lock;

    /* pool session */
    uint8_t xnonce1[32];
    int xnonce1_len;
    int xn2_size;
    uint64_t xnonce2_counter;

    /* latest mining.notify */
    int have_job;
    char job_id[128];
    uint8_t prevhash[32];
    char *coinb1_hex, *coinb2_hex;
    uint8_t branches[MAX_BRANCHES][32];
    int nbranches;
    uint8_t version_bin[4], nbits_bin[4], ntime_bin[4];
    char ntime_hex[16];
    double diff, next_diff;

    submit_entry_t *subq_head, *subq_tail;

    struct {
        int used;
        double diff;
        int thr;
    } pending[PENDING_SLOTS];

    _Atomic uint64_t gen;
    _Atomic uint64_t accepted, rejected;
} g = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
    .xn2_size = 4,
    .diff = 1.0,
};

static _Atomic int running = 1;
static _Atomic uint64_t thr_hashes[MAX_THREADS];
static const sha3t_impl_t *impl;

static void sha256d(uint8_t out[32], const uint8_t *in, size_t len)
{
    uint8_t t[32];

    SHA256(in, len, t);
    SHA256(t, 32, out);
}

/* ---- header construction (cpuminer/yiimp stratum convention) -------------
 * bytes 0..3   version hex bytes reversed
 * bytes 4..35  prevhash with every 4-byte group reversed
 * bytes 36..67 merkle root (sha256d output order, as-is)
 * bytes 68..71 ntime hex bytes reversed
 * bytes 72..75 nbits hex bytes reversed
 * bytes 76..79 nonce, big-endian; submitted as hex of the reversed bytes
 */

static void compute_merkle_root(uint8_t root[32], const uint8_t *coinbase,
                                size_t cb_len,
                                const uint8_t branches[][32], int nbranches)
{
    uint8_t buf[64];

    sha256d(root, coinbase, cb_len);
    for (int i = 0; i < nbranches; i++) {
        memcpy(buf, root, 32);
        memcpy(buf + 32, branches[i], 32);
        sha256d(root, buf, 64);
    }
}

static void build_header(uint8_t header[80], const uint8_t version[4],
                         const uint8_t prevhash[32], const uint8_t merkle[32],
                         const uint8_t ntime[4], const uint8_t nbits[4])
{
    for (int i = 0; i < 4; i++)
        header[i] = version[3 - i];
    for (int i = 0; i < 8; i++)
        for (int k = 0; k < 4; k++)
            header[4 + 4 * i + k] = prevhash[4 * i + 3 - k];
    memcpy(header + 36, merkle, 32);
    for (int i = 0; i < 4; i++) {
        header[68 + i] = ntime[3 - i];
        header[72 + i] = nbits[3 - i];
    }
    memset(header + 76, 0, 4);
}

/* ---- per-thread work ---------------------------------------------------- */

typedef struct {
    uint8_t header[80];
    uint32_t target[8];
    char job_id[128];
    char ntime_hex[16];
    char xnonce2_hex[65];
    uint64_t gen;
} work_t;

static int build_work(work_t *w)
{
    uint8_t coinbase[4096], xnonce2[32], merkle[32];
    size_t cb1_len, cb2_len, pos = 0;
    uint64_t ctr;

    pthread_mutex_lock(&g.lock);
    if (!g.have_job || !g.coinb1_hex || !g.coinb2_hex) {
        pthread_mutex_unlock(&g.lock);
        return 0;
    }

    cb1_len = strlen(g.coinb1_hex) / 2;
    cb2_len = strlen(g.coinb2_hex) / 2;
    if (cb1_len + (size_t)g.xnonce1_len + (size_t)g.xn2_size + cb2_len >
        sizeof coinbase) {
        pthread_mutex_unlock(&g.lock);
        return 0;
    }

    ctr = g.xnonce2_counter++;
    memset(xnonce2, 0, sizeof xnonce2);
    for (int i = 0; i < g.xn2_size && i < 8; i++)
        xnonce2[i] = (uint8_t)(ctr >> (8 * i));

    if (hex2bin(coinbase, g.coinb1_hex, cb1_len)) {
        pthread_mutex_unlock(&g.lock);
        return 0;
    }
    pos = cb1_len;
    memcpy(coinbase + pos, g.xnonce1, (size_t)g.xnonce1_len);
    pos += (size_t)g.xnonce1_len;
    memcpy(coinbase + pos, xnonce2, (size_t)g.xn2_size);
    pos += (size_t)g.xn2_size;
    if (hex2bin(coinbase + pos, g.coinb2_hex, cb2_len)) {
        pthread_mutex_unlock(&g.lock);
        return 0;
    }
    pos += cb2_len;

    compute_merkle_root(merkle, coinbase, pos, g.branches, g.nbranches);
    build_header(w->header, g.version_bin, g.prevhash, merkle, g.ntime_bin,
                 g.nbits_bin);
    diff_to_target(w->target, g.diff / cfg.diff_factor);

    snprintf(w->job_id, sizeof w->job_id, "%s", g.job_id);
    snprintf(w->ntime_hex, sizeof w->ntime_hex, "%s", g.ntime_hex);
    bin2hex(w->xnonce2_hex, xnonce2, (size_t)g.xn2_size);
    w->gen = atomic_load(&g.gen);

    pthread_mutex_unlock(&g.lock);
    return 1;
}

static void submit_share(const work_t *w, uint32_t nonce, int thr)
{
    submit_entry_t *e = calloc(1, sizeof *e);
    uint8_t hdr[80], hash[32], nonce_le[4];
    uint32_t hash32[8];

    if (!e)
        return;

    memcpy(hdr, w->header, 80);
    be32enc(hdr + 76, nonce);
    sha3_256t_80(hash, hdr);
    for (int i = 0; i < 8; i++)
        hash32[i] = le32dec(hash + 4 * i);

    snprintf(e->job_id, sizeof e->job_id, "%s", w->job_id);
    snprintf(e->xnonce2_hex, sizeof e->xnonce2_hex, "%s", w->xnonce2_hex);
    snprintf(e->ntime_hex, sizeof e->ntime_hex, "%s", w->ntime_hex);
    le32enc(nonce_le, nonce);
    bin2hex(e->nonce_hex, nonce_le, 4);
    e->share_diff = hash_to_diff(hash32);
    e->thr = thr;

    pthread_mutex_lock(&g.lock);
    if (g.subq_tail)
        g.subq_tail->next = e;
    else
        g.subq_head = e;
    g.subq_tail = e;
    pthread_mutex_unlock(&g.lock);

    applog("thread %d: share found, nonce %08x, diff %.3f", thr, nonce,
           e->share_diff);
}

static void *worker_thread(void *arg)
{
    int id = (int)(intptr_t)arg;
    work_t w;

    while (atomic_load(&running)) {
        if (!build_work(&w)) {
            usleep(200 * 1000);
            continue;
        }
        uint64_t n = 0;
        while (atomic_load(&running) && atomic_load(&g.gen) == w.gen &&
               n < NONCE_SPACE) {
            uint32_t chunk = SCAN_CHUNK;
            if (NONCE_SPACE - n < chunk)
                chunk = (uint32_t)(NONCE_SPACE - n);

            uint32_t found_nonce = 0;
            int found = 0;
            uint32_t done = impl->scan(w.header, (uint32_t)n, chunk,
                                       w.target, &found_nonce, &found);
            atomic_fetch_add(&thr_hashes[id], done);
            n += done;
            if (found)
                submit_share(&w, found_nonce, id);
        }
        /* nonce space exhausted: loop around and take a fresh extranonce2 */
    }
    return NULL;
}

/* ---- stratum ------------------------------------------------------------ */

static int sock_send_line(int fd, const char *line)
{
    size_t len = strlen(line), off = 0;

    while (off < len) {
        ssize_t n = send(fd, line + off, len - off, MSG_NOSIGNAL);
        if (n <= 0)
            return -1;
        off += (size_t)n;
    }
    return 0;
}

static int pool_connect(void)
{
    struct addrinfo hints, *res, *ai;
    int fd = -1;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(cfg.host, cfg.port, &hints, &res)) {
        applog("stratum: cannot resolve %s", cfg.host);
        return -1;
    }
    for (ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0)
            continue;
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0)
            break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

static void job_invalidate_locked(void)
{
    g.have_job = 0;
    atomic_fetch_add(&g.gen, 1);
}

static int handle_notify(const jval_t *params)
{
    const jval_t *branches = json_idx(params, 4);
    const char *job_id, *prevhash, *cb1, *cb2, *version, *nbits, *ntime;

    job_id = json_idx(params, 0) && json_idx(params, 0)->type == J_STR
                 ? json_idx(params, 0)->str : NULL;
    prevhash = json_idx(params, 1) && json_idx(params, 1)->type == J_STR
                   ? json_idx(params, 1)->str : NULL;
    cb1 = json_idx(params, 2) && json_idx(params, 2)->type == J_STR
              ? json_idx(params, 2)->str : NULL;
    cb2 = json_idx(params, 3) && json_idx(params, 3)->type == J_STR
              ? json_idx(params, 3)->str : NULL;
    version = json_idx(params, 5) && json_idx(params, 5)->type == J_STR
                  ? json_idx(params, 5)->str : NULL;
    nbits = json_idx(params, 6) && json_idx(params, 6)->type == J_STR
                ? json_idx(params, 6)->str : NULL;
    ntime = json_idx(params, 7) && json_idx(params, 7)->type == J_STR
                ? json_idx(params, 7)->str : NULL;

    if (!job_id || !prevhash || !cb1 || !cb2 || !version || !nbits ||
        !ntime || !branches || branches->type != J_ARR ||
        branches->n > MAX_BRANCHES || strlen(prevhash) != 64 ||
        strlen(version) != 8 || strlen(nbits) != 8 || strlen(ntime) != 8 ||
        strlen(cb1) % 2 || strlen(cb2) % 2) {
        applog("stratum: malformed mining.notify, ignored");
        return -1;
    }

    pthread_mutex_lock(&g.lock);
    if (hex2bin(g.prevhash, prevhash, 32) ||
        hex2bin(g.version_bin, version, 4) ||
        hex2bin(g.nbits_bin, nbits, 4) || hex2bin(g.ntime_bin, ntime, 4))
        goto bad;
    for (int i = 0; i < branches->n; i++) {
        const jval_t *b = branches->items[i];
        if (!b || b->type != J_STR || strlen(b->str) != 64 ||
            hex2bin(g.branches[i], b->str, 32))
            goto bad;
    }
    g.nbranches = branches->n;

    free(g.coinb1_hex);
    free(g.coinb2_hex);
    g.coinb1_hex = strdup(cb1);
    g.coinb2_hex = strdup(cb2);
    if (!g.coinb1_hex || !g.coinb2_hex)
        goto bad;

    snprintf(g.job_id, sizeof g.job_id, "%s", job_id);
    snprintf(g.ntime_hex, sizeof g.ntime_hex, "%s", ntime);
    if (g.next_diff > 0) {
        g.diff = g.next_diff;
        g.next_diff = 0;
    }
    g.xnonce2_counter = 0;
    g.have_job = 1;
    atomic_fetch_add(&g.gen, 1);
    pthread_mutex_unlock(&g.lock);

    applog("new job %s (diff %g, %d merkle branches)", job_id, g.diff,
           branches->n);
    return 0;
bad:
    job_invalidate_locked();
    pthread_mutex_unlock(&g.lock);
    applog("stratum: bad hex in mining.notify, job dropped");
    return -1;
}

static int set_extranonce(const jval_t *xn1, const jval_t *xn2sz)
{
    if (!xn1 || xn1->type != J_STR || strlen(xn1->str) % 2 ||
        strlen(xn1->str) / 2 > sizeof g.xnonce1 || !xn2sz ||
        xn2sz->type != J_NUM || xn2sz->num < 1 || xn2sz->num > 32)
        return -1;

    pthread_mutex_lock(&g.lock);
    g.xnonce1_len = (int)(strlen(xn1->str) / 2);
    if (hex2bin(g.xnonce1, xn1->str, (size_t)g.xnonce1_len)) {
        g.xnonce1_len = 0;
        pthread_mutex_unlock(&g.lock);
        return -1;
    }
    g.xn2_size = (int)xn2sz->num;
    pthread_mutex_unlock(&g.lock);
    return 0;
}

/* returns -1 to force a reconnect */
static int handle_line(int fd, const char *line, uint64_t *next_id,
                       int *authorized)
{
    jval_t *v = json_parse(line);
    int rc = 0;

    if (!v) {
        applog("stratum: unparseable line ignored: %.120s", line);
        return 0;
    }

    const char *method = json_get_str(v, "method");
    if (method) {
        const jval_t *params = json_get(v, "params");

        if (!strcmp(method, "mining.notify")) {
            handle_notify(params);
        } else if (!strcmp(method, "mining.set_difficulty")) {
            const jval_t *d = json_idx(params, 0);
            if (d && d->type == J_NUM && d->num > 0) {
                pthread_mutex_lock(&g.lock);
                g.next_diff = d->num;
                pthread_mutex_unlock(&g.lock);
                applog("difficulty set to %g (applies on next job)", d->num);
            }
        } else if (!strcmp(method, "mining.set_extranonce")) {
            if (set_extranonce(json_idx(params, 0), json_idx(params, 1)))
                applog("stratum: bad set_extranonce ignored");
        } else if (!strcmp(method, "client.reconnect")) {
            applog("stratum: pool requested reconnect");
            rc = -1;
        } else if (!strcmp(method, "client.get_version")) {
            const jval_t *id = json_get(v, "id");
            if (id && id->type == J_NUM) {
                char buf[128];
                snprintf(buf, sizeof buf,
                         "{\"id\":%.0f,\"result\":\"vecpool-cpu-miner/"
                         VERSION "\",\"error\":null}\n", id->num);
                if (sock_send_line(fd, buf))
                    rc = -1;
            }
        } else if (!strcmp(method, "client.show_message")) {
            const jval_t *m = json_idx(params, 0);
            if (m && m->type == J_STR)
                applog("pool message: %s", m->str);
        }
        json_free(v);
        return rc;
    }

    double id = json_get_num(v, "id", -1);
    const jval_t *result = json_get(v, "result");
    const jval_t *error = json_get(v, "error");

    if (id == 1) {
        /* subscribe result: [[subscriptions], xnonce1, xn2_size] */
        if (!result || result->type != J_ARR ||
            set_extranonce(json_idx(result, 1), json_idx(result, 2))) {
            applog("stratum: bad subscribe response");
            rc = -1;
        } else {
            char buf[512];
            applog("subscribed: extranonce1 %d bytes, extranonce2 %d bytes",
                   g.xnonce1_len, g.xn2_size);
            snprintf(buf, sizeof buf,
                     "{\"id\":2,\"method\":\"mining.authorize\","
                     "\"params\":[\"%s\",\"%s\"]}\n", cfg.user, cfg.pass);
            if (sock_send_line(fd, buf))
                rc = -1;
        }
    } else if (id == 2) {
        if (result && (result->type == J_BOOL || result->type == J_NULL) &&
            result->num != 0) {
            applog("authorized as %s", cfg.user);
            *authorized = 1;
        } else {
            applog("authorization FAILED — check wallet/worker name");
            rc = -1;
        }
    } else if (id >= 10) {
        int slot = (int)((uint64_t)id % PENDING_SLOTS);
        double sdiff = 0;
        int thr = -1;

        pthread_mutex_lock(&g.lock);
        if (g.pending[slot].used) {
            sdiff = g.pending[slot].diff;
            thr = g.pending[slot].thr;
            g.pending[slot].used = 0;
        }
        pthread_mutex_unlock(&g.lock);

        int ok = result && result->num != 0 &&
                 (result->type == J_BOOL || result->type == J_NUM);
        if (ok) {
            uint64_t a = atomic_fetch_add(&g.accepted, 1) + 1;
            applog("accepted %" PRIu64 "/%" PRIu64 " (thread %d, diff %.3f)",
                   a, a + atomic_load(&g.rejected), thr, sdiff);
        } else {
            uint64_t r = atomic_fetch_add(&g.rejected, 1) + 1;
            const jval_t *emsg = json_idx(error, 1);
            applog("REJECTED %" PRIu64 " (thread %d, diff %.3f)%s%s", r, thr,
                   sdiff,
                   emsg && emsg->type == J_STR ? ": " : "",
                   emsg && emsg->type == J_STR ? emsg->str : "");
        }
    }
    (void)next_id;
    json_free(v);
    return rc;
}

static void drain_submit_queue(int fd, uint64_t *next_id, int *net_error)
{
    for (;;) {
        submit_entry_t *e;

        pthread_mutex_lock(&g.lock);
        e = g.subq_head;
        if (e) {
            g.subq_head = e->next;
            if (!g.subq_head)
                g.subq_tail = NULL;
        }
        pthread_mutex_unlock(&g.lock);
        if (!e)
            return;

        uint64_t id = (*next_id)++;
        int slot = (int)(id % PENDING_SLOTS);

        pthread_mutex_lock(&g.lock);
        g.pending[slot].used = 1;
        g.pending[slot].diff = e->share_diff;
        g.pending[slot].thr = e->thr;
        pthread_mutex_unlock(&g.lock);

        char buf[1024];
        snprintf(buf, sizeof buf,
                 "{\"id\":%" PRIu64 ",\"method\":\"mining.submit\","
                 "\"params\":[\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"]}\n",
                 id, cfg.user, e->job_id, e->xnonce2_hex, e->ntime_hex,
                 e->nonce_hex);
        if (sock_send_line(fd, buf))
            *net_error = 1;
        free(e);
        if (*net_error)
            return;
    }
}

static void *stratum_thread(void *arg)
{
    int backoff = 2;

    (void)arg;
    while (atomic_load(&running)) {
        int fd = pool_connect();

        if (fd < 0) {
            applog("stratum: connect to %s:%s failed, retrying in %ds",
                   cfg.host, cfg.port, backoff);
            for (int i = 0; i < backoff * 10 && atomic_load(&running); i++)
                usleep(100 * 1000);
            if (backoff < 30)
                backoff *= 2;
            continue;
        }
        applog("connected to %s:%s", cfg.host, cfg.port);
        backoff = 2;

        char sub[256];
        snprintf(sub, sizeof sub,
                 "{\"id\":1,\"method\":\"mining.subscribe\","
                 "\"params\":[\"vecpool-cpu-miner/" VERSION "\"]}\n");
        if (sock_send_line(fd, sub)) {
            close(fd);
            continue;
        }

        char rbuf[16384];
        size_t rlen = 0;
        uint64_t next_id = 10;
        int authorized = 0, net_error = 0;

        while (atomic_load(&running) && !net_error) {
            fd_set rfds;
            struct timeval tv = { 0, 100 * 1000 };

            FD_ZERO(&rfds);
            FD_SET(fd, &rfds);
            int sel = select(fd + 1, &rfds, NULL, NULL, &tv);
            if (sel < 0 && errno != EINTR)
                break;

            if (sel > 0 && FD_ISSET(fd, &rfds)) {
                ssize_t n = recv(fd, rbuf + rlen, sizeof rbuf - rlen - 1, 0);
                if (n <= 0) {
                    applog("stratum: connection closed by pool");
                    break;
                }
                rlen += (size_t)n;
                rbuf[rlen] = '\0';

                char *start = rbuf, *nl;
                while ((nl = strchr(start, '\n'))) {
                    *nl = '\0';
                    if (*start &&
                        handle_line(fd, start, &next_id, &authorized) < 0) {
                        net_error = 1;
                        break;
                    }
                    start = nl + 1;
                }
                rlen = (size_t)(rbuf + rlen - start);
                memmove(rbuf, start, rlen);
                if (rlen >= sizeof rbuf - 1) {
                    applog("stratum: oversized line, reconnecting");
                    break;
                }
            }
            drain_submit_queue(fd, &next_id, &net_error);
        }
        close(fd);
        pthread_mutex_lock(&g.lock);
        job_invalidate_locked();
        pthread_mutex_unlock(&g.lock);
        if (atomic_load(&running))
            applog("stratum: reconnecting...");
    }
    return NULL;
}

/* ---- selftest ----------------------------------------------------------- */

static int check_hex(const char *what, const uint8_t *got, size_t len,
                     const char *want_hex)
{
    char hex[2 * 80 + 1];

    bin2hex(hex, got, len);
    if (strcmp(hex, want_hex)) {
        printf("FAIL %-28s got  %s\n     %-28s want %s\n", what, hex, "",
               want_hex);
        return 1;
    }
    printf("ok   %s\n", what);
    return 0;
}

/* Reference digests generated with Python hashlib (see tests/gen_vectors.py) */
static int selftest(void)
{
    int fails = 0;
    uint8_t buf[256], out[32], tmpl[80];

    printf("vecpool-cpu-miner " VERSION " selftest\n");

    sha3_256(out, (const uint8_t *)"", 0);
    fails += check_hex("sha3-256(empty)", out, 32,
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
    sha3_256(out, (const uint8_t *)"abc", 3);
    fails += check_hex("sha3-256(\"abc\")", out, 32,
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
    for (int i = 0; i < 200; i++)
        buf[i] = (uint8_t)((i * 7 + 3) & 0xff);
    sha3_256(out, buf, 200);
    fails += check_hex("sha3-256(200-byte, 2 blocks)", out, 32,
        "9da37ea2fb33acd563a014f50d6f7cc225f25577a81d900452b72b5de98f239d");

    for (int i = 0; i < 80; i++)
        tmpl[i] = (uint8_t)i;
    sha3_256(out, tmpl, 80);
    fails += check_hex("sha3-256(80-byte header)", out, 32,
        "0e34ae32d043275b50e9a9e0dd024ab024213f096ca6e5b7f16b524f0b37c271");

    struct { uint32_t nonce; const char *hex; } tvec[] = {
        { 0, "6353e0a0e45c957d574adbaf29023ac870ae71cb3f26fa5f741f0808a7b3d7a7" },
        { 0xdeadbeef, "71e111c284cff5468d6222284bd31614362165f9beb0151721dd26b14b1aea7f" },
        { 1234567, "b0d0245d21a72e7b4d4cd25686c9fef71511648ec26c78f5614ff5b98c182582" },
    };
    for (size_t i = 0; i < sizeof tvec / sizeof tvec[0]; i++) {
        uint8_t hdr[80];
        char what[64];

        memcpy(hdr, tmpl, 80);
        be32enc(hdr + 76, tvec[i].nonce);
        sha3_256t_80(out, hdr);
        snprintf(what, sizeof what, "sha3-256t nonce %#x", tvec[i].nonce);
        fails += check_hex(what, out, 32, tvec[i].hex);
    }

    /* every available SIMD path must match the scalar path exactly,
     * including the non-multiple-of-width tail */
    {
        enum { N = 21 };
        uint8_t ref[N * 32], got[N * 32];
        const uint32_t n0 = 0xfffffff0u; /* crosses uint32 wrap in lanes */

        sha3t_impls[0].hash_batch(tmpl, n0, N, ref);
        for (int i = 1; i < sha3t_nimpls; i++) {
            if (!sha3t_impls[i].available()) {
                printf("skip %s cross-check (not supported on this CPU)\n",
                       sha3t_impls[i].name);
                continue;
            }
            memset(got, 0, sizeof got);
            sha3t_impls[i].hash_batch(tmpl, n0, N, got);
            if (memcmp(ref, got, sizeof ref)) {
                printf("FAIL %s batch != scalar batch\n", sha3t_impls[i].name);
                fails++;
            } else {
                printf("ok   %s batch matches scalar (%d nonces)\n",
                       sha3t_impls[i].name, N);
            }
        }
    }

    /* scan must find the smallest hash in a range and stop on it: set the
     * target to exactly that hash, so it is the only nonce that satisfies
     * hash <= target */
    {
        enum { N0 = 1234560, N = 64 };
        uint8_t hashes[N * 32];
        uint32_t target[8], want_nonce = N0;
        uint32_t best[8];

        sha3t_impls[0].hash_batch(tmpl, N0, N, hashes);
        for (int i = 0; i < 8; i++)
            best[i] = le32dec(hashes + 4 * i);
        for (uint32_t j = 1; j < N; j++) {
            uint32_t h[8];
            for (int i = 0; i < 8; i++)
                h[i] = le32dec(hashes + 32 * j + 4 * i);
            if (fulltest(h, best) && memcmp(h, best, 32)) {
                memcpy(best, h, 32);
                want_nonce = N0 + j;
            }
        }
        memcpy(target, best, 32);

        for (int i = 0; i < sha3t_nimpls; i++) {
            uint32_t fn = 0, done;
            int found = 0;

            if (!sha3t_impls[i].available())
                continue;
            done = sha3t_impls[i].scan(tmpl, N0, N, target, &fn, &found);
            if (!found || fn != want_nonce ||
                done != want_nonce - N0 + 1) {
                printf("FAIL %s scan: found=%d nonce=%u done=%u "
                       "(want nonce %u)\n", sha3t_impls[i].name, found, fn,
                       done, want_nonce);
                fails++;
            } else {
                printf("ok   %s scan stops on minimal-hash nonce %u\n",
                       sha3t_impls[i].name, want_nonce);
            }
        }
    }

    /* header builder vs an independent Python reference */
    {
        uint8_t version[4], prevhash[32], ntime[4], nbits[4];
        uint8_t branches[2][32], coinbase[64], merkle[32], header[80];
        size_t pos = 0;

        hex2bin(version, "20000000", 4);
        for (int i = 0; i < 32; i++)
            prevhash[i] = (uint8_t)i;
        hex2bin(ntime, "68a1b2c3", 4);
        hex2bin(nbits, "1d00ffff", 4);
        memset(branches[0], 0x11, 32);
        memset(branches[1], 0x22, 32);
        /* coinb1 + xnonce1 + xnonce2(ctr=5,LE,4B) + coinb2 */
        hex2bin(coinbase, "01000000", 4); pos = 4;
        hex2bin(coinbase + pos, "abcd0123", 4); pos += 4;
        hex2bin(coinbase + pos, "05000000", 4); pos += 4;
        hex2bin(coinbase + pos, "ffffffff", 4); pos += 4;

        compute_merkle_root(merkle, coinbase, pos, branches, 2);
        fails += check_hex("merkle root (2 branches)", merkle, 32,
            "65d332fb6cf3d746e993982437072f3cabddd23dc683714f71cf318bac0dc151");
        build_header(header, version, prevhash, merkle, ntime, nbits);
        fails += check_hex("80-byte header build", header, 80,
            "0000002003020100070605040b0a09080f0e0d0c13121110171615141b1a1918"
            "1f1e1d1c65d332fb6cf3d746e993982437072f3cabddd23dc683714f71cf318b"
            "ac0dc151c3b2a168ffff001d00000000");
    }

    /* diff 1 must produce the classic bitcoin diff-1 share target */
    {
        uint32_t t[8];

        diff_to_target(t, 1.0);
        if (t[7] != 0 || t[6] != 0xffff0000u) {
            printf("FAIL diff_to_target(1.0): t7=%08x t6=%08x\n", t[7], t[6]);
            fails++;
        } else {
            printf("ok   diff_to_target(1.0)\n");
        }
    }

    printf(fails ? "SELFTEST FAILED (%d)\n" : "selftest passed\n", fails);
    return fails ? 1 : 0;
}

/* ---- bench -------------------------------------------------------------- */

typedef struct {
    const sha3t_impl_t *im;
    _Atomic uint64_t *counter;
    _Atomic int *stop;
    int id;
} bench_arg_t;

static void *bench_thread(void *p)
{
    bench_arg_t *b = p;
    uint8_t tmpl[80];
    uint32_t target[8] = { 0 }; /* nothing ever matches */
    uint32_t fn;
    int found;
    uint32_t n = (uint32_t)b->id << 24;

    for (int i = 0; i < 80; i++)
        tmpl[i] = (uint8_t)i;
    while (!atomic_load(b->stop)) {
        atomic_fetch_add(b->counter,
                         b->im->scan(tmpl, n, SCAN_CHUNK, target, &fn,
                                     &found));
        n += SCAN_CHUNK;
    }
    return NULL;
}

static double bench_impl(const sha3t_impl_t *im, int threads, int ms)
{
    _Atomic uint64_t counter = 0;
    _Atomic int stop = 0;
    pthread_t tid[MAX_THREADS];
    bench_arg_t args[MAX_THREADS];
    uint64_t t0;

    for (int i = 0; i < threads; i++) {
        args[i] = (bench_arg_t){ im, &counter, &stop, i };
        pthread_create(&tid[i], NULL, bench_thread, &args[i]);
    }
    t0 = now_ms();
    while (now_ms() - t0 < (uint64_t)ms)
        usleep(10 * 1000);
    atomic_store(&stop, 1);
    for (int i = 0; i < threads; i++)
        pthread_join(tid[i], NULL);
    return (double)atomic_load(&counter) / ((double)(now_ms() - t0) / 1000.0);
}

static int bench(void)
{
    printf("vecpool-cpu-miner " VERSION " benchmark — %s\n", cpu_brand());
    for (int i = 0; i < sha3t_nimpls; i++) {
        const sha3t_impl_t *im = &sha3t_impls[i];

        if (!im->available()) {
            printf("  %-7s not supported on this CPU\n", im->name);
            continue;
        }
        printf("  %-7s (%d-way) 1 thread : %8.3f Mh/s\n", im->name,
               im->lanes, bench_impl(im, 1, 2000) / 1e6);
    }
    printf("  %-7s (%d-way) %d threads: %8.3f Mh/s\n", impl->name,
           impl->lanes, cfg.threads,
           bench_impl(impl, cfg.threads, 3000) / 1e6);
    return 0;
}

/* ---- main --------------------------------------------------------------- */

static void on_sigint(int sig)
{
    (void)sig;
    atomic_store(&running, 0);
}

static void usage(const char *argv0)
{
    printf(
        "Usage: %s -a sha3-256t -o stratum+tcp://HOST:PORT -u WALLET.worker [-p x]\n"
        "\n"
        "  -a ALGO           algorithm (only sha3-256t)\n"
        "  -o URL            pool url, stratum+tcp://host:port\n"
        "  -u USER           wallet[.worker]\n"
        "  -p PASS           pool password (default x)\n"
        "  -t, --threads N   worker threads (default: all cores)\n"
        "  --cpu-simd MODE   auto | avx512 | avx2 | scalar (default auto)\n"
        "  --diff-factor F   divide pool difficulty by F (default 1.0)\n"
        "  --time-limit S    stop after S seconds\n"
        "  --selftest        run built-in verification and exit\n"
        "  --bench           offline benchmark of every SIMD path and exit\n"
        "  -cpu              accepted for compatibility (this build is CPU-only)\n",
        argv0);
}

static int parse_url(const char *url, char **host, char **port)
{
    const char *p = url, *colon;

    if (!strncmp(p, "stratum+tcp://", 14))
        p += 14;
    else if (strstr(p, "://"))
        return -1;
    colon = strrchr(p, ':');
    if (!colon || !colon[1])
        return -1;
    *host = strndup(p, (size_t)(colon - p));
    *port = strdup(colon + 1);
    return *host && **host && *port ? 0 : -1;
}

int main(int argc, char **argv)
{
    int do_selftest = 0, do_bench = 0;

    cfg.threads = (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (cfg.threads < 1)
        cfg.threads = 1;
    if (cfg.threads > MAX_THREADS)
        cfg.threads = MAX_THREADS;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        const char *val = i + 1 < argc ? argv[i + 1] : NULL;

        if (!strcmp(a, "-a")) {
            if (!val || strcmp(val, "sha3-256t")) {
                fprintf(stderr, "only -a sha3-256t is supported\n");
                return 1;
            }
            i++;
        } else if (!strcmp(a, "-o") && val) {
            cfg.url = val; i++;
        } else if (!strcmp(a, "-u") && val) {
            cfg.user = val; i++;
        } else if (!strcmp(a, "-p") && val) {
            cfg.pass = val; i++;
        } else if ((!strcmp(a, "-t") || !strcmp(a, "--threads")) && val) {
            cfg.threads = atoi(val); i++;
            if (cfg.threads < 1 || cfg.threads > MAX_THREADS) {
                fprintf(stderr, "bad thread count\n");
                return 1;
            }
        } else if (!strcmp(a, "--cpu-simd") && val) {
            cfg.simd = strcmp(val, "auto") ? val : NULL; i++;
        } else if (!strcmp(a, "--diff-factor") && val) {
            cfg.diff_factor = atof(val); i++;
            if (cfg.diff_factor <= 0) {
                fprintf(stderr, "bad diff factor\n");
                return 1;
            }
        } else if (!strcmp(a, "--time-limit") && val) {
            cfg.time_limit = atoi(val); i++;
        } else if (!strcmp(a, "--selftest")) {
            do_selftest = 1;
        } else if (!strcmp(a, "--bench")) {
            do_bench = 1;
        } else if (!strcmp(a, "-cpu") || !strcmp(a, "--cpu")) {
            /* compatibility with the combined miner's CLI */
        } else if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "unknown option %s (see --help)\n", a);
            return 1;
        }
    }

    impl = sha3t_pick(cfg.simd);
    if (!impl) {
        fprintf(stderr,
                "--cpu-simd %s is not available on this CPU "
                "(use auto, or one of:", cfg.simd);
        for (int i = 0; i < sha3t_nimpls; i++)
            if (sha3t_impls[i].available())
                fprintf(stderr, " %s", sha3t_impls[i].name);
        fprintf(stderr, ")\n");
        return 1;
    }

    if (do_selftest)
        return selftest();

    applog("vecpool-cpu-miner " VERSION);
    applog("[cpu] %s — using %s (%d nonces/iteration)%s", cpu_brand(),
           impl->name, impl->lanes,
           cfg.simd ? " [forced]" : "");

    if (do_bench)
        return bench();

    if (!cfg.url || !cfg.user) {
        usage(argv[0]);
        return 1;
    }
    {
        char *host, *port;

        if (parse_url(cfg.url, &host, &port)) {
            fprintf(stderr, "bad -o url (want stratum+tcp://host:port)\n");
            return 1;
        }
        cfg.host = host;
        cfg.port = port;
    }

    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint);

    pthread_t stid, wtid[MAX_THREADS];

    pthread_create(&stid, NULL, stratum_thread, NULL);
    applog("starting %d worker thread(s)", cfg.threads);
    for (int i = 0; i < cfg.threads; i++)
        pthread_create(&wtid[i], NULL, worker_thread, (void *)(intptr_t)i);

    uint64_t t_start = now_ms(), t_last = t_start, h_last = 0;

    while (atomic_load(&running)) {
        usleep(500 * 1000);
        uint64_t now = now_ms();

        if (cfg.time_limit &&
            now - t_start >= (uint64_t)cfg.time_limit * 1000) {
            applog("time limit reached");
            atomic_store(&running, 0);
            break;
        }
        if (now - t_last >= 15000) {
            uint64_t total = 0;
            for (int i = 0; i < cfg.threads; i++)
                total += atomic_load(&thr_hashes[i]);
            double rate = (double)(total - h_last) /
                          ((double)(now - t_last) / 1000.0);
            applog("hashrate %.3f Mh/s (%s) | accepted %" PRIu64
                   " rejected %" PRIu64,
                   rate / 1e6, impl->name, atomic_load(&g.accepted),
                   atomic_load(&g.rejected));
            t_last = now;
            h_last = total;
        }
    }

    for (int i = 0; i < cfg.threads; i++)
        pthread_join(wtid[i], NULL);
    pthread_join(stid, NULL);

    uint64_t total = 0;
    for (int i = 0; i < cfg.threads; i++)
        total += atomic_load(&thr_hashes[i]);
    applog("exiting: %" PRIu64 " hashes, accepted %" PRIu64 ", rejected %"
           PRIu64, total, atomic_load(&g.accepted),
           atomic_load(&g.rejected));
    return 0;
}
