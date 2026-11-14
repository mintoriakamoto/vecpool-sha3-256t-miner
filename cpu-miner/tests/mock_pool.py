#!/usr/bin/env python3
"""Mock SHA3-256T stratum pool for end-to-end testing of vecpool-cpu-miner.

Speaks just enough stratum (subscribe/authorize/set_difficulty/notify/submit)
and — critically — verifies every submitted share INDEPENDENTLY with
hashlib: it rebuilds the coinbase from the submitted extranonce2, recomputes
the merkle root and the 80-byte header, triple-SHA3s it and checks the result
against the difficulty target. Any disagreement in byte order between miner
and pool conventions shows up here as a rejected share.

Usage:  python3 tests/mock_pool.py [--port 13333] [--shares 3] [--diff 0.001]
Exits 0 once the requested number of valid shares was accepted; exits 1 on
any invalid share or on timeout.
"""

import argparse
import hashlib
import json
import socket
import sys
import time

TRUEDIFFONE = 0x00000000FFFF0000000000000000000000000000000000000000000000000000

JOB = {
    "job_id": "job1",
    "prevhash": "".join(f"{i:02x}" for i in range(32)),
    "coinb1": "01000000010000000000000000000000000000000000000000000000000000"
              "0000000000ffffffff20",
    "coinb2": "ffffffff0100f2052a010000001976a914000000000000000000000000000"
              "000000000000088ac00000000",
    "branches": ["11" * 32, "22" * 32],
    "version": "20000000",
    "nbits": "1d00ffff",
    "ntime": "68a1b2c3",
}
XNONCE1 = "abcd0123"


def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def sha3t(b):
    h = hashlib.sha3_256
    return h(h(h(b).digest()).digest()).digest()


def diff_to_target_int(diff):
    """Same construction as the miner's diff_to_target (cpuminer formula)."""
    words = [0] * 8
    k = 6
    while k > 0 and diff > 1.0:
        diff /= 4294967296.0
        k -= 1
    m = int(4294901760.0 / diff)
    if m == 0 and k == 6:
        words = [0xFFFFFFFF] * 8
    else:
        words[k] = m & 0xFFFFFFFF
        words[k + 1] = (m >> 32) & 0xFFFFFFFF
    t = 0
    for i in reversed(range(8)):
        t = (t << 32) | words[i]
    return t


def rev4(b):
    return b[::-1]


def build_header(job, xnonce2_hex, ntime_hex, nonce_hex):
    coinbase = (bytes.fromhex(job["coinb1"]) + bytes.fromhex(XNONCE1) +
                bytes.fromhex(xnonce2_hex) + bytes.fromhex(job["coinb2"]))
    merkle = sha256d(coinbase)
    for br in job["branches"]:
        merkle = sha256d(merkle + bytes.fromhex(br))
    hdr = bytearray(80)
    hdr[0:4] = rev4(bytes.fromhex(job["version"]))
    ph = bytes.fromhex(job["prevhash"])
    for i in range(8):
        hdr[4 + 4 * i:8 + 4 * i] = rev4(ph[4 * i:4 * i + 4])
    hdr[36:68] = merkle
    hdr[68:72] = rev4(bytes.fromhex(ntime_hex))
    hdr[72:76] = rev4(bytes.fromhex(job["nbits"]))
    # miner submits the nonce as hex of the little-endian bytes; the header
    # carries it big-endian (yiimp string_be convention)
    hdr[76:80] = rev4(bytes.fromhex(nonce_hex))
    return bytes(hdr)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=13333)
    ap.add_argument("--shares", type=int, default=3)
    ap.add_argument("--diff", type=float, default=0.001)
    ap.add_argument("--timeout", type=float, default=120)
    args = ap.parse_args()

    target = diff_to_target_int(args.diff)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", args.port))
    srv.listen(1)
    srv.settimeout(args.timeout)
    print(f"[pool] listening on 127.0.0.1:{args.port}, "
          f"diff {args.diff}, want {args.shares} shares", flush=True)

    conn, addr = srv.accept()
    conn.settimeout(args.timeout)
    print(f"[pool] miner connected from {addr}", flush=True)
    f = conn.makefile("rwb")

    def send(obj):
        f.write((json.dumps(obj) + "\n").encode())
        f.flush()

    accepted = 0
    seen = set()
    deadline = time.time() + args.timeout
    jobs_sent = 0

    def send_job(clean):
        nonlocal jobs_sent
        jobs_sent += 1
        job_id = f"job{jobs_sent}"
        JOB["job_id"] = job_id
        # every job must be unique work, as on a real pool
        JOB["ntime"] = f"{int(JOB['ntime'], 16) + jobs_sent:08x}"
        send({"id": None, "method": "mining.notify",
              "params": [job_id, JOB["prevhash"], JOB["coinb1"],
                         JOB["coinb2"], JOB["branches"], JOB["version"],
                         JOB["nbits"], JOB["ntime"], clean]})

    while time.time() < deadline:
        line = f.readline()
        if not line:
            print("[pool] miner disconnected", flush=True)
            break
        msg = json.loads(line)
        method = msg.get("method")

        if method == "mining.subscribe":
            send({"id": msg["id"],
                  "result": [[["mining.notify", "sub1"]], XNONCE1, 4],
                  "error": None})
        elif method == "mining.authorize":
            send({"id": msg["id"], "result": True, "error": None})
            send({"id": None, "method": "mining.set_difficulty",
                  "params": [args.diff]})
            send_job(True)
        elif method == "mining.submit":
            user, job_id, xn2, ntime, nonce = msg["params"]
            ok, why = True, "ok"
            if job_id != JOB["job_id"]:
                ok, why = False, "stale job id"
            elif len(xn2) != 8 or len(nonce) != 8:
                ok, why = False, "bad field length"
            elif (job_id, xn2, nonce) in seen:
                ok, why = False, "duplicate"
            else:
                hdr = build_header(JOB, xn2, ntime, nonce)
                hval = int.from_bytes(sha3t(hdr), "little")
                if hval > target:
                    ok, why = False, f"hash above target ({hval:#066x})"
            send({"id": msg["id"], "result": ok,
                  "error": None if ok else [23, why, None]})
            if ok:
                seen.add((job_id, xn2, nonce))
                accepted += 1
                print(f"[pool] share {accepted}/{args.shares} VALID "
                      f"(job {job_id}, xn2 {xn2}, nonce {nonce})", flush=True)
                if accepted == 2:
                    # exercise job switching mid-run
                    send_job(True)
                if accepted >= args.shares:
                    print("[pool] all shares valid — PASS", flush=True)
                    return 0
            else:
                print(f"[pool] INVALID share: {why} — FAIL", flush=True)
                return 1

    print("[pool] timeout — FAIL", flush=True)
    return 1


if __name__ == "__main__":
    sys.exit(main())
