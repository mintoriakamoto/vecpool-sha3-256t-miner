#!/usr/bin/env python3
"""Regenerates the reference digests hardcoded in miner.c's --selftest.

All vectors come from Python's hashlib (an independent FIPS-202 / SHA-256
implementation), so the C code is never checked against itself.
"""

import hashlib
import struct


def sha3(b):
    return hashlib.sha3_256(b).digest()


def sha3t(b):
    return sha3(sha3(sha3(b)))


def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


tmpl = bytes(range(80))

print("sha3-256(empty)   :", sha3(b"").hex())
print("sha3-256('abc')   :", sha3(b"abc").hex())
m200 = bytes((i * 7 + 3) & 0xFF for i in range(200))
print("sha3-256(200B)    :", sha3(m200).hex())
print("sha3-256(hdr80)   :", sha3(tmpl).hex())

for n in (0, 0xDEADBEEF, 1234567):
    hdr = tmpl[:76] + struct.pack(">I", n)
    print(f"sha3-256t n={n:<10}: {sha3t(hdr).hex()}")

# header build vector (cpuminer/yiimp stratum convention)
version, nbits, ntime = "20000000", "1d00ffff", "68a1b2c3"
prevhash = "".join(f"{i:02x}" for i in range(32))
coinbase = (bytes.fromhex("01000000") + bytes.fromhex("abcd0123") +
            bytes.fromhex("05000000") + bytes.fromhex("ffffffff"))
merkle = sha256d(coinbase)
for br in (bytes([0x11] * 32), bytes([0x22] * 32)):
    merkle = sha256d(merkle + br)


def rev4(b):
    return b[::-1]


hdr = bytearray(80)
hdr[0:4] = rev4(bytes.fromhex(version))
ph = bytes.fromhex(prevhash)
for i in range(8):
    hdr[4 + 4 * i:8 + 4 * i] = rev4(ph[4 * i:4 * i + 4])
hdr[36:68] = merkle
hdr[68:72] = rev4(bytes.fromhex(ntime))
hdr[72:76] = rev4(bytes.fromhex(nbits))
print("merkle root       :", merkle.hex())
print("header            :", bytes(hdr).hex())
