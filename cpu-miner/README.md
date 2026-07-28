vecpool-cpu-miner — SHA3-256T CPU miner with runtime SIMD dispatch
==================================================================

CPU miner for the SHA3-256T proof-of-work (Bitcoin III / FJARCODE) over
plain Bitcoin stratum. One binary, three code paths, picked once at startup
by CPUID:

  path     width            example CPUs
  ------   --------------   -------------------------------------------
  avx512   8 nonces/iter    Ryzen 9950X (Zen 4/5), Xeon Skylake-SP+
  avx2     4 nonces/iter    Xeon E5-2699 v4, i7-7700K, most 2013+ CPUs
  scalar   1 nonce/iter     anything x86_64

The startup line tells you what was picked:

  [cpu] AMD Ryzen 9 9950X 16-Core Processor — using avx512 (8 nonces/iteration)

Only the two SIMD objects are compiled with vector flags (see Makefile), and
they are entered strictly after the CPUID check — so the same binary cannot
hit an illegal instruction on an older CPU. `--cpu-simd avx2|scalar` forces
a lower path for benchmarking.

Build
-----
  make            (needs gcc, OpenSSL dev headers, pthreads)
  make test       (build + run the built-in selftest)

Run
---
  ./vecpool-cpu-miner -a sha3-256t -o stratum+tcp://POOL:PORT -u WALLET.worker -p x

  -t, --threads N    worker threads (default: all cores)
  --cpu-simd MODE    auto | avx512 | avx2 | scalar
  --diff-factor F    divide pool difficulty by F if your pool scales targets
  --time-limit S     stop after S seconds
  --selftest         verification suite (see below), exit code 0/1
  --bench            offline benchmark of every path supported by this CPU

Each worker thread takes its own extranonce2, so threads never duplicate
work; every found share is rebuilt and re-hashed on the submitting path
before it is sent.

Verification
------------
`--selftest` checks, in order: SHA3-256 against FIPS-202 vectors generated
with an independent implementation (Python hashlib — see
tests/gen_vectors.py), including a multi-block input; the triple hash at
three nonces; that the AVX2 and AVX-512 scanners produce bit-identical
output to the scalar path including odd-sized tails; that scanning stops
exactly on a minimal-hash nonce; and the stratum header/merkle construction
against an independently computed reference.

tests/mock_pool.py is a stand-alone stratum pool that verifies every
submitted share independently with hashlib (it rebuilds the coinbase from
the submitted extranonce2, recomputes merkle + header, re-hashes and checks
the target). Run it end-to-end with:

  python3 tests/mock_pool.py --port 13333 --shares 5 &
  ./vecpool-cpu-miner -o stratum+tcp://127.0.0.1:13333 -u TEST.worker --time-limit 60

Exit code 0 from the pool means every share the miner sent was
byte-for-byte valid under an independent implementation.

Note: header construction follows the standard cpuminer/yiimp stratum
convention (the same one the GPU release binary validated against a
pool-accepted share). If your pool scales share targets for this algorithm,
adjust with --diff-factor.
