VECPOOL Miner 1.0 (Linux, CUDA)
================================

A fast, honest multi-GPU CUDA miner for SHA3-256T coins — Bitcoin III (BC3)
and FJARCODE (FJAR). Implements the SHA3-256T proof-of-work: triple FIPS-202
SHA3-256 over the standard Bitcoin 80-byte header, spoken over plain Bitcoin
stratum. Header construction is validated against a pool-accepted share and
covered by a built-in self-test. Each GPU auto-tunes its launch geometry at
startup, hashrates shown are real per-device measurements, and vardiff
(mining.set_difficulty) is handled correctly.

Build:
  make            (needs CUDA toolkit + OpenSSL dev headers)

Run examples:
  # all GPUs — Bitcoin III on Crypto-Eire (prop) ** BEST SETTINGS 
  ./vecpool-miner -a sha3-256t -o stratum+tcp://stratum.crypto-eire.com:3363 -u YOUR_WALLET.worker -p x --allgpu

  # single GPU (CUDA device order, not nvidia-smi order)
  ./vecpool-miner -a sha3-256t -o stratum+tcp://stratum.pythonpool.dev:3357 -u YOUR_WALLET.worker -p x --devices 0

  # FJARCODE — same miner, FJAR port
  ./vecpool-miner -a sha3-256t -o stratum+tcp://stratum.crypto-eire.com:3387 -u YOUR_FJAR_WALLET.worker -p x --allgpu

  # CPU mode
  ./vecpool-miner -cpu -a sha3-256t -o stratum+tcp://POOL:PORT -u WALLET.worker -p x

Diagnostics:
  ./vecpool-miner --selftest   # replays a known pool-accepted share through
                               # the header builder, host hash and GPU kernel
  ./vecpool-miner --bench      # offline per-GPU kernel benchmark

Notes:
- CUDA device numbering differs from nvidia-smi (CUDA orders fastest-first).
  Check the "[cuda] devN: <name>" startup lines when using --devices.
- Bitcoin III and FJARCODE share the same algorithm and version bit; one
  binary serves both — only the pool URL/port changes.
- Tesla V100 note: passively cooled cards throttle hard without case airflow
  (watch nvidia-smi temperature; 83C+ costs more than half the hashrate).
  Works with 1660ti 6gb, 3060 12gb and cmp100-210 16gb flashed with v100 bios and 2699v4 cpu
  Links btc3 wallet : https://github.com/PinkStarrySky/BitcoinIII-Core/releases/tag/v29.1.1
