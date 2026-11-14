/* 8-way SHA3-256T scanner. This file (only) is built with
 * -mavx512f -mavx512dq -mavx512bw -mavx512vl — see the Makefile — so no
 * AVX-512 instruction exists outside the CPUID-guarded calls. */

#define VLANES 8
#define FN_SUFFIX _avx512
#include "sha3t_vec.inc"
