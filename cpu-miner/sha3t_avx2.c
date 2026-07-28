/* 4-way SHA3-256T scanner. This file (only) is built with -mavx2 — see the
 * Makefile — so no AVX2 instruction exists outside the CPUID-guarded calls. */

#define VLANES 4
#define FN_SUFFIX _avx2
#include "sha3t_vec.inc"
