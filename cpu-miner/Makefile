# vecpool-cpu-miner — CPU SHA3-256T miner with runtime SIMD dispatch.
#
# Only the sha3t_avx2.o / sha3t_avx512.o objects are built with SIMD flags;
# everything else is plain x86_64, so the binary starts on any CPU and the
# vector code is entered only after the CPUID check in sha3t_pick().

CC      ?= gcc
CFLAGS  ?= -O3 -funroll-loops
CFLAGS  += -Wall -Wextra -pthread -MMD -MP
LDFLAGS += -pthread
LDLIBS  += -lcrypto

OBJS = miner.o util.o sha3.o json.o sha3t_avx2.o sha3t_avx512.o

vecpool-cpu-miner: $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

sha3t_avx2.o: CFLAGS += -mavx2
sha3t_avx512.o: CFLAGS += -mavx512f -mavx512dq -mavx512bw -mavx512vl

sha3t_avx2.o sha3t_avx512.o: sha3t_vec.inc

test: vecpool-cpu-miner
	./vecpool-cpu-miner --selftest

clean:
	rm -f vecpool-cpu-miner *.o *.d

-include $(OBJS:.o=.d)

.PHONY: test clean
