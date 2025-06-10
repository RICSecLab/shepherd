#!/bin/bash
set -euo pipefail

# libpng_read_fuzzer no-sanitizer & no-fuzzer
mkdir -p /work/bin/libpng_read_fuzzer
git clone --branch v1.6.44 --depth 1 https://github.com/pnggroup/libpng
cd libpng
autoreconf -f -i
CC=clang CXX=clang++ CFLAGS="-DPNG_DEBUG=2" CXXFLAGS="-DPNG_DEBUG=2" ./configure
make -j$(nproc) clean
make -j$(nproc) libpng16.la
clang++ -O3 -std=c++11 -I. \
     ./contrib/oss-fuzz/libpng_read_fuzzer.cc \
     /work/harnesses/libpng_driver.cpp \
     -o /work/bin/libpng_read_fuzzer/put_bin  \
     .libs/libpng16.a -lz

autoreconf -f -i
CC=afl-clang-fast CXX=afl-clang-fast++ CFLAGS="-DPNG_DEBUG=2" CXXFLAGS="-DPNG_DEBUG=2" ./configure
make -j$(nproc) clean
make -j$(nproc) libpng16.la
afl-clang-fast++ -O3 -std=c++11 -I. \
     ./contrib/oss-fuzz/libpng_read_fuzzer.cc \
     /work/harnesses/libpng_driver.cpp \
     -o /work/bin/libpng_read_fuzzer/afl_put_bin  \
     .libs/libpng16.a -lz
