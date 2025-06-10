set -euo pipefail

# bloaty 1.1
mkdir -p /work/bin/bloaty
git clone https://github.com/google/bloaty
cd bloaty
# current main (2024-08-16)
git checkout 34f4a66559ad4938c1e629e9b5f54630b2b4d7b0
cmake -B build -GNinja -S . -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++
ninja -Cbuild -j$(nproc)
cp build/bloaty /work/bin/bloaty/put_bin
ninja -Cbuild clean
cmake -B build -GNinja -S . -DCMAKE_C_COMPILER=afl-clang-fast -DCMAKE_CXX_COMPILER=afl-clang-fast++
ninja -Cbuild -j$(nproc)
cp build/bloaty /work/bin/bloaty/afl_put_bin
