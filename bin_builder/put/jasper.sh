set -euo pipefail

# Jasper-software 4.2.4
wget https://github.com/jasper-software/jasper/archive/refs/tags/version-4.2.4.zip
unzip version-4.2.4.zip
cd jasper-version-4.2.4
CC=clang CXX=clang++ ./build/build --static --install-dir install/ --install
mkdir -p /work/bin/imginfo /work/bin/jasper
cp install/bin/imginfo /work/bin/imginfo/put_bin
cp install/bin/jasper /work/bin/jasper/put_bin

rm -rf tmp_cmake install
CC=afl-clang-fast CXX=afl-clang-fast++ ./build/build --static --install-dir install/ --install
cp install/bin/imginfo /work/bin/imginfo/afl_put_bin
cp install/bin/jasper /work/bin/jasper/afl_put_bin

