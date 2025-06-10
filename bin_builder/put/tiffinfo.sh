set -euo pipefail

# tiffinfo 4.6.0
mkdir -p /work/bin/tiffinfo
wget https://download.osgeo.org/libtiff/tiff-4.6.0.tar.gz
tar zxvf tiff-4.6.0.tar.gz
mv tiff-4.6.0 tiffinfo
cd tiffinfo
CC=clang CXX=clang++ ./configure --disable-shared --enable-static
make -j$(nproc)
cp tools/tiffinfo /work/bin/tiffinfo/put_bin
make clean
CC=afl-clang-fast CXX=afl-clang-fast++ ./configure --disable-shared --enable-static
make -j$(nproc)
cp tools/tiffinfo /work/bin/tiffinfo/afl_put_bin
