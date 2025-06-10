set -euo pipefail

# binutils 2.32
wget https://ftp.gnu.org/gnu/binutils/binutils-2.32.tar.gz
tar zxvf binutils-2.32.tar.gz
cd binutils-2.32
CC=clang ./configure
make -j$(nproc)
mkdir -p /work/bin/objdump /work/bin/nm /work/bin/readelf
cp binutils/objdump /work/bin/objdump/put_bin
cp binutils/nm-new /work/bin/nm/put_bin
cp binutils/readelf /work/bin/readelf/put_bin

make distclean 
CC=afl-clang-fast ./configure
make -j$(nproc)
cp binutils/objdump /work/bin/objdump/afl_put_bin
cp binutils/nm-new /work/bin/nm/afl_put_bin
cp binutils/readelf /work/bin/readelf/afl_put_bin


