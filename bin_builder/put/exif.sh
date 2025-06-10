set -euo pipefail

# libexif for exif (0.6.22)
mkdir -p /work/libs
wget https://github.com/libexif/libexif/releases/download/libexif-0_6_22-release/libexif-0.6.22.tar.gz
tar zxvf libexif-0.6.22.tar.gz -C /work/libs
mv /work/libs/libexif-0.6.22 /work/libs/libexif
cd /work/libs/libexif
CC=clang ./configure
make -j$(nproc)
cd /work/
tar zxvf libexif-0.6.22.tar.gz -C /work/libs
mv /work/libs/libexif-0.6.22 /work/libs/afl_libexif
cd /work/libs/afl_libexif
CC=afl-clang-fast ./configure
make -j$(nproc)
cd /work/

# exif 0.6.22
mkdir -p /work/bin/exif
wget https://github.com/libexif/exif/releases/download/exif-0_6_22-release/exif-0.6.22.tar.gz
tar zxvf exif-0.6.22.tar.gz
mv exif-0.6.22 exif
cd exif

CC=clang CFLAGS="-lm" LIBEXIF_LIBS=/work/libs/libexif/libexif/.libs/libexif.a \
  LIBEXIF_CFLAGS="-I/work/libs/libexif/" ./configure
make -j$(nproc)
cp exif/exif /work/bin/exif/put_bin
make clean

CC=afl-clang-fast CFLAGS="-lm" LIBEXIF_LIBS=/work/libs/afl_libexif/libexif/.libs/libexif.a \
  LIBEXIF_CFLAGS="-I/work/libs/afl_libexif/" ./configure
make -j$(nproc)
cp exif/exif /work/bin/exif/afl_put_bin

