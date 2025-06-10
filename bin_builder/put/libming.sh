# libming 0.4.8
cd /work 
wget https://github.com/libming/libming/archive/refs/tags/ming-0_4_8.tar.gz
tar zxvf ming-0_4_8.tar.gz
cp -r libming-ming-0_4_8 afl_libming-ming-0_4_8
cd libming-ming-0_4_8
mkdir -p /work/bin/swftocxx
mkdir -p /work/bin/listswf
sh autogen.sh
CFLAGS='-fcommon' CC=clang CXX=clang++ ./configure --disable-shared --enable-static --prefix=$(pwd)/install/ --disable-freetype # https://github.com/squaresLab/security-repair-benchmarks/issues/19
make # idk why but make -j$(nproc) causes build error while make does not
make install
cp install/bin/swftocxx /work/bin/swftocxx/put_bin
cp install/bin/listswf /work/bin/listswf/put_bin

cd /work
cd afl_libming-ming-0_4_8
sh autogen.sh
CFLAGS='-fcommon' CC=afl-clang-fast CXX=afl-clang-fast++ ./configure --disable-shared --enable-static --prefix=$(pwd)/install/ --disable-freetype 
make
make install
cp install/bin/swftocxx /work/bin/swftocxx/afl_put_bin
cp install/bin/listswf /work/bin/listswf/afl_put_bin