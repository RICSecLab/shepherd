set -euo pipefail
# bento4 v1.6.0-641
cd /work
wget https://github.com/axiomatic-systems/Bento4/archive/refs/tags/v1.6.0-641.tar.gz
tar zxvf v1.6.0-641.tar.gz
cd Bento4-1.6.0-641
mkdir -p /work/bin/mp4dump
mkdir cmakebuild
cd cmakebuild
cmake -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_INSTALL_PREFIX=$(pwd)/install/ -DBUILD_SHARED_LIBS=OFF ..
make -j$(nproc)
make install
cp install/bin/mp4dump /work/bin/mp4dump/put_bin

cd ../
mkdir cmakebuild_afl
cd cmakebuild_afl
cmake -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_COMPILER=afl-clang-fast -DCMAKE_CXX_COMPILER=afl-clang-fast++ -DCMAKE_INSTALL_PREFIX=$(pwd)/install/ -DBUILD_SHARED_LIBS=OFF ..
make -j$(nproc)
make install
cp install/bin/mp4dump /work/bin/mp4dump/afl_put_bin