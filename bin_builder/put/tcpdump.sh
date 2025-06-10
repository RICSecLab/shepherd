set -euo pipefail
# tcpdump 4.99.4
mkdir -p /work/bin/tcpdump
# libpcap 1.10.4 for tcpdump
git clone https://github.com/the-tcpdump-group/tcpdump --branch tcpdump-4.99.4 --depth 1
wget https://github.com/the-tcpdump-group/libpcap/archive/refs/tags/libpcap-1.10.4.tar.gz
tar zxvf libpcap-1.10.4.tar.gz
mv libpcap-libpcap-1.10.4 libpcap
cd libpcap
CC=afl-clang-fast ./configure
make -j$(nproc)
cd /work/tcpdump

CC=afl-clang-fast ./configure
make -j$(nproc)
cp tcpdump /work/bin/tcpdump/afl_put_bin
make clean

cd /work/libpcap
make clean
CC=clang ./configure
make -j$(nproc)
cd /work/tcpdump
CC=clang ./configure
make -j$(nproc)
cp tcpdump /work/bin/tcpdump/put_bin
