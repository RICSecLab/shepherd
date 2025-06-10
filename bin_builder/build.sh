#!/bin/bash
set -euo pipefail

bash ./put/libpng_read_fuzzer.sh
bash ./put/tcpdump.sh
bash ./put/bloaty.sh
bash ./put/tiffinfo.sh
bash ./put/exif.sh
bash ./put/binutils.sh
bash ./put/jasper.sh
bash ./put/libming.sh
bash ./put/bento4.sh
