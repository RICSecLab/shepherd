#!/bin/bash
set -euo pipefail

SCRIPT_DIR=$(dirname "$(realpath "$0")")
STAT_DIR="$SCRIPT_DIR/../static-analysis-result"

echo "Script directory: $SCRIPT_DIR"

filename=$(basename "$1")

if [ ! -e "$STAT_DIR" ]; then
    mkdir $STAT_DIR
fi
chmod 777 $STAT_DIR

rm -rf $STAT_DIR/$filename

DOCKERFILE=$SCRIPT_DIR/Dockerfile.ghidra
GHIDRA_DIR="$SCRIPT_DIR/../ghidra"
SRC_DIR="$SCRIPT_DIR/../src"

docker build ./ -t ghidra-stat --build-arg UID=$(id -u) -f $DOCKERFILE

# filename is "put_bin", then we use the directory name of the file as filename
if [ "$filename" = "put_bin" ]; then
    filename=$(basename $(dirname "$1"))
fi

docker run --rm -e TARGET_BIN=/work/targets/$filename \
           -v $GHIDRA_DIR:/work/ghidra \
           -v $SRC_DIR:/work/src \
           -v $STAT_DIR:/work/static-analysis-result \
           -v $1:/work/targets/$filename ghidra-stat
