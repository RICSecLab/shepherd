#!/bin/bash
set -euo pipefail

SCRIPT_DIR=$(dirname "$(realpath "$0")")
STAT_DIR="$SCRIPT_DIR/../static-analysis-result"

if [ ! -e "$STAT_DIR" ]; then
    mkdir $STAT_DIR
fi
chmod 777 $STAT_DIR

DOCKERFILE=$SCRIPT_DIR/Dockerfile.ghidra
GHIDRA_DIR="$SCRIPT_DIR/../ghidra"
SRC_DIR="$SCRIPT_DIR/../src"

docker build ./ -t ghidra-stat --build-arg UID=$(id -u) -f $DOCKERFILE

docker run --rm \
           -v $GHIDRA_DIR:/work/ghidra \
           -v "$SCRIPT_DIR/../script":/work/script \
           -v "$SCRIPT_DIR/../target":/work/target \
           -v $SRC_DIR:/work/src \
           -v $STAT_DIR:/work/static-analysis-result \
           ghidra-stat python3 /work/script/ghidra-all.py /work/target
