#!/bin/bash
set -euo pipefail

SCRIPT_DIR=$(dirname "$(realpath "$0")")
STAT_DIR="$SCRIPT_DIR/static-analysis-result"

# Use the first argument as the output directory, or default to /dev/shm/rgf_precision
HOST_OUT_DIR="${1:-/dev/shm/rgf_precision}"
CONTAINER_OUT_DIR="/dev/shm/rgf_precision"

if [ ! -e "$STAT_DIR" ]; then
    mkdir $STAT_DIR
fi
chmod 777 $STAT_DIR
if [ ! -e "$HOST_OUT_DIR" ]; then
    mkdir -p "$HOST_OUT_DIR"/pin_output
fi
chmod 777 $HOST_OUT_DIR

DOCKERFILE=$SCRIPT_DIR/Dockerfile.fuzz
SRC_DIR="$SCRIPT_DIR/src"
IMAGE_NAME="shepherd-fuzz"

docker build ./ -t $IMAGE_NAME --build-arg UID=$(id -u) -f $DOCKERFILE

docker run --rm -it \
           -e "SHEPHERD_PRECISION_DIR=${CONTAINER_OUT_DIR}" \
           -v "$SCRIPT_DIR/src":/work/src \
           -v "$SCRIPT_DIR/script":/work/script \
           -v "$SCRIPT_DIR/target":/work/target \
           -v "$SCRIPT_DIR/docker-fuzz.py":/work/docker-fuzz.py \
           -v "$SCRIPT_DIR/pintools":/work/pintools \
           -v "$STAT_DIR":/work/static-analysis-result \
           -v "$HOST_OUT_DIR":"$CONTAINER_OUT_DIR" \
           $IMAGE_NAME pypy3 -O /work/script/eval_precision.py
