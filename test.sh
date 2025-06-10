#!/bin/bash
set -euo pipefail

SCRIPT_DIR=$(dirname "$(realpath "$0")")

HOST_TMP_OUTPUT="${1:-/dev/shm/fuzzer-output}"
CONTAINER_OUTPUT_DIR="/dev/shm/output"

echo "Using host output directory: $HOST_TMP_OUTPUT"

STAT_DIR="$SCRIPT_DIR/static-analysis-result"

if [ ! -e "$STAT_DIR" ]; then
    mkdir $STAT_DIR
fi
chmod 777 $STAT_DIR
if [ ! -d "$HOST_TMP_OUTPUT" ]; then
    mkdir -p "$HOST_TMP_OUTPUT"
fi
chmod 777 "$HOST_TMP_OUTPUT"

DOCKERFILE=$SCRIPT_DIR/Dockerfile.fuzz
SRC_DIR="$SCRIPT_DIR/src"
IMAGE_NAME="shepherd-fuzz"

docker build ./ -t $IMAGE_NAME --build-arg UID=$(id -u) -f $DOCKERFILE

docker run --rm -it \
           -e "SHEPHERD_OUTPUT_DIR=${CONTAINER_OUTPUT_DIR}" \
           -v "$SCRIPT_DIR/src":/work/src \
           -v "$SCRIPT_DIR/script":/work/script \
           -v "$SCRIPT_DIR/target":/work/target \
           -v "$SCRIPT_DIR/docker-fuzz.py":/work/docker-fuzz.py \
           -v "$SCRIPT_DIR/pintools":/work/pintools \
           -v "$STAT_DIR":/work/static-analysis-result \
           -v "$HOST_TMP_OUTPUT":"$CONTAINER_OUTPUT_DIR" \
           $IMAGE_NAME /bin/bash
