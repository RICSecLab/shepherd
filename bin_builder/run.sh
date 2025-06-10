#!/bin/bash
set -euo pipefail

SCRIPT_DIR=$(dirname "$(realpath "$0")")
DOCKERFILE=$SCRIPT_DIR/Dockerfile.puts
IMAGE_NAME="puts-builder"

if [ ! -d "$SCRIPT_DIR/../put_bin" ]; then
    mkdir "$SCRIPT_DIR/../put_bin"
fi

docker build ./ -t $IMAGE_NAME --build-arg UID=$(id -u) -f $DOCKERFILE

# Mount the put_bin dir
docker run --rm -it \
           -v "$SCRIPT_DIR/build.sh":/work/build.sh \
           -v "$SCRIPT_DIR/harnesses/":/work/harnesses/ \
           -v "$SCRIPT_DIR/put/":/work/put/ \
           -v "$SCRIPT_DIR/../put_bin/":/work/bin/ \
           $IMAGE_NAME bash /work/build.sh
