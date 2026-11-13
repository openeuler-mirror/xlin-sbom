#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
IMAGE=${IMAGE:-debian:12}
OUT_DIR=${1:-"$ROOT/debian/output"}

mkdir -p "$OUT_DIR"

docker run --rm \
    -v "$ROOT:/src:ro" \
    -v "$OUT_DIR:/out" \
    "$IMAGE" /bin/sh -euxc '
        apt-get update
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
            build-essential ca-certificates debhelper dpkg-dev fakeroot

        rm -rf /tmp/build
        mkdir -p /tmp/build
        tar -C /src \
            --exclude="./.git" \
            --exclude="./.venv" \
            --exclude="./.cache" \
            --exclude="./data" \
            --exclude="./output" \
            --exclude="./log" \
            --exclude="./debian/output" \
            --exclude="./rpm/output" \
            --exclude="*/__pycache__" \
            --exclude="*.pyc" \
            -cf - . | tar -C /tmp/build -xf -

        cd /tmp/build
        dpkg-buildpackage -us -uc -b
        cp /tmp/*.deb /out/
        chown -R '"$(id -u)"':'"$(id -g)"' /out
    '
