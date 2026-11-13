#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
IMAGE=${IMAGE:-openeuler/openeuler:24.03}
OUT_DIR=${1:-"$ROOT/rpm/output"}
VERSION=$(sed -n 's/^Version:[[:space:]]*//p' "$ROOT/rpm/xlin-sbom.spec" | head -n 1)

test -n "$VERSION"
mkdir -p "$OUT_DIR"

docker run --rm \
    -e VERSION="$VERSION" \
    -v "$ROOT:/src:ro" \
    -v "$OUT_DIR:/out" \
    "$IMAGE" /bin/sh -euxc '
        # 先单独升级基础包，避免在安装过程中替换正在运行的 python3 解释器。
        dnf -y --setopt=install_weak_deps=False --setopt=tsflags=nodocs \
            upgrade rpm rpm-libs python3 gzip tar

        dnf -y --setopt=install_weak_deps=False --setopt=tsflags=nodocs install \
            gzip rpm-build tar

        rm -rf /tmp/rpmbuild
        mkdir -p /tmp/rpmbuild/BUILD /tmp/rpmbuild/BUILDROOT \
            /tmp/rpmbuild/RPMS /tmp/rpmbuild/SOURCES /tmp/rpmbuild/SPECS \
            /tmp/rpmbuild/SRPMS

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
            --transform "s,^\.,xlin-sbom-${VERSION}," \
            -czf /tmp/rpmbuild/SOURCES/xlin-sbom-${VERSION}.tar.gz .

        rpmbuild -bb /src/rpm/xlin-sbom.spec \
            --define "_topdir /tmp/rpmbuild"
        cp /tmp/rpmbuild/RPMS/*/*.rpm /out/
        chown -R '"$(id -u)"':'"$(id -g)"' /out
    '
