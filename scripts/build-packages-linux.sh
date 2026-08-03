#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
. "$ROOT/VERSIONS.env"
VERSION=${VERSION:-0.1.0}
OUT="$ROOT/.build/packages"
DIST="$ROOT/dist"
mkdir -p "$OUT" "$DIST"

docker build --platform linux/amd64 \
    --build-arg "VERSION=$VERSION" --build-arg "TONGSUO_COMMIT=$TONGSUO_COMMIT" \
    --file "$ROOT/build/package/centos7.Containerfile" \
    --tag certarium-package-centos7:amd64 "$ROOT"
docker run --platform linux/amd64 --rm --env "VERSION=$VERSION" \
    --volume "$OUT:/out" certarium-package-centos7:amd64
docker build --platform linux/amd64 --file "$ROOT/build/package/debian.Containerfile" \
    --tag certarium-package-debian:amd64 "$ROOT"
docker run --platform linux/amd64 --rm --env "VERSION=$VERSION" \
    --volume "$OUT:/out" certarium-package-debian:amd64

cp "$OUT"/certarium-*.x86_64.rpm "$DIST/"
cp "$OUT"/certarium_*_amd64.deb "$DIST/"
cp "$OUT/TONGSUO-GLIBC-VERSIONS.txt" "$DIST/"
(cd "$DIST" && sha256sum certarium-*.x86_64.rpm certarium_*_amd64.deb >SHA256SUMS-packages)
