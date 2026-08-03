#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
. "$ROOT/VERSIONS.env"
VERSION=${VERSION:-0.1.0}
OUT="$ROOT/.build/packages"
DIST="$ROOT/dist"
CENTOS_IMAGE=certarium-package-centos7:amd64
DEBIAN_IMAGE=certarium-package-debian:amd64
mkdir -p "$OUT" "$DIST"

container build --arch amd64 \
    --build-arg "VERSION=$VERSION" \
    --build-arg "TONGSUO_COMMIT=$TONGSUO_COMMIT" \
    --file "$ROOT/build/package/centos7.Containerfile" \
    --tag "$CENTOS_IMAGE" "$ROOT"
container run --arch amd64 --rosetta --rm --env "VERSION=$VERSION" --volume "$OUT:/out" "$CENTOS_IMAGE"

container build --arch amd64 \
    --file "$ROOT/build/package/debian.Containerfile" \
    --tag "$DEBIAN_IMAGE" "$ROOT"
container run --arch amd64 --rosetta --rm --env "VERSION=$VERSION" --volume "$OUT:/out" "$DEBIAN_IMAGE"

cp "$OUT"/certarium-*.x86_64.rpm "$DIST/"
cp "$OUT"/certarium_*_amd64.deb "$DIST/"
cp "$OUT/TONGSUO-GLIBC-VERSIONS.txt" "$DIST/"
(cd "$DIST" && shasum -a 256 certarium-*.x86_64.rpm certarium_*_amd64.deb >SHA256SUMS-packages)
echo "Packages written to $DIST"
