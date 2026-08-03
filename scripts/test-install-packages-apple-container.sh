#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PACKAGES="$ROOT/.build/packages"
test -n "$(find "$PACKAGES" -maxdepth 1 -name 'certarium-*.x86_64.rpm' -print -quit)"
test -n "$(find "$PACKAGES" -maxdepth 1 -name 'certarium_*_amd64.deb' -print -quit)"

container build --arch amd64 \
    --file "$ROOT/build/package/centos7-smoke.Containerfile" \
    --tag certarium-smoke-centos7:amd64 "$ROOT"
container run --arch amd64 --rosetta --rm \
    --volume "$PACKAGES:/packages" certarium-smoke-centos7:amd64

container build --arch amd64 \
    --file "$ROOT/build/package/debian12-smoke.Containerfile" \
    --tag certarium-smoke-debian12:amd64 "$ROOT"
container run --arch amd64 --rosetta --rm \
    --volume "$PACKAGES:/packages" certarium-smoke-debian12:amd64

echo 'ALL PACKAGE INSTALL SMOKES PASSED'
