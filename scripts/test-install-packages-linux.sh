#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PACKAGES="$ROOT/.build/packages"
docker build --platform linux/amd64 --file "$ROOT/build/package/centos7-smoke.Containerfile" \
    --tag certarium-smoke-centos7:amd64 "$ROOT"
docker run --platform linux/amd64 --rm --volume "$PACKAGES:/packages" certarium-smoke-centos7:amd64
docker build --platform linux/amd64 --file "$ROOT/build/package/debian12-smoke.Containerfile" \
    --tag certarium-smoke-debian12:amd64 "$ROOT"
docker run --platform linux/amd64 --rm --volume "$PACKAGES:/packages" certarium-smoke-debian12:amd64
