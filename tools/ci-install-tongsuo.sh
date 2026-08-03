#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
. "$ROOT/VERSIONS.env"
PREFIX=${1:-$ROOT/.build/ci-tongsuo}
if [ -x "$PREFIX/bin/openssl" ] && "$PREFIX/bin/openssl" version | grep -F "Tongsuo $TONGSUO_VERSION" >/dev/null; then
    exit 0
fi
SOURCE="$ROOT/.build/Tongsuo-ci"
mkdir -p "$ROOT/.build"
if [ ! -d "$SOURCE/.git" ]; then
    git clone https://github.com/Tongsuo-Project/Tongsuo.git "$SOURCE"
fi
git -C "$SOURCE" fetch --depth 1 origin "$TONGSUO_COMMIT"
git -C "$SOURCE" checkout --detach "$TONGSUO_COMMIT"
test "$(git -C "$SOURCE" rev-parse HEAD)" = "$TONGSUO_COMMIT"
cd "$SOURCE"
./config --prefix="$PREFIX" no-shared no-tests enable-ntls
make -j2 build_sw
make install_sw
install -D -m 0644 LICENSE.txt "$PREFIX/licenses/Tongsuo-LICENSE.txt"
