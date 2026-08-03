#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
GO_BIN=${GO_BIN:-go}
GOFMT_BIN=${GOFMT_BIN:-gofmt}
OPENSSL_BIN=${CERTARIUM_OPENSSL:-}
TONGSUO_LICENSE=${CERTARIUM_TONGSUO_LICENSE:-/opt/tongsuo/licenses/Tongsuo-LICENSE.txt}
TMP_DIR=$(mktemp -d)
SERVER_PID=

cleanup() {
    if [ -n "$SERVER_PID" ]; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT HUP INT TERM
cd "$ROOT"

echo "== source format =="
unformatted=$($GOFMT_BIN -l .)
if [ -n "$unformatted" ]; then
    echo "gofmt found unformatted files:" >&2
    echo "$unformatted" >&2
    exit 1
fi

echo "== static analysis =="
$GO_BIN vet ./...

echo "== unit, property, integration, and race tests =="
if [ -z "$OPENSSL_BIN" ]; then
    echo "CERTARIUM_OPENSSL must identify the pinned Tongsuo executable" >&2
    exit 1
fi
$OPENSSL_BIN version | grep -F "Tongsuo 8.4.0"
$GO_BIN test -race -shuffle=on -count=1 ./...

echo "== coverage =="
$GO_BIN test -count=1 -coverprofile="$TMP_DIR/coverage.out" ./internal/pki
$GO_BIN tool cover -func="$TMP_DIR/coverage.out" | tee "$TMP_DIR/coverage.txt"

echo "== manual mutation =="
GO_BIN="$GO_BIN" ./tools/mutation-test.sh
GO_BIN="$GO_BIN" ./tools/web-mutation-test.sh
./tools/package-contract-test.sh
./tools/package-mutation-test.sh

echo "== build and real HTTP health request =="
$GO_BIN build -trimpath -o "$TMP_DIR/certarium" ./cmd/certarium
"$TMP_DIR/certarium" -listen 127.0.0.1:18080 -data-dir "$TMP_DIR/data" >"$TMP_DIR/server.log" 2>&1 &
SERVER_PID=$!
attempt=0
until curl --fail --silent --show-error http://127.0.0.1:18080/api/v1/health >"$TMP_DIR/health.json"; do
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 20 ]; then
        cat "$TMP_DIR/server.log" >&2
        exit 1
    fi
    sleep 0.1
done
grep -F '"status":"ok"' "$TMP_DIR/health.json"

echo "== real Web/API issuance smoke =="
GO_BIN="$GO_BIN" CERTARIUM_OPENSSL="$OPENSSL_BIN" ./tools/web-smoke.sh

echo "== dependency, license, and secret checks =="
$GO_BIN list -m all
for file in LICENSE NOTICE THIRD_PARTY_NOTICES.md AI_ASSISTED_DEVELOPMENT.md; do
    test -s "$file"
done
test -s "$TONGSUO_LICENSE"
if git grep -n -I -E -- '(BEGIN (RSA |EC |ENCRYPTED )?PRIVATE KEY|gh[opsu]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16})' -- ':!tools/gauntlet.sh'; then
    echo "possible committed secret detected" >&2
    exit 1
fi

echo "GAUNTLET PASSED"
