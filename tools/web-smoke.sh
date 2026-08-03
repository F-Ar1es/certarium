#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
GO_BIN=${GO_BIN:-go}
OPENSSL_BIN=${CERTARIUM_OPENSSL:?CERTARIUM_OPENSSL must point to Tongsuo}
TMP_DIR=$(mktemp -d)
PID=

cleanup() {
    if [ -n "$PID" ]; then
        kill "$PID" 2>/dev/null || true
        wait "$PID" 2>/dev/null || true
    fi
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT HUP INT TERM

cd "$ROOT"
$GO_BIN build -trimpath -o "$TMP_DIR/certarium" ./cmd/certarium
printf '%s\n' 'web-smoke-passphrase' >"$TMP_DIR/ca.pass"
chmod 0400 "$TMP_DIR/ca.pass"
"$TMP_DIR/certarium" -listen 127.0.0.1:18081 -data-dir "$TMP_DIR/data" -tongsuo "$OPENSSL_BIN" -ca-passphrase-file "$TMP_DIR/ca.pass" >"$TMP_DIR/server.log" 2>&1 &
PID=$!

attempt=0
until curl --fail --silent http://127.0.0.1:18081/api/v1/status >"$TMP_DIR/status.json"; do
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 30 ]; then
        cat "$TMP_DIR/server.log" >&2
        exit 1
    fi
    sleep 0.1
done
grep -F '"initialized":false' "$TMP_DIR/status.json"

curl --fail --silent --show-error -H 'Content-Type: application/json' \
    -d '{"organization":"Certarium Web Smoke"}' \
    http://127.0.0.1:18081/api/v1/initialize >"$TMP_DIR/init.json"
grep -F '"initialized":true' "$TMP_DIR/init.json"

curl --fail --silent --show-error -H 'Content-Type: application/json' \
    -d '{"name":"rsa-smoke","common_name":"rsa-smoke.test","dns_names":["rsa-smoke.test"],"ip_addresses":["192.0.2.30"],"valid_days":30,"confirm_server_key_generation":true}' \
    http://127.0.0.1:18081/api/v1/certificates/rsa >"$TMP_DIR/rsa.json"
grep -F '"id":"rsa-smoke"' "$TMP_DIR/rsa.json"

curl --fail --silent --show-error -H 'Content-Type: application/json' \
    -d '{"name":"tlcp-smoke","common_name":"tlcp-smoke.test","dns_names":["tlcp-smoke.test"],"valid_days":30,"confirm_server_key_generation":true}' \
    http://127.0.0.1:18081/api/v1/certificates/tlcp >"$TMP_DIR/tlcp.json"
grep -F '"id":"tlcp-smoke"' "$TMP_DIR/tlcp.json"

curl --fail --silent http://127.0.0.1:18081/api/v1/certificates >"$TMP_DIR/list.json"
grep -F '"id":"rsa-smoke"' "$TMP_DIR/list.json"
grep -F '"id":"tlcp-smoke"' "$TMP_DIR/list.json"

check_ocsp() {
    expected=$1
    kind=$2
    cert=$3
    issuer="$TMP_DIR/data/pki/ca/$kind/root-ca.crt"
    request="$TMP_DIR/$kind-request.der"
    response="$TMP_DIR/$kind-response.der"
    "$OPENSSL_BIN" ocsp -issuer "$issuer" -cert "$cert" -reqout "$request" -no_nonce
    curl --fail --silent --show-error -H 'Content-Type: application/ocsp-request' \
        --data-binary "@$request" "http://127.0.0.1:18081/ocsp/$kind" >"$response"
    "$OPENSSL_BIN" ocsp -respin "$response" -issuer "$issuer" -cert "$cert" \
        -CAfile "$issuer" >"$TMP_DIR/$kind-ocsp.txt" 2>&1
    grep -F "$expected" "$TMP_DIR/$kind-ocsp.txt"
}

check_ocsp good rsa "$TMP_DIR/data/pki/issued/rsa-smoke/server-rsa.crt"
check_ocsp good sm2 "$TMP_DIR/data/pki/issued/tlcp-smoke/server-sign.crt"

for id in rsa-smoke tlcp-smoke; do
    curl --fail --silent --show-error -H 'Content-Type: application/json' -d '{}' \
        "http://127.0.0.1:18081/api/v1/certificates/$id/revoke" >"$TMP_DIR/$id-revoke.json"
    grep -F '"state":"revoked"' "$TMP_DIR/$id-revoke.json"
done

check_ocsp revoked rsa "$TMP_DIR/data/pki/issued/rsa-smoke/server-rsa.crt"
check_ocsp revoked sm2 "$TMP_DIR/data/pki/issued/tlcp-smoke/server-sign.crt"

for kind in rsa sm2; do
    curl --fail --silent --show-error \
        "http://127.0.0.1:18081/api/v1/crl/$kind" >"$TMP_DIR/$kind.crl.pem"
    "$OPENSSL_BIN" crl -in "$TMP_DIR/$kind.crl.pem" -noout -text -verify \
        -CAfile "$TMP_DIR/data/pki/ca/$kind/root-ca.crt" >"$TMP_DIR/$kind-crl.txt" 2>&1
    grep -F 'verify OK' "$TMP_DIR/$kind-crl.txt"
    if ! grep -F 'Serial Number' "$TMP_DIR/$kind-crl.txt"; then
        echo "$kind CRL contains no revoked serial" >&2
        cat "$TMP_DIR/$kind-crl.txt" >&2
        cat "$TMP_DIR/server.log" >&2
        exit 1
    fi
done

curl --fail --silent --dump-header "$TMP_DIR/key.headers" \
    http://127.0.0.1:18081/api/v1/certificates/rsa-smoke/files/server-rsa.key \
    --output "$TMP_DIR/server-rsa.key"
grep -i -F 'cache-control: no-store' "$TMP_DIR/key.headers"
grep -F 'PRIVATE KEY' "$TMP_DIR/server-rsa.key"

status=$(curl --silent --output "$TMP_DIR/denied.json" --write-out '%{http_code}' \
    http://127.0.0.1:18081/api/v1/certificates/rsa-smoke/files/root-ca.key)
test "$status" = "404"
if grep -F 'root-ca.key' "$TMP_DIR/denied.json"; then
    echo "denial response leaked forbidden filename" >&2
    exit 1
fi

echo "WEB SMOKE PASSED"
