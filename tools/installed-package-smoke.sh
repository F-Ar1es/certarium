#!/bin/sh
set -eu

PORT=${CERTARIUM_SMOKE_PORT:-18082}
BASE="http://127.0.0.1:$PORT"
STATE=/var/lib/certarium/package-smoke
OPENSSL=/opt/certarium/bin/openssl
WORK=$(mktemp -d "${TMPDIR:-/tmp}/certarium-installed-smoke.XXXXXX")
PID=

cleanup() {
    if [ -n "$PID" ]; then
        kill "$PID" 2>/dev/null || true
        wait "$PID" 2>/dev/null || true
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT HUP INT TERM

id certarium >/dev/null
test "$(stat -c '%U:%G:%a' /var/lib/certarium)" = 'certarium:certarium:700'
grep -Fx 'User=certarium' /usr/lib/systemd/system/certarium.service
grep -F '127.0.0.1:8080' /usr/lib/systemd/system/certarium.service
if [ "${CERTARIUM_SKIP_INSTALLED_DOC_CHECK:-0}" != 1 ]; then
    test -s /usr/share/doc/certarium/LICENSE
    test -s /usr/share/doc/certarium/Tongsuo-LICENSE.txt
fi
test -x /usr/bin/certarium
test -x /usr/bin/certarium-backup
test -x "$OPENSSL"
"$OPENSSL" version | grep -F 'Tongsuo 8.4.0'

install -d -m 0700 -o certarium -g certarium "$STATE"
runuser -u certarium -- /usr/bin/certarium \
    -listen "127.0.0.1:$PORT" -data-dir "$STATE" -tongsuo "$OPENSSL" \
    -ca-passphrase-file /etc/certarium/ca.pass \
    >"$WORK/server.log" 2>&1 &
PID=$!

attempt=0
until curl --fail --silent "$BASE/api/v1/health" >"$WORK/health.json"; do
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 50 ]; then
        cat "$WORK/server.log" >&2
        exit 1
    fi
    sleep 0.1
done
grep -F '"status":"ok"' "$WORK/health.json"

curl --fail --silent --show-error -H 'Content-Type: application/json' \
    -d '{"organization":"Installed Package Smoke"}' \
    "$BASE/api/v1/initialize" >"$WORK/init.json"

curl --fail --silent --show-error -H 'Content-Type: application/json' \
    -d '{"name":"rpm-deb-rsa","common_name":"package-rsa.test","dns_names":["package-rsa.test"],"valid_days":7,"confirm_server_key_generation":true}' \
    "$BASE/api/v1/certificates/rsa" >"$WORK/rsa.json"
grep -F '"id":"rpm-deb-rsa"' "$WORK/rsa.json"

curl --fail --silent --show-error -H 'Content-Type: application/json' \
    -d '{"name":"rpm-deb-tlcp","common_name":"package-tlcp.test","dns_names":["package-tlcp.test"],"valid_days":7,"confirm_server_key_generation":true}' \
    "$BASE/api/v1/certificates/tlcp" >"$WORK/tlcp.json"
grep -F '"id":"rpm-deb-tlcp"' "$WORK/tlcp.json"

check_ocsp() {
    expected=$1
    kind=$2
    cert=$3
    issuer="$STATE/pki/ca/$kind/root-ca.crt"
    "$OPENSSL" ocsp -issuer "$issuer" -cert "$cert" -reqout "$WORK/$kind.req" -no_nonce
    curl --fail --silent --show-error -H 'Content-Type: application/ocsp-request' \
        --data-binary "@$WORK/$kind.req" "$BASE/ocsp/$kind" >"$WORK/$kind.resp"
    "$OPENSSL" ocsp -respin "$WORK/$kind.resp" -issuer "$issuer" -cert "$cert" \
        -CAfile "$issuer" >"$WORK/$kind.txt" 2>&1
    grep -F "$expected" "$WORK/$kind.txt"
}

check_ocsp good rsa "$STATE/pki/issued/rpm-deb-rsa/server-rsa.crt"
check_ocsp good sm2 "$STATE/pki/issued/rpm-deb-tlcp/server-sign.crt"

for id_value in rpm-deb-rsa rpm-deb-tlcp; do
    curl --fail --silent --show-error -H 'Content-Type: application/json' -d '{}' \
        "$BASE/api/v1/certificates/$id_value/revoke" >/dev/null
done
check_ocsp revoked rsa "$STATE/pki/issued/rpm-deb-rsa/server-rsa.crt"
check_ocsp revoked sm2 "$STATE/pki/issued/rpm-deb-tlcp/server-sign.crt"

for kind in rsa sm2; do
    curl --fail --silent "$BASE/api/v1/crl/$kind" >"$WORK/$kind.crl"
    "$OPENSSL" crl -in "$WORK/$kind.crl" -noout -verify \
        -CAfile "$STATE/pki/ca/$kind/root-ca.crt" 2>&1 | grep -F 'verify OK'
done

sha256sum "$STATE/pki/ca/rsa/root-ca.key" "$STATE/pki/ca/sm2/root-ca.key" \
    >"$STATE/private-key-hashes.before-uninstall"
chown certarium:certarium "$STATE/private-key-hashes.before-uninstall"
echo 'INSTALLED PACKAGE SMOKE PASSED'
