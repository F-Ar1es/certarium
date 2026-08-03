#!/bin/sh
set -eu

GO_BIN=${GO_BIN:-go}
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TMP_DIR=$(mktemp -d)
CURRENT_FILE=

restore() {
    if [ -n "$CURRENT_FILE" ] && [ -f "$TMP_DIR/original" ]; then
        cp "$TMP_DIR/original" "$CURRENT_FILE"
    fi
}

cleanup() {
    restore
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT HUP INT TERM

run_mutant() {
    name=$1
    file=$2
    before=$3
    after=$4
    test_name=$5
    CURRENT_FILE="$ROOT/$file"
    cp "$CURRENT_FILE" "$TMP_DIR/original"
    if ! grep -F "$before" "$CURRENT_FILE" >/dev/null; then
        echo "mutation anchor missing: $name" >&2
        exit 1
    fi
    sed "s#$before#$after#" "$TMP_DIR/original" >"$CURRENT_FILE"
    if "$GO_BIN" test ./internal/webapp -run "$test_name" >"$TMP_DIR/test.log" 2>&1; then
        echo "SURVIVED: $name" >&2
        cat "$TMP_DIR/test.log" >&2
        exit 1
    fi
    restore
    CURRENT_FILE=
    rm -f "$TMP_DIR/original"
    echo "KILLED: $name"
}

cd "$ROOT"
run_mutant explicit-key-confirmation internal/webapp/handler.go \
    'if !input.ConfirmServerKeyGeneration {' 'if false {' \
    TestIssuanceRequiresExplicitServerKeyConfirmation
run_mutant loopback-enforcement internal/webapp/handler.go \
    'return ip != nil && ip.IsLoopback()' 'return ip != nil' \
    TestOnlyExplicitLoopbackListenersAreAccepted
run_mutant download-manifest-allowlist internal/webapp/pki_service.go \
    '!containsString(manifest.Files, name)' 'false' \
    TestPKIServiceDownloadUsesManifestAllowlist
run_mutant download-symlink-rejection internal/webapp/pki_service.go \
    'if err != nil || !info.Mode().IsRegular() {' 'if err != nil || false {' \
    TestPKIServiceRejectsSymlinkEvenWhenNameIsAllowlisted
run_mutant safe-dom-rendering internal/webapp/ui.go \
    'title.textContent=' 'title.innerHTML=' \
    TestLocalWebUIAndScriptAreServedSafely
run_mutant tlcp-pair-revocation internal/webapp/pki_service.go \
    'for _, name := range manifest.Files {' 'for _, name := range manifest.Files[:1] {' \
    TestTLCPRevocationIncludesBothCertificates
run_mutant revoked-state-reporting internal/webapp/pki_service.go \
    'target.State = "revoked"' 'target.State = "valid"' \
    TestConcurrentRepeatedRevocationIsIdempotent
run_mutant ocsp-body-limit internal/webapp/handler.go \
    'MaxBytesReader(w, r.Body, 16' 'MaxBytesReader(w, r.Body, 32' \
    TestStandardOCSPRouteEnforcesMIMEAndBodyLimit
run_mutant ocsp-response-content-type internal/webapp/handler.go \
    'w.Header().Set("Content-Type", "application/ocsp-response")' 'w.Header().Set("Content-Type", "application/octet-stream")' \
    TestStandardOCSPRouteEnforcesMIMEAndBodyLimit
run_mutant issuance-status-refresh internal/webapp/pki_service.go \
    'if err := s.refreshIssuer(ctx, kind, ""); err != nil {' 'if err := error(nil); err != nil {' \
    TestIssuanceRefreshesOnlineStatusIndex

echo "All Web/API manual mutants were killed."
