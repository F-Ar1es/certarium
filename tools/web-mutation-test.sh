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

echo "All Web/API manual mutants were killed."
