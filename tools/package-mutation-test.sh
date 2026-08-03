#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
WORK=$(mktemp -d "${TMPDIR:-/tmp}/certarium-package-mutants.XXXXXX")
trap 'rm -rf "$WORK"' EXIT HUP INT TERM

prepare() {
    rm -rf "$WORK/tree"
    mkdir -p "$WORK/tree/build" "$WORK/tree/tools"
    cp -a "$ROOT/packaging" "$WORK/tree/"
    cp -a "$ROOT/build/package" "$WORK/tree/build/"
    cp "$ROOT/tools/package-contract-test.sh" "$WORK/tree/tools/"
}

expect_killed() {
    name=$1
    if CERTARIUM_SOURCE_ROOT="$WORK/tree" "$WORK/tree/tools/package-contract-test.sh" >/dev/null 2>&1; then
        echo "SURVIVED: $name" >&2
        exit 1
    fi
    echo "KILLED: $name"
}

prepare
sed -i.bak 's/^User=certarium$/User=root/' "$WORK/tree/packaging/rootfs/usr/lib/systemd/system/certarium.service"
expect_killed root_service

prepare
sed -i.bak 's/127\.0\.0\.1:8080/0.0.0.0:8080/' "$WORK/tree/packaging/rootfs/usr/lib/systemd/system/certarium.service"
expect_killed wildcard_listener

prepare
printf '\nrm -rf /var/lib/certarium\n' >>"$WORK/tree/packaging/deb/postrm"
expect_killed deletes_pki_state

prepare
sed -i.bak '/Tongsuo-LICENSE\.txt/d' "$WORK/tree/build/package/build-centos-package.sh"
expect_killed missing_tongsuo_license

prepare
sed -i.bak '/GLIBC_2/d' "$WORK/tree/build/package/build-centos-package.sh"
expect_killed missing_glibc_guard

prepare
sed -i.bak 's/\[ -d \/run\/systemd\/system \] && //g' "$WORK/tree/packaging/deb/postinst"
expect_killed systemctl_without_systemd

prepare
sed -i.bak 's/if \[ ! -e \/etc\/certarium\/certarium.env \]; then/if [ -e \/etc\/certarium\/certarium.env ]; then/' "$WORK/tree/packaging/rpm/certarium.spec"
expect_killed overwrites_existing_config

echo 'PACKAGE MUTATION TEST PASSED: 7/7 mutants killed'
