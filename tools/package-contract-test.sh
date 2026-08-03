#!/bin/sh
set -eu

ROOT=${CERTARIUM_SOURCE_ROOT:-$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)}
UNIT="$ROOT/packaging/rootfs/usr/lib/systemd/system/certarium.service"
ENV_FILE="$ROOT/packaging/rootfs/etc/certarium/certarium.env"
PACKAGE_BUILDER="$ROOT/build/package/build-centos-package.sh"

test -s "$UNIT"
grep -Fx 'User=certarium' "$UNIT"
grep -Fx 'Group=certarium' "$UNIT"
grep -Fx 'UMask=0077' "$UNIT"
grep -Fx 'NoNewPrivileges=true' "$UNIT"
grep -Fx 'PrivateTmp=true' "$UNIT"
grep -F 'ReadWritePaths=/var/lib/certarium' "$UNIT"
grep -F '/usr/bin/certarium -listen 127.0.0.1:8080' "$UNIT"
grep -F -- '-data-dir /var/lib/certarium' "$UNIT"
grep -F -- '-tongsuo /opt/certarium/bin/openssl' "$UNIT"

test -s "$ENV_FILE"
grep -Fx 'CERTARIUM_CRYPTO_TIMEOUT=30s' "$ENV_FILE"
if grep -E '(PASSWORD|TOKEN|PRIVATE_KEY|0\.0\.0\.0)' "$ENV_FILE"; then
    echo 'unsafe packaged configuration' >&2
    exit 1
fi

for file in \
    "$ROOT/packaging/rpm/certarium.spec" \
    "$ROOT/packaging/deb/control" \
    "$ROOT/packaging/deb/postinst" \
    "$ROOT/packaging/deb/prerm"; do
    test -s "$file"
done

grep -F 'License: AGPL-3.0-only' "$ROOT/packaging/rpm/certarium.spec"
grep -F 'certarium.env.default' "$ROOT/packaging/rpm/certarium.spec"
grep -F 'if [ ! -e /etc/certarium/certarium.env ]; then' "$ROOT/packaging/rpm/certarium.spec"
grep -F '[ -d /run/systemd/system ]' "$ROOT/packaging/rpm/certarium.spec"
for script in postinst prerm postrm; do
    grep -F '[ -d /run/systemd/system ]' "$ROOT/packaging/deb/$script"
done
grep -F 'Tongsuo-LICENSE.txt' "$PACKAGE_BUILDER"
grep -F "readelf --version-info" "$PACKAGE_BUILDER"
grep -F "GLIBC_2\\.(1[89]|[2-9][0-9])" "$PACKAGE_BUILDER"
if grep -E 'rm +(-rf +)?/var/lib/certarium' "$ROOT/packaging/rpm/certarium.spec" "$ROOT/packaging/deb/"*; then
    echo 'ordinary package removal deletes PKI state' >&2
    exit 1
fi

echo 'PACKAGE CONTRACT PASSED'
