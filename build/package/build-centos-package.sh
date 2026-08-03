#!/bin/sh
set -eu

VERSION=${VERSION:-0.1.0}
OUT=/out
STAGE=/tmp/certarium-rootfs
TOP=/tmp/rpmbuild
rm -rf "$STAGE" "$TOP"
mkdir -p "$STAGE" "$TOP/BUILD" "$TOP/BUILDROOT" "$TOP/RPMS" "$TOP/SOURCES" "$TOP/SPECS" "$TOP/SRPMS" "$OUT"
cp -a /src/packaging/rootfs/. "$STAGE/"
install -D -m 0755 /build/certarium "$STAGE/usr/bin/certarium"
install -D -m 0755 /opt/tongsuo/bin/openssl "$STAGE/opt/certarium/bin/openssl"
install -d -m 0755 "$STAGE/opt/certarium/lib/ossl-modules"
for modules in /opt/tongsuo/lib/ossl-modules /opt/tongsuo/lib64/ossl-modules; do
    if [ -d "$modules" ]; then
        cp -a "$modules"/. "$STAGE/opt/certarium/lib/ossl-modules/"
    fi
done
install -d -m 0700 "$STAGE/var/lib/certarium"
install -d -m 0755 "$STAGE/usr/share/doc/certarium"
for file in LICENSE NOTICE THIRD_PARTY_NOTICES.md COMMERCIAL_LICENSE.md; do
    install -m 0644 "/src/$file" "$STAGE/usr/share/doc/certarium/$file"
done
install -m 0644 /build/Tongsuo/LICENSE.txt "$STAGE/usr/share/doc/certarium/Tongsuo-LICENSE.txt"

{
    echo "certarium_version=$VERSION"
    echo "build_arch=$(uname -m)"
    echo "glibc=$(getconf GNU_LIBC_VERSION)"
    echo "tongsuo_commit=$TONGSUO_COMMIT"
    echo "go_binary_static=$(file /build/certarium)"
    echo "tongsuo_version=$(/opt/tongsuo/bin/openssl version)"
} >"$STAGE/usr/share/doc/certarium/BUILD-MANIFEST.txt"

readelf --version-info "$STAGE/opt/certarium/bin/openssl" >"$OUT/TONGSUO-GLIBC-VERSIONS.txt"
if grep -E 'GLIBC_2\.(1[89]|[2-9][0-9])' "$OUT/TONGSUO-GLIBC-VERSIONS.txt"; then
    echo 'Tongsuo requires glibc newer than 2.17' >&2
    exit 1
fi
file "$STAGE/usr/bin/certarium" | grep -F 'x86-64'
file "$STAGE/usr/bin/certarium" | grep -F 'statically linked'

cp -a "$STAGE" "$TOP/SOURCES/rootfs"
sed "s/^Version: .*/Version: $VERSION/" /src/packaging/rpm/certarium.spec >"$TOP/SPECS/certarium.spec"
rpmbuild -bb --define "_topdir $TOP" "$TOP/SPECS/certarium.spec"
cp "$TOP"/RPMS/x86_64/certarium-*.x86_64.rpm "$OUT/"
tar -C "$STAGE" -czf "$OUT/certarium-rootfs-linux-amd64.tar.gz" .
