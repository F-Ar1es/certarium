#!/bin/sh
set -eu

VERSION=${VERSION:-0.1.0}
OUT=/out
PKG=/tmp/certarium-deb
rm -rf "$PKG"
mkdir -p "$PKG/DEBIAN"
tar -C "$PKG" -xzf "$OUT/certarium-rootfs-linux-amd64.tar.gz"
cp /templates/deb/control "$PKG/DEBIAN/control"
sed -i "s/^Version: .*/Version: ${VERSION}-1/" "$PKG/DEBIAN/control"
for file in conffiles postinst prerm postrm; do
    cp "/templates/deb/$file" "$PKG/DEBIAN/$file"
done
chmod 0755 "$PKG/DEBIAN/postinst" "$PKG/DEBIAN/prerm" "$PKG/DEBIAN/postrm"
chmod 0644 "$PKG/DEBIAN/control" "$PKG/DEBIAN/conffiles"
dpkg-deb --root-owner-group --build "$PKG" "$OUT/certarium_${VERSION}-1_amd64.deb"
