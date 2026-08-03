#!/bin/sh
set -eu

package=$(find /packages -maxdepth 1 -name 'certarium_*_amd64.deb' -print -quit)
test -n "$package"
dpkg-deb -c "$package" | grep -F './usr/share/doc/certarium/LICENSE'
dpkg-deb -c "$package" | grep -F './usr/share/doc/certarium/Tongsuo-LICENSE.txt'
apt-get install -y "$package"
# debian:slim intentionally path-excludes /usr/share/doc during installation;
# the package payload itself was checked immediately above.
CERTARIUM_SKIP_INSTALLED_DOC_CHECK=1 /usr/local/bin/installed-package-smoke
test -s /var/lib/certarium/package-smoke/private-key-hashes.before-uninstall
cp /var/lib/certarium/package-smoke/private-key-hashes.before-uninstall /tmp/private-key-hashes
apt-get remove -y certarium
test -d /var/lib/certarium/package-smoke
test -f /etc/certarium/certarium.env
sha256sum -c /tmp/private-key-hashes
echo 'DEBIAN 12 DEB INSTALL/UNINSTALL SMOKE PASSED'
