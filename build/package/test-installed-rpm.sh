#!/bin/sh
set -eu

package=$(find /packages -maxdepth 1 -name 'certarium-*.x86_64.rpm' -print -quit)
test -n "$package"
rpm -i "$package"
/usr/local/bin/installed-package-smoke
test -s /var/lib/certarium/package-smoke/private-key-hashes.before-uninstall
cp /var/lib/certarium/package-smoke/private-key-hashes.before-uninstall /tmp/private-key-hashes
rpm -e certarium
test -d /var/lib/certarium/package-smoke
test -f /etc/certarium/certarium.env
sha256sum -c /tmp/private-key-hashes
echo 'CENTOS 7 RPM INSTALL/UNINSTALL SMOKE PASSED'
