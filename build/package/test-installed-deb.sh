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
sha256sum /etc/certarium/ca.pass /var/lib/certarium/package-smoke/pki/ca/rsa/root-ca.key /var/lib/certarium/package-smoke/pki/ca/sm2/root-ca.key >/tmp/reinstall-hashes
dpkg -i "$package"
sha256sum -c /tmp/reinstall-hashes
printf '%s\n' 'package-backup-password' >/tmp/backup.pass
chmod 0400 /tmp/backup.pass
/usr/bin/certarium-backup -mode backup -file /tmp/certarium.backup -passphrase-file /tmp/backup.pass
/usr/bin/certarium-backup -mode restore -file /tmp/certarium.backup -passphrase-file /tmp/backup.pass -data-dir /tmp/restored-data -config-dir /tmp/restored-config
sha256sum /tmp/restored-data/package-smoke/pki/ca/rsa/root-ca.key /tmp/restored-data/package-smoke/pki/ca/sm2/root-ca.key
test -s /var/lib/certarium/package-smoke/private-key-hashes.before-uninstall
cp /var/lib/certarium/package-smoke/private-key-hashes.before-uninstall /tmp/private-key-hashes
apt-get remove -y certarium
test -d /var/lib/certarium/package-smoke
test -f /etc/certarium/certarium.env
sha256sum -c /tmp/private-key-hashes
echo 'DEBIAN 12 DEB INSTALL/REINSTALL/UNINSTALL SMOKE PASSED'
