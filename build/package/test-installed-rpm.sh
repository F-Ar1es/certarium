#!/bin/sh
set -eu

package=$(find /packages -maxdepth 1 -name 'certarium-*.x86_64.rpm' -print -quit)
test -n "$package"
rpm -i "$package"
/usr/local/bin/installed-package-smoke
sha256sum /etc/certarium/ca.pass /var/lib/certarium/package-smoke/pki/ca/rsa/root-ca.key /var/lib/certarium/package-smoke/pki/ca/sm2/root-ca.key >/tmp/reinstall-hashes
rpm -U --replacepkgs "$package"
sha256sum -c /tmp/reinstall-hashes
printf '%s\n' 'package-backup-password' >/tmp/backup.pass
chmod 0400 /tmp/backup.pass
/usr/bin/certarium-backup -mode backup -file /tmp/certarium.backup -passphrase-file /tmp/backup.pass
/usr/bin/certarium-backup -mode restore -file /tmp/certarium.backup -passphrase-file /tmp/backup.pass -data-dir /tmp/restored-data -config-dir /tmp/restored-config
sha256sum /tmp/restored-data/package-smoke/pki/ca/rsa/root-ca.key /tmp/restored-data/package-smoke/pki/ca/sm2/root-ca.key
test -s /var/lib/certarium/package-smoke/private-key-hashes.before-uninstall
cp /var/lib/certarium/package-smoke/private-key-hashes.before-uninstall /tmp/private-key-hashes
rpm -e certarium
test -d /var/lib/certarium/package-smoke
test -f /etc/certarium/certarium.env
sha256sum -c /tmp/private-key-hashes
echo 'CENTOS 7 RPM INSTALL/REINSTALL/UNINSTALL SMOKE PASSED'
