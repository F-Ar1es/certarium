# Encrypted backup and restore

Backups include configuration, the CA credential, encrypted CA keys, PKI state,
issued material, and audit history. Stop the service and keep the backup password
in a separate mode-0400 file.

```sh
sudo systemctl stop certarium
sudo certarium-backup -mode backup -data-dir /var/lib/certarium \
  -config-dir /etc/certarium -file /secure/certarium.backup \
  -passphrase-file /secure/backup.pass
sudo systemctl start certarium
```

The artifact uses AES-256-GCM with PBKDF2-HMAC-SHA256 and an authenticated
SHA-256 manifest. No plaintext archive is written. Restore rejects wrong
passwords, corruption, links, unsafe paths, duplicates, and hash mismatches.

```sh
sudo systemctl stop certarium
sudo certarium-backup -mode restore -data-dir /var/lib/certarium \
  -config-dir /etc/certarium -file /secure/certarium.backup \
  -passphrase-file /secure/backup.pass
sudo systemctl start certarium
```

Destinations must be absent unless `-replace` is explicitly supplied. Preserve
the current directories separately before replacement. Possession of both the
backup and password grants access to all included private keys.
