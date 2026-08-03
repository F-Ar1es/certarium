# Operations

The service runs as `certarium`, listens on `127.0.0.1:8080`, reads
`/etc/certarium`, and stores durable state and `audit.jsonl` in
`/var/lib/certarium`.

```sh
systemctl status certarium
journalctl -u certarium --no-pager -n 100
curl --fail http://127.0.0.1:8080/api/v1/health
```

Use the package manager for upgrades. Reinstall and ordinary removal preserve
the passphrase, configuration, CA, certificates, revocation database, and audit
history. Back up before upgrading. Never replace `ca.pass`: losing it makes the
encrypted CA keys unusable.

For VM acceptance, copy a package and `tools/systemd-vm-smoke.sh` into a clean
systemd VM and run it as root. Reboot and rerun the health/inventory checks to
complete persistence verification; the script intentionally never reboots hosts.
