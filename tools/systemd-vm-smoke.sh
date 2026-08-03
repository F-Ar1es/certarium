#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ] || [ "$(cat /proc/1/comm 2>/dev/null || true)" != systemd ]; then
    echo 'run as root in a VM booted with systemd as PID 1' >&2
    exit 2
fi
PACKAGE=${1:?usage: systemd-vm-smoke.sh PACKAGE.rpm|PACKAGE.deb}
case "$PACKAGE" in
    *.rpm) yum install -y "$PACKAGE" ;;
    *.deb) apt-get update; apt-get install -y "$PACKAGE" ;;
    *) echo 'unsupported package suffix' >&2; exit 2 ;;
esac
systemctl enable --now certarium
systemctl is-enabled certarium
systemctl is-active certarium
curl --fail --silent http://127.0.0.1:8080/api/v1/health | grep -F '"status":"ok"'
systemctl restart certarium
systemctl is-active certarium
journalctl -u certarium --no-pager -n 50
echo 'SYSTEMD VM SMOKE PASSED; reboot the VM and rerun without reinstall to verify persistence'
