#!/bin/sh
set -eu

[ "$#" -eq 2 ] || { echo "Usage: $0 PREVIOUS.deb CURRENT.deb" >&2; exit 2; }
previous=$(realpath "$1")
current=$(realpath "$2")
cleanup() {
    apt-get purge -y ipad-manager >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM
dpkg-query -W ipad-manager >/dev/null 2>&1 && exit 3
apt-get install -y "$previous"
printf '\n' >> /etc/ipad-manager/config.json
apt-get install -y "$current"
ipad-manager-health --json | python3 -c 'import json,sys; assert json.load(sys.stdin)["status"] == "pass"'
trap - EXIT HUP INT TERM
cleanup
echo "Debian upgrade checks passed"
