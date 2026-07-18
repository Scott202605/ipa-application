#!/bin/sh
set -eu

[ "$#" -eq 1 ] || { echo "Usage: $0 PACKAGE.deb" >&2; exit 2; }
deb=$(realpath "$1")
cleanup() {
    apt-get purge -y ipad-manager >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM

dpkg-query -W ipad-manager >/dev/null 2>&1 && {
    echo "ipad-manager is already installed; refusing destructive lifecycle test" >&2
    exit 3
}

apt-get install -y "$deb"
ipad-manager-health --json | python3 -c 'import json,sys; data=json.load(sys.stdin); assert not any(item["status"] == "fail" for item in data["checks"])'
python3 - <<'PY'
import json
from pathlib import Path
path = Path("/etc/ipad-manager/config.json")
value = json.loads(path.read_text(encoding="utf-8"))
value["user_marker"] = True
path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
PY

apt-get install -y --reinstall "$deb"
grep -q '"user_marker": true' /etc/ipad-manager/config.json
apt-get remove -y ipad-manager
test -f /etc/ipad-manager/config.json
apt-get install -y "$deb"
grep -q '"user_marker": true' /etc/ipad-manager/config.json
apt-get purge -y ipad-manager
test ! -e /etc/ipad-manager/config.json
trap - EXIT HUP INT TERM
echo "Debian lifecycle checks passed"
