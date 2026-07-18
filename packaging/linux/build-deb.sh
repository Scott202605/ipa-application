#!/bin/sh
set -eu

usage() {
    echo "Usage: $0 --sdk-build DIR --output DIR --version VERSION" >&2
    exit 2
}

sdk_build=
output=
version=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --sdk-build) [ "$#" -ge 2 ] || usage; sdk_build=$2; shift 2 ;;
        --output) [ "$#" -ge 2 ] || usage; output=$2; shift 2 ;;
        --version) [ "$#" -ge 2 ] || usage; version=$2; shift 2 ;;
        *) usage ;;
    esac
done
[ -n "$sdk_build" ] && [ -n "$output" ] && [ -n "$version" ] || usage
[ "$(uname -m)" = x86_64 ] || { echo "Only amd64 packages are supported" >&2; exit 3; }

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo=$(CDPATH= cd -- "$script_dir/../.." && pwd)
git_commit=${IPAD_GIT_COMMIT:-}
if [ -z "$git_commit" ]; then
    git_commit=$(git -C "$repo" rev-parse HEAD 2>/dev/null) || {
        echo "Set IPAD_GIT_COMMIT when building from a Windows-created WSL worktree" >&2
        exit 5
    }
fi
sdk_build=$(realpath "$sdk_build")
sdk="$sdk_build/ipa-src/hw/linux/libipa.so"
[ -f "$sdk" ] || { echo "Missing gated SDK: $sdk" >&2; exit 4; }
mkdir -p "$output"
output=$(realpath "$output")
work=$(mktemp -d "${TMPDIR:-/tmp}/ipad-deb.XXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM
build="$work/build"
stage="$work/stage"

cmake -S "$repo/ipad_host_app" -B "$build" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_FLAGS=-Werror \
    -DENABLE_DEBUG=OFF \
    -DIPAD_SDK_ROOT="$repo/ipa_sdk_pc" \
    -DIPA_LIBRARY="$sdk"
cmake --build "$build" --parallel "${IPAD_BUILD_JOBS:-2}"
DESTDIR="$stage" cmake --install "$build" --prefix /usr

install -d "$stage/DEBIAN" "$stage/etc/ipad-manager" \
    "$stage/usr/bin" "$stage/usr/lib/ipad-manager" \
    "$stage/usr/share/applications" "$stage/usr/share/ipad-manager"
install -m 0755 "$sdk" "$stage/usr/lib/ipad-manager/libipa.so"
install -m 0755 "$script_dir/ipad-manager-health" "$stage/usr/bin/ipad-manager-health"
install -m 0755 "$script_dir/ipad-manager-diagnostics" "$stage/usr/bin/ipad-manager-diagnostics"
install -m 0755 "$script_dir/ipad-manager-launch" "$stage/usr/bin/ipad-manager-launch"
install -m 0644 "$script_dir/ipad-manager.desktop" "$stage/usr/share/applications/ipad-manager.desktop"
install -m 0644 "$script_dir/config.json" "$stage/etc/ipad-manager/config.json"
install -m 0644 "$script_dir/config.json" "$stage/usr/share/ipad-manager/ipad_config.example.json"
install -m 0644 "$sdk_build/BUILD_METADATA.txt" "$stage/usr/share/ipad-manager/BUILD_METADATA.txt"
install -m 0644 "$repo/ipa_sdk_pc/DEPENDENCIES.lock.txt" "$stage/usr/share/ipad-manager/DEPENDENCIES.lock.txt"

sed "s/@VERSION@/$version/g" "$script_dir/debian/control.in" > "$stage/DEBIAN/control"
install -m 0644 "$script_dir/debian/conffiles" "$stage/DEBIAN/conffiles"
for lifecycle in postinst prerm postrm; do
    install -m 0755 "$script_dir/debian/$lifecycle" "$stage/DEBIAN/$lifecycle"
done

STAGE="$stage" VERSION="$version" GIT_COMMIT="$git_commit" python3 - <<'PY'
import hashlib
import json
import os
from pathlib import Path

stage = Path(os.environ["STAGE"])
tracked = []
for path in sorted(stage.rglob("*")):
    if not path.is_file() or "DEBIAN" in path.parts:
        continue
    installed = "/" + path.relative_to(stage).as_posix()
    if installed == "/usr/share/ipad-manager/install-manifest.json":
        continue
    tracked.append({"path": installed, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
manifest = {
    "schema_version": 1,
    "package": "ipad-manager",
    "version": os.environ["VERSION"],
    "git_commit": os.environ["GIT_COMMIT"],
    "files": tracked,
}
(stage / "usr/share/ipad-manager/install-manifest.json").write_text(
    json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
PY

if [ -n "${SOURCE_DATE_EPOCH:-}" ]; then
    find "$stage" -print0 | xargs -0 touch -h -d "@$SOURCE_DATE_EPOCH"
fi
artifact="$output/ipad-manager_${version}_amd64.deb"
dpkg-deb --root-owner-group --build "$stage" "$artifact"
sha256sum "$artifact"
