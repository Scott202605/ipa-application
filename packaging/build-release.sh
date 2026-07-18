#!/bin/sh
set -eu

usage() { echo "Usage: $0 --sdk-build DIR --output DIR [--version-base VERSION]" >&2; exit 2; }
sdk_build=; output=; version_base=1.1.0
while [ "$#" -gt 0 ]; do
    case "$1" in
        --sdk-build) [ "$#" -ge 2 ] || usage; sdk_build=$2; shift 2 ;;
        --output) [ "$#" -ge 2 ] || usage; output=$2; shift 2 ;;
        --version-base) [ "$#" -ge 2 ] || usage; version_base=$2; shift 2 ;;
        *) usage ;;
    esac
done
[ -n "$sdk_build" ] && [ -n "$output" ] || usage
: "${IPAD_GIT_COMMIT:?Set IPAD_GIT_COMMIT to the Windows git rev-parse HEAD value}"
: "${IPAD_SOURCE_DATE_EPOCH:?Set IPAD_SOURCE_DATE_EPOCH to the commit timestamp}"
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo=$(CDPATH= cd -- "$script_dir/.." && pwd)
sdk_build=$(realpath "$sdk_build")
mkdir -p "$output"; output=$(realpath "$output")
version="$version_base+git.$(printf '%s' "$IPAD_GIT_COMMIT" | cut -c1-7)"

ctest --test-dir "$sdk_build" --output-on-failure
python3 "$repo/packaging/tests/test_packaging_policy.py" -v
python3 "$repo/packaging/tests/test_manager_cli.py" -v
python3 "$repo/packaging/tests/test_health_tool.py" -v
python3 "$repo/packaging/tests/test_diagnostics_redaction.py" -v
SOURCE_DATE_EPOCH="$IPAD_SOURCE_DATE_EPOCH" IPAD_GIT_COMMIT="$IPAD_GIT_COMMIT" \
    "$repo/packaging/linux/build-deb.sh" --sdk-build "$sdk_build" --output "$output" --version "$version"
deb="$output/ipad-manager_${version}_amd64.deb"
IPAD_DEB="$deb" python3 "$repo/packaging/tests/test_deb_package.py" -v

extract=$(mktemp -d "${TMPDIR:-/tmp}/ipad-release.XXXXXX")
trap 'rm -rf "$extract"' EXIT HUP INT TERM
dpkg-deb -x "$deb" "$extract"
cp "$extract/usr/share/ipad-manager/BUILD_METADATA.txt" "$output/BUILD_METADATA.txt"
cp "$extract/usr/share/ipad-manager/DEPENDENCIES.lock.txt" "$output/DEPENDENCIES.lock.txt"
cp "$extract/usr/share/ipad-manager/install-manifest.json" "$output/install-manifest.json"
IPAD_ROOT="$extract" "$extract/usr/bin/ipad-manager-health" --json > "$output/health.json"

repo_win=$(wslpath -w "$repo"); deb_win=$(wslpath -w "$deb"); output_win=$(wslpath -w "$output")
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$repo_win\\packaging\\tests\\Test-WindowsInstallerPolicy.ps1"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$repo_win\\packaging\\windows\\build-installer.ps1" \
    -Deb "$deb_win" -Version "$version" -Output "$output_win" -MakeNsis 'C:\tmp\nsis-3.12\makensis.exe'
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$repo_win\\packaging\\tests\\Test-WindowsInstallerArtifact.ps1"

OUTPUT="$output" VERSION="$version" GIT_COMMIT="$IPAD_GIT_COMMIT" python3 - <<'PY'
import json, os
from pathlib import Path
output = Path(os.environ["OUTPUT"])
payload = {"schema_version": 1, "product": "IPAd Manager", "version": os.environ["VERSION"], "git_commit": os.environ["GIT_COMMIT"], "architectures": {"linux": "amd64", "windows": "x64"}, "windows_payload": "canonical-deb"}
(output / "release.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
(cd "$output" && find . -maxdepth 1 -type f ! -name SHA256SUMS -printf '%f\n' | sort | xargs sha256sum > SHA256SUMS)
IPAD_DIST="$output" IPAD_GIT_COMMIT="$IPAD_GIT_COMMIT" python3 "$repo/packaging/tests/test_release_manifest.py" -v
(cd "$output" && sha256sum -c SHA256SUMS)
printf 'Release ready: %s\n' "$output"
