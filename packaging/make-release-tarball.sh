#!/bin/sh

set -eu

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <build-dir> <output-dir>" >&2
    exit 2
fi

BUILD_DIR=$1
OUTPUT_DIR=$2
STAGE_DIR="$OUTPUT_DIR/ipad-manager-release"
TARBALL="$OUTPUT_DIR/ipad-manager-release.tar.gz"

require_file() {
    if [ ! -f "$1" ]; then
        echo "missing required file: $1" >&2
        exit 1
    fi
}

copy_file() {
    src=$1
    dst=$2
    mkdir -p "$(dirname "$dst")"
    cp "$src" "$dst"
}

require_file "$BUILD_DIR/ipad_managerd/ipad-managerd"
require_file "$BUILD_DIR/ipad_worker/ipad-sdk-worker"
require_file "$BUILD_DIR/ipadctl/ipadctl"

rm -rf "$STAGE_DIR" "$TARBALL"
mkdir -p "$STAGE_DIR/bin" "$STAGE_DIR/config" "$STAGE_DIR/docs" "$STAGE_DIR/packaging"

copy_file "$BUILD_DIR/ipad_managerd/ipad-managerd" "$STAGE_DIR/bin/ipad-managerd"
copy_file "$BUILD_DIR/ipad_worker/ipad-sdk-worker" "$STAGE_DIR/bin/ipad-sdk-worker"
copy_file "$BUILD_DIR/ipadctl/ipadctl" "$STAGE_DIR/bin/ipadctl"

cp packaging/config/*.json "$STAGE_DIR/config/"
cp -R packaging/systemd "$STAGE_DIR/packaging/"
cp -R packaging/openrc "$STAGE_DIR/packaging/"
cp -R packaging/sysvinit "$STAGE_DIR/packaging/"
cp -R packaging/manual "$STAGE_DIR/packaging/"
cp -R packaging/tmpfiles "$STAGE_DIR/packaging/"

copy_file docs/quick-start.md "$STAGE_DIR/docs/quick-start.md"
copy_file docs/install-delivery.md "$STAGE_DIR/docs/install-delivery.md"
copy_file docs/real-device-validation.md "$STAGE_DIR/docs/real-device-validation.md"
copy_file docs/real-device-acceptance.md "$STAGE_DIR/docs/real-device-acceptance.md"
copy_file docs/troubleshooting-guide.md "$STAGE_DIR/docs/troubleshooting-guide.md"

if git rev-parse --short HEAD >/dev/null 2>&1; then
    git rev-parse --short HEAD > "$STAGE_DIR/VERSION"
else
    echo "unknown" > "$STAGE_DIR/VERSION"
fi

(
    cd "$STAGE_DIR"
    find . -type f | sort > MANIFEST.txt
)

(
    cd "$OUTPUT_DIR"
    tar -czf "$(basename "$TARBALL")" "$(basename "$STAGE_DIR")"
)

echo "$TARBALL"
