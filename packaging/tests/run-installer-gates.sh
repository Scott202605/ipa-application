#!/bin/sh
set -eu
repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
: "${IPAD_GIT_COMMIT:?Set IPAD_GIT_COMMIT from Windows git}"
: "${IPAD_SOURCE_DATE_EPOCH:?Set IPAD_SOURCE_DATE_EPOCH from Windows git}"
exec "$repo/packaging/build-release.sh" --sdk-build "$repo/ipa_sdk_pc/build-release-gates/release" --output "$repo/dist" --version-base 1.1.0
