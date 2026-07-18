#!/bin/sh
set -eu

if [ "$#" -ne 3 ]; then
  echo "usage: $0 LEGACY_MANAGER NEW_LIBRARY_DIR EXPECTED_SHA256" >&2
  exit 2
fi

manager=$1
library_dir=$2
expected_sha=$3

test -x "$manager"
test -f "$library_dir/libipa.so"

actual_sha=$(sha256sum "$manager" | awk '{print $1}')
if [ "$actual_sha" != "$expected_sha" ]; then
  echo "legacy Manager hash mismatch: $actual_sha" >&2
  exit 1
fi

if ! readelf -d "$manager" | grep -q 'Shared library: \[libipa.so\]'; then
  echo "legacy Manager does not depend on the unversioned libipa.so ABI" >&2
  exit 1
fi

resolved=$(LD_LIBRARY_PATH="$library_dir" ldd "$manager" |
  sed -n 's/^[[:space:]]*libipa[.]so => \(.*\) (0x.*$/\1/p')
if [ "$resolved" != "$library_dir/libipa.so" ]; then
  echo "legacy Manager resolved unexpected SDK: $resolved" >&2
  exit 1
fi

before_sha=$actual_sha
set +e
printf 'q\n' | LD_LIBRARY_PATH="$library_dir" timeout 8s "$manager"
status=$?
set -e
if [ "$status" -ne 0 ] && [ "$status" -ne 124 ]; then
  echo "legacy Manager startup failed with status $status" >&2
  exit "$status"
fi

after_sha=$(sha256sum "$manager" | awk '{print $1}')
if [ "$before_sha" != "$after_sha" ]; then
  echo "legacy Manager binary changed during compatibility test" >&2
  exit 1
fi

echo "legacy Manager loaded new libipa.so without relinking"
