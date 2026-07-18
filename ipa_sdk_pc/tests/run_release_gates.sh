#!/bin/sh
set -eu

sdk_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
gate_root=${IPA_RELEASE_BUILD_ROOT:-"$sdk_root/build-release-gates"}
legacy_manager=${1:-}
legacy_sha=${2:-}
previous_library=${3:-}
source_commit=$(git -c safe.directory="$(dirname "$sdk_root")" \
  -C "$sdk_root" rev-parse --verify HEAD 2>/dev/null || echo unknown)

case "$gate_root" in
  "$sdk_root"/build-*) ;;
  *) echo "unsafe release build path: $gate_root" >&2; exit 2 ;;
esac
rm -rf -- "$gate_root"
mkdir -p "$gate_root"

if [ -n "$legacy_manager" ] && [ -n "$legacy_sha" ]; then
  cmake -S "$sdk_root" -B "$gate_root/release" -DBUILD_SHARED_LIBS=ON \
    -DBUILD_TESTING=ON -DCMAKE_BUILD_TYPE=Release \
    -DIPA_BUILD_GIT_COMMIT="$source_commit" \
    -DIPA_LEGACY_MANAGER_BINARY="$legacy_manager" \
    -DIPA_LEGACY_MANAGER_SHA256="$legacy_sha"
else
  cmake -S "$sdk_root" -B "$gate_root/release" -DBUILD_SHARED_LIBS=ON \
    -DBUILD_TESTING=ON -DCMAKE_BUILD_TYPE=Release \
    -DIPA_BUILD_GIT_COMMIT="$source_commit"
fi
cmake --build "$gate_root/release" -j2
ctest --test-dir "$gate_root/release" --output-on-failure

cmake -S "$sdk_root" -B "$gate_root/asan" -DBUILD_SHARED_LIBS=ON \
  -DBUILD_TESTING=ON -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DIPA_BUILD_GIT_COMMIT="$source_commit" \
  -DIPA_ENABLE_ASAN_UBSAN=ON
cmake --build "$gate_root/asan" -j2
ctest --test-dir "$gate_root/asan" --output-on-failure

cmake -S "$sdk_root" -B "$gate_root/tsan" -DBUILD_SHARED_LIBS=ON \
  -DBUILD_TESTING=ON -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DIPA_BUILD_GIT_COMMIT="$source_commit" -DIPA_ENABLE_TSAN=ON
cmake --build "$gate_root/tsan" -j2
ctest --test-dir "$gate_root/tsan" --output-on-failure

for test_binary in ipa_config_snapshot_test ipa_task_supervisor_test \
                   ipa_runtime_lifecycle_test ipa_euicc_executor_test \
                   ipa_eim_registry_test ipa_diagnostics_test; do
  valgrind --quiet --error-exitcode=99 --leak-check=full \
    "$gate_root/release/tests/$test_binary"
done

package_dir="$gate_root/package"
mkdir -p "$package_dir"
cp "$gate_root/release/ipa-src/hw/linux/libipa.so" "$package_dir/libipa.so"
cp "$gate_root/release/BUILD_METADATA.txt" "$package_dir/BUILD_METADATA.txt"
cp "$sdk_root/DEPENDENCIES.lock.txt" "$package_dir/DEPENDENCIES.lock.txt"
if [ -n "$previous_library" ]; then
  cp "$previous_library" "$package_dir/libipa.previous.so"
fi
(cd "$package_dir" && sha256sum ./* > SHA256SUMS)
echo "release gates passed; package: $package_dir"
