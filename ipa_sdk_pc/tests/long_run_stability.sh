#!/bin/sh
set -eu

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
  echo "usage: $0 BUILD_DIR [DURATION_SECONDS]" >&2
  exit 2
fi
build_dir=$1
duration=${2:-86400}
test_binary="$build_dir/tests/ipa_fault_injection_smoke"
test -x "$test_binary"

deadline=$(($(date +%s) + duration))
cycles=0
failures=0
max_rss_kb=0
while [ "$(date +%s)" -lt "$deadline" ]; do
  metrics=$(/usr/bin/time -f '%M' "$test_binary" 2>&1 >/dev/null) || failures=$((failures + 1))
  case "$metrics" in
    ''|*[!0-9]*) ;;
    *) [ "$metrics" -le "$max_rss_kb" ] || max_rss_kb=$metrics ;;
  esac
  cycles=$((cycles + 1))
done
echo "duration_seconds=$duration cycles=$cycles failures=$failures max_rss_kb=$max_rss_kb"
[ "$failures" -eq 0 ]
