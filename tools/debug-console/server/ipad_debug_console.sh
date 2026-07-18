#!/bin/sh
set -eu

HOST="${IPAD_DEBUG_CONSOLE_HOST:-127.0.0.1}"
PORT="${IPAD_DEBUG_CONSOLE_PORT:-8765}"

case "$HOST" in
  127.0.0.1|localhost) ;;
  *) echo "Refusing to bind non-local host by default: $HOST" >&2; exit 2 ;;
esac

echo "Debug console static files are in tools/debug-console/static"
echo "Bind address: $HOST:$PORT"

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec node "$SCRIPT_DIR/server.js"
