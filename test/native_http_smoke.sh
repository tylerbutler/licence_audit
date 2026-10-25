#!/usr/bin/env bash
set -euo pipefail

binary=$(realpath "${1:?Usage: native_http_smoke.sh BINARY}")
test -x "$binary"
if command -v erl >/dev/null; then
  echo "Run this test in a container without Erlang (just smoke-native-http)." >&2
  exit 1
fi
exec python3 "$(dirname -- "${BASH_SOURCE[0]}")/native_release_smoke.py" --binary "$binary"
