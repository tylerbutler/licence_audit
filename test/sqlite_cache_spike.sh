#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -eq 0 ]; then
  echo "Usage: sqlite_cache_spike.sh COMMAND [ARGUMENTS...]" >&2
  exit 1
fi
command=("$@")
work=$(mktemp -d)
holder=""
cleanup() {
  status=$?
  if [ -n "$holder" ]; then
    kill "$holder" 2>/dev/null || true
    wait "$holder" 2>/dev/null || true
  fi
  if [ "$status" -ne 0 ]; then
    for log in "$work"/*.log; do
      [ -f "$log" ] || continue
      printf '\n=== %s ===\n' "$(basename "$log")" >&2
      cat "$log" >&2
    done
  fi
  rm -rf -- "$work"
}
trap cleanup EXIT
cd "$work"
mkdir "cache with spaces" home
database="$work/cache with spaces/metadata.sqlite3"
value=$'{"licences":["MIT"],"publisher":"O\'Brien"}\nline two \u03bb'

run() {
  env HOME="$work/home" XDG_CACHE_HOME="$work/home/.cache" \
    ERL_FLAGS="+S 2:2 +SDcpu 1 +SDio 2" ERL_CRASH_DUMP="$work/erl_crash.dump" \
    timeout --kill-after=2s 10s "${command[@]}" "$@" 2>>"$work/stderr.log"
}

expect() {
  expected=$1
  shift
  output=$(run "$@")
  if [ "$output" != "$expected" ]; then
    printf 'Expected %q, got %q\n' "$expected" "$output" >&2
    exit 1
  fi
}

expect "stored" put "$database" "example@1.0.0" "$value" 100
expect $'100\t'"$value" get "$database" "example@1.0.0"
expect "stored" put "$database" "example@1.0.0" "$value" 200
expect $'200\t'"$value" get "$database" "example@1.0.0"
expect "miss" get "$database" "missing"
expect "stored" put "$database" "x'); DROP TABLE entries; --" "$value" 300
expect $'300\t'"$value" get "$database" "x'); DROP TABLE entries; --"

env HOME="$work/home" XDG_CACHE_HOME="$work/home/.cache" \
  ERL_FLAGS="+S 2:2 +SDcpu 1 +SDio 2" ERL_CRASH_DUMP="$work/erl_crash.dump" \
  timeout --preserve-status --kill-after=2s 15s "${command[@]}" hold "$database" >"$work/holder.log" 2>&1 &
holder=$!
ready=false
for _ in {1..100}; do
  if grep -Fqx "writer locked" "$work/holder.log"; then
    ready=true
    break
  fi
  if ! kill -0 "$holder" 2>/dev/null; then
    echo "Writer exited before it acquired the lock." >&2
    exit 1
  fi
  sleep 0.05
done
if [ "$ready" != true ]; then
  echo "Writer did not acquire the lock within five seconds." >&2
  exit 1
fi

# Another VM can read the committed row while the writer has uncommitted data.
expect $'200\t'"$value" get "$database" "example@1.0.0"
elapsed=0
for index in 1 2 3; do
  output=$(run put "$database" "blocked-$index" "must not persist" 400)
  if [[ ! "$output" =~ ^skipped\ in\ ([0-9]+)\ ms$ ]]; then
    printf 'Expected a skipped busy write, got %q\n' "$output" >&2
    exit 1
  fi
  elapsed=$((elapsed + BASH_REMATCH[1]))
done
if [ "$elapsed" -ge 1000 ]; then
  echo "Busy writes took ${elapsed}ms; expected less than 1000ms in total." >&2
  exit 1
fi
grep -Fq "Warning: cache busy; write skipped" "$work/stderr.log"

kill "$holder"
status=0
wait "$holder" || status=$?
holder=""
if [ "$status" -ne 0 ] && [ "$status" -ne 143 ]; then
  echo "Writer did not stop cleanly on SIGTERM (status $status)." >&2
  exit 1
fi
expect $'200\t'"$value" get "$database" "example@1.0.0"
for index in 1 2 3; do
  expect "miss" get "$database" "blocked-$index"
done
expect "stored" put "$database" "after-release" "safe" 500
expect $'500\tsafe' get "$database" "after-release"

printf 'not a database' >"$work/corrupt.sqlite3"
if run get "$work/corrupt.sqlite3" "example" >"$work/corrupt.log"; then
  echo "A corrupt database must report a failure." >&2
  exit 1
fi
grep -Fq "SQLite spike failed:" "$work/stderr.log"
test "$(cat "$work/corrupt.sqlite3")" = "not a database"
echo "SQLite spike passed: persistence, atomic upsert, WAL reads, busy writes (${elapsed}ms), writer termination, corrupt input."
