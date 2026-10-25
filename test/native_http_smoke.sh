#!/usr/bin/env bash
set -euo pipefail

binary=$(realpath "${1:?Usage: native_http_smoke.sh BINARY}")
fixtures="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/fixtures/native_http"
test -x "$binary"
if command -v erl >/dev/null; then
  echo "Run this test in a container without Erlang (just smoke-native-http)." >&2
  exit 1
fi

work=$(mktemp -d)
cleanup() {
  status=$?
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
cp "$fixtures/gleam.toml" "$fixtures/manifest.toml" "$work/"
mkdir "$work/home"
cd "$work"

run() {
  name=$1
  shift
  status=0
  env -i HOME="$work/home" XDG_CACHE_HOME="$work/home/.cache" \
    PATH=/usr/bin:/bin ERL_CRASH_DUMP=/dev/null \
    timeout --kill-after=5s 60s "$binary" "$@" >"$name.log" 2>&1 || status=$?
  if grep -Eq 'noproc|Failed to eval|Runtime terminating|Crash dump|Vulnerability check incomplete:|\(details unavailable\)' "$name.log" \
    || { grep -E 'WARN[[:space:]]+\|' "$name.log" \
      | grep -Ev 'IPv6 .*; using IPv4 for the remaining Hex and OSV requests'; }; then
    echo "$name: runtime failure or incomplete report" >&2
    exit 1
  fi
  if [ "$name" = check ] && [ "$status" -eq 1 ]; then
    # A new advisory may fail the gate; a crash or failed request must not pass.
    grep -Fq 'Vulnerability check failed: one or more advisories' "$name.log"
  elif [ "$status" -ne 0 ]; then
    echo "$name: unexpected exit $status" >&2
    exit 1
  fi
}

run help --help
grep -Fq 'USAGE:' help.log
run version --version
grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+' version.log

run report --no-cache --color=never
grep -Eq 'gleam_stdlib[[:space:]]+1\.0\.5[[:space:]]+Apache-2\.0' report.log
grep -Fq 'Skipped non-Hex packages: 0' report.log

run vulns vulns --color=never
grep -Eq '^Checked 1 packages: (0 with vulnerabilities, 1 clean|1 with vulnerabilities, 0 clean)\.$' vulns.log

run check check --vulns --no-cache --color=never
grep -Eq 'gleam_stdlib[[:space:]]+1\.0\.5[[:space:]]+Apache-2\.0.*allowed' check.log
grep -Eq 'No known vulnerabilities reported by OSV.dev.|advisory/advisories at or above' check.log

run sbom sbom --reproducible --offline --output=smoke-sbom.json
test -s smoke-sbom.json
grep -Fq 'pkg:hex/gleam_stdlib@1.0.5' smoke-sbom.json
echo "Native HTTP smoke test passed."
