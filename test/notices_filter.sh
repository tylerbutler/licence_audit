#!/usr/bin/env bash
set -euo pipefail

# Run after `gleam build`, with real CLI cache settings in a fresh VM.
root="$PWD/build/notices-filter-cli"
mkdir -p "$root"
trap 'rm -rf "$root"' EXIT
export XDG_CACHE_HOME="$root/cache"

cat > "$root/manifest.toml" <<'TOML'
packages = [
  { name = "hex_dep", version = "1.0.0", source = "hex", outer_checksum = "unused" },
  { name = "git_dep", version = "1.0.0", source = "git", repo = "https://github.com/example/dep", commit = "abc" },
  { name = "path_dep", version = "1.0.0", source = "path", path = "missing" },
]
TOML
cat > "$root/gleam.toml" <<'TOML'
[tools.licence_audit.notices]
exclude = ["hex_dep", "git_dep", "path_dep"]
TOML

run_cli() {
  timeout --kill-after=5s 30s erl -noshell -pa build/dev/erlang/*/ebin \
    -eval 'licence_audit:main().' -extra notices \
    "--manifest=$root/manifest.toml" "--cache-path=$root/metadata.dets" "$@"
}

output=$(run_cli --quiet)
[[ "$output" == *"Third-party licences"* ]]
[[ "$output" != *"Products using this licence"* ]]
test ! -e "$root/metadata.dets"
test ! -e "$root/cache"

cat > "$root/gleam.toml" <<'TOML'
[tools.licence_audit.notices]
exclude = ["stale"]
TOML
printf 'preserve existing output' > "$root/NOTICES"
status=0
output=$(run_cli "--output=$root/NOTICES" --quiet 2>&1) || status=$?
test "$status" -eq 2
[[ "$output" == *"Unknown locked package names in notices configuration: stale"* ]]
test "$(cat "$root/NOTICES")" = 'preserve existing output'
test ! -e "$root/metadata.dets"
test ! -e "$root/cache"

cat > "$root/manifest.toml" <<'TOML'
packages = [
  { name = "hex_dep", version = "1.0.0", source = "hex", outer_checksum = "unused" },
  { name = "path_dep", version = "1.0.0", source = "path", path = "missing" },
]
[requirements]
hex_dep = { version = ">= 1.0.0" }
path_dep = { path = "missing" }
TOML
cat > "$root/gleam.toml" <<'TOML'
[dev-dependencies]
hex_dep = ">= 1.0.0"
path_dep = { path = "missing" }
[tools.licence_audit.notices]
include = ["hex_dep", "path_dep"]
TOML
output=$(run_cli --quiet)
[[ "$output" == *"Third-party licences"* ]]
[[ "$output" != *"Products using this licence"* ]]
test ! -e "$root/metadata.dets"
test ! -e "$root/cache"

mkdir -p "$root/missing"
printf 'Dev-only licence text\n' > "$root/missing/LICENSE"
printf '\nexclude = ["hex_dep"]\n' >> "$root/gleam.toml"
output=$(run_cli --include-dev --no-cache --quiet)
[[ "$output" == *"path_dep 1.0.0"* ]]
[[ "$output" == *"Dev-only licence text"* ]]
test ! -e "$root/metadata.dets"
test ! -e "$root/cache"

echo "Notices filtering CLI cache tests passed."
