#!/usr/bin/env bash
set -euo pipefail

application=build/prod/erlang/licence_audit/ebin/licence_audit.app
grep -Fq 'licence_audit@internal@vendor@glint,' "$application"
if grep -Eq 'glint_markdown|gen_docs|glugify' "$application"; then
  printf 'Development documentation tooling appears in the production application:\n' >&2
  grep -En 'glint_markdown|gen_docs|glugify' "$application" >&2
  exit 1
fi

for file in build/prod/erlang/licence_audit/ebin/*glint_markdown*.beam \
            build/prod/erlang/licence_audit/ebin/*gen_docs*.beam; do
  if [ -e "$file" ]; then
    printf 'Development module appears in production: %s\n' "$file" >&2
    exit 1
  fi
done

python3 -B - <<'PY'
import zipfile

with zipfile.ZipFile("licence_audit") as archive:
    files = archive.namelist()
    assert "licence_audit@internal@vendor@glint.beam" in files
    leaked = [
        name for name in files
        if any(module in name for module in ("glint_markdown", "gen_docs", "glugify"))
    ]
    if leaked:
        raise SystemExit(f"Development files appear in the shipped escript: {leaked}")
PY
