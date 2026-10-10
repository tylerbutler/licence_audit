# Gleam licence audit command-line tool

# Persisted Hex licence metadata cache (DETS file). Kept in-repo so CI can
# restore it between runs via actions/cache, cutting calls to the Hex API.
hex_cache := ".hex-cache/hex-v2.dets"

# OSS Review Toolkit image used to cross-check our SBOM (see docs/sbom-comparison-ort.md).
ort_image := "ghcr.io/oss-review-toolkit/ort-minimal:74.0.0"
ort_out := "ort-result"

xerj_home := env("HOME") / ".local/share/xerj/licence-audit"
xerj_url := "http://127.0.0.1:19200"

# === ALIASES ===
alias b := build
alias t := test
alias f := format
alias l := lint
alias c := clean
alias cl := change

# Default recipe
default:
    @just --list

# === DEPENDENCIES ===

# Download Gleam dependencies
deps:
    mise exec -- gleam deps download

# === REFERENCE CODING ===

# Install the pinned local search tool.
xerj-install:
    mise install github:xerj-org/xerj

# Run the local search node in the foreground.
xerj-serve:
    #!/usr/bin/env bash
    set -euo pipefail
    umask 077
    mkdir -p {{quote(xerj_home / "data")}}
    mise exec -- xerj --config xerj.toml --data-dir {{quote(xerj_home / "data")}} --embed-mode lexical --disable-feedback

[positional-arguments]
_xerj *args:
    #!/usr/bin/env bash
    set -euo pipefail
    umask 077
    export XERJ_CODE_HOME={{quote(xerj_home)}}
    export XERJ_URL={{quote(xerj_url)}}
    export XERJ_API_KEY="$(cat {{quote(xerj_home / "data/admin.key")}})"
    export XERJ_AUTH="ApiKey $XERJ_API_KEY"
    export XERJ_DISABLE_FEEDBACK=true
    exec mise exec -- xerj "$@"

# Index project sources; pass --dry-run to inspect the plan first.
[positional-arguments]
xerj-index *flags:
    #!/usr/bin/env bash
    set -euo pipefail
    just _xerj autoindex {{quote(justfile_directory())}} --url {{quote(xerj_url)}} \
      --prefix licence-audit --state-dir {{quote(xerj_home / "project-state")}} \
      --no-graph --workers 2 --code-analyzer code "$@"

# Clone reference repositories and record their commits and licences.
xerj-reference-add:
    XERJ_CODE_HOME={{quote(xerj_home)}} XERJ_DISABLE_FEEDBACK=true mise exec -- xerj corpus add licence-audit-references \
      https://github.com/EmbarkStudios/cargo-deny https://github.com/google/osv-scanner \
      https://github.com/oss-review-toolkit/ort https://github.com/gleam-lang/gleam
    cp reference-code.xerjignore {{quote(xerj_home / "corpora/licence-audit-references/.xerjignore")}}

# Index the cloned references; pass --fresh for a verified replacement index.
[positional-arguments]
xerj-reference-index *flags:
    #!/usr/bin/env bash
    set -euo pipefail
    just _xerj corpus index licence-audit-references "$@"

# Search this project's indexed sources.
xerj-search query:
    #!/usr/bin/env bash
    set -euo pipefail
    key=$(cat {{quote(xerj_home / "data/admin.key")}})
    jq -n --arg query {{quote(query)}} '{
      query: {multi_match: {query: $query, fields: ["text", "body", "defs^4"], operator: "and"}},
      size: 5, _source: ["ax_path", "start_line", "end_line"], fields: ["_passage"]
    }' | curl --silent --show-error --fail-with-body \
      -H "Authorization: ApiKey $key" -H 'Content-Type: application/json' \
      --data-binary @- {{quote(xerj_url + "/licence-audit-*/_search")}} | jq -r '
      if .error then error(.error.reason)
      elif .timed_out then error("XERJ search timed out.")
      elif ._shards.failed > 0 then error("XERJ search reported failed shards.")
      elif ._shards.total == 0 then error("Project index is missing; run just xerj-index.")
      elif .hits == null then error("XERJ response has no search results.")
      elif .hits.hits | length == 0 then "No matching project source passages."
      else .hits.hits[] |
        "\n\(.["_source"].ax_path):\(.["_source"].start_line // "?")-\(.["_source"].end_line // "?")",
        (.fields._passage[]?.text // empty)
      end'

# Find a mechanism in the reference repositories, with file and line citations.
xerj-reference query:
    @just _xerj code licence-audit-references {{quote(query)}}

# === STANDARD RECIPES ===

# Compile the project into the bundled escript at `./licence_audit`.
build:
    mise exec -- gleam build
    mise exec -- gleam run -m gleescript

# Build everything with warnings treated as errors (used in CI).
build-strict:
    mise exec -- gleam build --warnings-as-errors
    mise exec -- gleam run -m gleescript

# Build self-contained native executables with Queso into `build/queso/`.
build-queso:
    mise exec -- queso build

# Test a native Linux glibc executable with real HTTPS requests, without Erlang.
smoke-native-http binary:
    #!/usr/bin/env bash
    set -euo pipefail
    binary=$(realpath {{quote(binary)}})
    test -x "$binary"
    docker build --quiet --file test/native_http.Dockerfile --tag licence-audit-native-http test
    docker run --rm --user "$(id -u):$(id -g)" \
      --mount "type=bind,src=$binary,dst=/licence_audit,readonly" \
      --mount "type=bind,src=$PWD/test,dst=/tests,readonly" \
      licence-audit-native-http bash /tests/native_http_smoke.sh /licence_audit

# Run tests
test:
    mise exec -- gleam test

# Test CLI application startup and failure diagnostics in fresh Erlang VMs.
test-runtime-startup:
    mise exec -- gleam build
    mise exec -- bash test/runtime_startup.sh

# Type check without producing artifacts
check:
    mise exec -- gleam check

# Format code
format:
    mise exec -- gleam format src test

# Check formatting without making changes
format-check:
    mise exec -- gleam format --check src test

# Run the glinter linter (exits non-zero only on error-level rules)
glint:
    mise exec -- gleam run -m glinter

# Check formatting and run the linter
lint: format-check glint

# Remove build artifacts
clean:
    rm -rf build
    rm -rf priv
    rm -f licence_audit
    rm -rf dist
    rm -rf .hex-cache

# === CHANGELOG ===

# Create a new changelog entry (for example: just change Fixed "Fix ...")
change kind body:
    mise exec -- trellis changelog new --kind {{quote(kind)}} --body {{quote(body)}}

# Preview pending version changes
changelog-preview:
    mise exec -- trellis version plan

# Apply pending versions and regenerate CHANGELOG.md
changelog:
    mise exec -- trellis version apply

# Check Trellis workspace, changelog, version, and tag invariants
doctor:
    mise exec -- trellis doctor

# === SBOM ===

# Generate a release-ready third-party licence notices file into ./dist/NOTICES.txt
notices: build
    mkdir -p dist
    ./licence_audit notices --output=THIRD_PARTY_NOTICES.txt

# Generate a reproducible CycloneDX 1.6 JSON SBOM into ./dist/sbom.json
sbom-generate: build
    mkdir -p dist
    ./licence_audit sbom --reproducible --output=dist/sbom.json --cache-path={{hex_cache}}

# Fail if regenerating the checked-in SBOM changes ./dist/sbom.json.
sbom-drift-check: sbom-generate
    git diff --exit-code -- dist/sbom.json

# Validate the generated SBOM with three independent validators (fails on any
# schema/structural error). cdx-validate runs schema + deep purl/ref checks;
# --fail-severity critical keeps compliance gaps (e.g. "not signed") off the gate.
sbom-validate: sbom-generate
    mise exec -- cyclonedx validate --input-file dist/sbom.json --input-format json --fail-on-errors
    mise exec -- sbom-utility validate --input-file dist/sbom.json
    mise exec -- cdx-validate -i dist/sbom.json --strict --fail-severity critical --no-include-manual

# Score the generated SBOM's quality (informational, local only). sbom-tools is
# CycloneDX 1.6-aware; sbomqs is kept for cross-reference but under-counts
# licences on 1.6 / with the `acknowledgement` field.
sbom-score: sbom-generate
    mise exec -- sbom-tools quality dist/sbom.json
    mise exec -- sbomqs score dist/sbom.json

# Validate the SBOM schema and report its quality score
sbom-check: sbom-validate sbom-score

# === ORT (cross-check) ===
# Generate a reference SBOM with the OSS Review Toolkit (the tool the Gleam guide
# recommends) to cross-check ours. Requires Docker. Output lands in ./ort-result
# (gitignored). See docs/sbom-comparison-ort.md for the analysis. The container
# runs as the host user (-u) so it can write to the mounted output dir.
#
# Note: ORT exits non-zero when it finds unresolved issues (this repo's
# test/fixtures/gleam.toml is a deliberately malformed manifest that ORT cannot
# parse), so the recipes tolerate the exit code and instead assert that the
# expected artifact was written.

_ort *args:
    mkdir -p {{ort_out}}
    docker run --rm -u "$(id -u):$(id -g)" -v "$(pwd)":/workspace -w /workspace {{ort_image}} {{args}}

# Resolve direct + transitive dependencies into ort-result/analyzer-result.yml.
ort-analyze:
    #!/usr/bin/env bash
    set -uo pipefail
    mkdir -p {{ort_out}}
    rm -f {{ort_out}}/analyzer-result.yml
    docker run --rm -u "$(id -u):$(id -g)" -v "$(pwd)":/workspace -w /workspace \
      {{ort_image}} analyze --input-dir /workspace --output-dir /workspace/{{ort_out}} || true
    test -f {{ort_out}}/analyzer-result.yml || { echo "ORT analyze produced no analyzer-result.yml" >&2; exit 1; }

# Render a CycloneDX 1.6 JSON SBOM from the analyzer result into
# ort-result/bom.cyclonedx.json. Run `just ort-analyze` first.
ort-report:
    #!/usr/bin/env bash
    set -uo pipefail
    rm -f {{ort_out}}/bom.cyclonedx.json
    docker run --rm -u "$(id -u):$(id -g)" -v "$(pwd)":/workspace -w /workspace \
      {{ort_image}} report --ort-file /workspace/{{ort_out}}/analyzer-result.yml \
      --output-dir /workspace/{{ort_out}} -f CycloneDx -O CycloneDX=output.file.formats=json || true
    test -f {{ort_out}}/bom.cyclonedx.json || { echo "ORT report produced no bom.cyclonedx.json" >&2; exit 1; }

# Full ORT pipeline: analyze then report -> ort-result/bom.cyclonedx.json.
ort-sbom: ort-analyze ort-report

# Generate both SBOMs and print a purl coverage diff (ours vs ORT). Needs jq.
ort-compare: sbom-generate ort-sbom
    #!/usr/bin/env bash
    set -euo pipefail
    norm() { jq -r '.components[].purl' "$1" | sed -E 's/\?.*//;s#^pkg:[^/]+/##' | sort -u; }
    echo "=== components: ours vs ORT ==="
    echo "ours: $(jq '.components | length' dist/sbom.json)  ort: $(jq '.components | length' {{ort_out}}/bom.cyclonedx.json)"
    echo "=== purls only in ours ==="
    comm -23 <(norm dist/sbom.json) <(norm {{ort_out}}/bom.cyclonedx.json) || true
    echo "=== purls only in ORT ==="
    comm -13 <(norm dist/sbom.json) <(norm {{ort_out}}/bom.cyclonedx.json) || true

# Remove ORT output.
ort-clean:
    rm -rf {{ort_out}}

# === DOCS ===

# Generate Markdown reference docs into ./docs and inject the topics index
# into README.md between the <!-- commands --> sentinels.
docs: build
    mise exec -- gleam run -m licence_audit/gen_docs -- --mode=multi --out=docs --readme=README.md

# Fail if `just docs` would change anything on disk (use in CI to catch drift).
docs-check: build
    mise exec -- gleam run -m licence_audit/gen_docs -- --mode=multi --out=docs --readme=README.md --check

# === CI ===

# Full validation workflow (matches what CI runs)
ci: doctor format-check glint check test test-runtime-startup build-strict docs-check sbom-drift-check sbom-validate

alias pr := ci
