# Gleam licence audit command-line tool

# Persisted package metadata cache path. Kept in-repo so CI can restore
# .hex-cache/ between runs via actions/cache and avoid repeated downloads.
hex_cache := ".hex-cache/hex-v2"

# OSS Review Toolkit image used to cross-check our SBOM (see docs/sbom-comparison-ort.md).
ort_image := "ghcr.io/oss-review-toolkit/ort-minimal:74.0.0"
ort_out := "ort-result"

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

# === VENDORED SOURCES ===

# Regenerate committed source copies after a git-subrepo update.
vendor-sync:
    mise exec -- python3 -B scripts/vendor_sync.py

# Check source drift without changing files or fetching upstream repositories.
vendor-check:
    mise exec -- python3 -B scripts/vendor_sync.py --check

vendor-test:
    mise exec -- python3 -B -m unittest discover -s test -p vendor_sync_test.py

# Verify notice staging, archive contents, and missing-material failures.
test-release-notices:
    mise exec -- python3 -B -m unittest discover -s test -p release_notices_test.py

# Check the production application and the shipped escript.
test-vendor-production: build
    mise exec -- bash test/vendor_production.sh

# === STANDARD RECIPES ===

# Compile the project into the bundled escript at `./licence_audit`.
build:
    mise exec -- gleam export escript

# Build everything with warnings treated as errors (used in CI).
build-strict:
    mise exec -- gleam build --warnings-as-errors
    mise exec -- gleam export escript

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

# Check notices filtering with real CLI cache settings in fresh Erlang VMs.
test-notices-filter:
    mise exec -- gleam build
    mise exec -- bash test/notices_filter.sh

# Test CLI application startup and failure diagnostics in fresh Erlang VMs.
test-runtime-startup:
    mise exec -- gleam build
    mise exec -- bash test/runtime_startup.sh

# Reproduce an interrupted update write in a fresh VM (Linux only).
test-update-atomic:
    mise exec -- gleam build
    mise exec -- python3 -B test/update_atomic_write.py

# Capture report and diagnostic streams from the built CLI independently.
test-cli-streams: build
    mise exec -- python3 -B test/cli_stream_test.py

# Test Unicode environment conversion and ASCII cache paths in fresh VMs.
test-env-cache-paths: build
    mise exec -- gleam build
    mise exec -- bash test/env_cache_paths.sh

# Type check without producing artifacts
check:
    mise exec -- gleam check

# Format code
format:
    mise exec -- gleam format src test dev

# Check formatting without making changes
format-check:
    mise exec -- gleam format --check src test dev

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
[positional-arguments]
changelog-preview *args:
    mise exec -- trellis version plan "$@"

# Apply pending versions and regenerate CHANGELOG.md
[positional-arguments]
changelog *args:
    mise exec -- trellis version apply "$@"

# Prepare or resume release/pending (pushes a branch and creates/updates its PR).
[positional-arguments]
release-pr *args:
    mise exec -- trellis release pr --base main --branch release/pending "$@"

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

_docs-ffi: build
    mise exec -- gleam build
    mise exec -- erlc -o build/dev/erlang/licence_audit/ebin native/dev/licence_audit/internal/vendor/licence_audit_vendor_glint_markdown_filesystem_ffi.erl

# Generate marked CLI reference sections in the canonical website guides.
docs: _docs-ffi
    mise exec -- gleam run -m licence_audit/gen_docs

# Fail if `just docs` would change anything on disk (use in CI to catch drift).
docs-check: _docs-ffi
    mise exec -- gleam run -m licence_audit/gen_docs -- --check

# Exercise generator drift and failure handling in isolated guide copies.
test-docs: _docs-ffi
    mise exec -- python3 -B test/docs_generation.py

# Install the website's locked dependencies.
website-deps:
    mise exec -- pnpm --dir website install --frozen-lockfile

# Check Astro types and the website routing worker.
website-check:
    mise exec -- pnpm --dir website check
    mise exec -- pnpm --dir website test

# Build the static website without deploying it.
website-build:
    mise exec -- pnpm --dir website build

# === CI ===

# Full validation workflow (matches what CI runs)
ci: doctor vendor-check vendor-test format-check glint check test test-notices-filter test-runtime-startup test-env-cache-paths build-strict test-vendor-production docs-check test-docs website-deps website-check website-build sbom-drift-check sbom-validate

alias pr := ci
