# Gleam licence audit command-line tool

# Persisted Hex licence metadata cache (DETS file). Kept in-repo so CI can
# restore it between runs via actions/cache, cutting calls to the Hex API.
hex_cache := ".hex-cache/hex-v2.dets"

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

# Run tests
test:
    mise exec -- gleam test

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

# Create a new changelog entry
change:
    mise exec -- changie new

# Preview unreleased changelog
changelog-preview:
    mise exec -- changie batch auto --dry-run

# Generate CHANGELOG.md from unreleased fragments
changelog:
    mise exec -- changie merge

# === SBOM ===

# Generate a release-ready third-party licence notices file into ./dist/NOTICES.txt
notices: build
    mkdir -p dist
    ./licence_audit notices --output=dist/NOTICES.txt

# Generate a reproducible CycloneDX 1.6 JSON SBOM into ./dist/sbom.json
sbom-generate: build notices
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
    ./licence_audit gen-docs --mode=multi --out=docs --readme=README.md

# Fail if `just docs` would change anything on disk (use in CI to catch drift).
docs-check: build
    ./licence_audit gen-docs --mode=multi --out=docs --readme=README.md --check

# === CI ===

# Full validation workflow (matches what CI runs)
ci: format-check glint check test build-strict docs-check sbom-drift-check sbom-validate

alias pr := ci
