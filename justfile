# Gleam licence audit command-line tool

# Persisted Hex licence metadata cache (DETS file). Kept in-repo so CI can
# restore it between runs via actions/cache, cutting calls to the Hex API.
hex_cache := ".hex-cache/hex-v2.dets"

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

# Generate a CycloneDX 1.6 JSON SBOM into ./dist/sbom.json
sbom-generate: build
    mkdir -p dist
    ./licence_audit sbom --output=dist/sbom.json --cache-path={{hex_cache}}

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

# === CI ===

# Full validation workflow (matches what CI runs)
ci: format-check glint check test build-strict

alias pr := ci

