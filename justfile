# Gleam licence audit command-line tool

# Persisted package metadata cache path. Kept in-repo so CI can restore
# .hex-cache/ between runs via actions/cache and avoid repeated downloads.
hex_cache := ".hex-cache"

# OSS Review Toolkit image used to cross-check our SBOM (see docs/sbom-comparison-ort.md).
ort_image := "ghcr.io/oss-review-toolkit/ort-minimal:74.0.0"
ort_out := "ort-result"

# CI jobs with separate tool versions can use the tools already on PATH.
toolchain := env("LICENCE_AUDIT_TOOLCHAIN", "mise exec --")
python := if os_family() == "windows" { "python" } else { "python3" }

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
    {{toolchain}} gleam deps download

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
    {{toolchain}} gleam export escript

# Build everything with warnings treated as errors (used in CI).
build-strict:
    {{toolchain}} gleam build --warnings-as-errors
    {{toolchain}} gleam export escript

# Build self-contained native executables with Queso into `build/queso/`.
[positional-arguments]
build-queso *args:
    {{toolchain}} queso build "$@"

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

# Compile native test helpers into the development build only.
test-ffi:
    {{toolchain}} {{python}} -B scripts/test_ffi.py

# Run tests
test: test-ffi
    {{toolchain}} gleam test

# Check picker reader exit before terminal restoration and policy writing.
[unix]
test-picker-lifecycle: test-ffi
    {{toolchain}} {{python}} -B test/picker_lifecycle.py

# Run only the SPDX/policy examples and fixed-seed properties.
test-spdx-policy: test-ffi
    {{toolchain}} gleam build
    {{toolchain}} erl -noshell -pa build/dev/erlang/*/ebin -eval 'case eunit:test([licence_audit@spdx_expression_test, licence_audit@policy_test, licence_audit@spdx_policy_property_test], [verbose, {print_depth, 1000}]) of ok -> halt(0); error -> halt(1) end.'

# Check notices filtering with real CLI cache settings in fresh Erlang VMs.
test-notices-filter:
    mise exec -- gleam build
    mise exec -- bash test/notices_filter.sh

# Test CLI application startup and failure diagnostics in fresh Erlang VMs.
test-runtime-startup:
    mise exec -- gleam build
    mise exec -- bash test/runtime_startup.sh

# Test platform-specific atomic policy writes in fresh VMs.
[linux]
test-update-atomic:
    {{toolchain}} gleam build
    {{toolchain}} {{python}} -B test/update_atomic_write.py

[macos]
test-update-atomic:
    {{toolchain}} gleam build
    {{toolchain}} {{python}} -B test/update_atomic_macos.py

[windows]
test-update-atomic: test-ffi
    {{toolchain}} {{python}} -u -B test/update_atomic_windows.py

# Capture report and diagnostic streams from the built CLI independently.
test-cli-streams: build
    mise exec -- python3 -B test/cli_stream_test.py

# Test default cache paths in fresh VMs on all supported platforms.
test-cache-paths:
    {{toolchain}} gleam build
    {{toolchain}} {{python}} -B test/cache_default_paths.py

# Test Unicode environment conversion and default cache paths in fresh VMs.
test-env-cache-paths: build test-cache-paths
    mise exec -- bash test/env_cache_paths.sh

# Smoke-test the built CLI without rebuilding an escript with embedded notices.
test-escript:
    ./licence_audit --help

# Test cache behavior of an existing native executable or escript.
[positional-arguments]
test-cache binary *args:
    {{toolchain}} {{python}} -B test/native_cache_smoke.py "$@"

# Test an existing native executable in a container without system Erlang.
test-native-cache binary:
    test -f {{quote(binary)}}
    docker run --rm \
      --mount "type=bind,src=$PWD,dst=/work" --workdir /work \
      debian:bookworm-slim sh -ec \
      'apt-get update -qq && apt-get install -y --no-install-recommends ca-certificates libstdc++6 libtinfo6 python3 && exec python3 -B test/native_cache_smoke.py "$1"' \
      sh {{quote(binary)}}

# Type check the project without generating its executable code
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

# Remove build artifacts and the local Hex cache; preserve dist/.
clean:
    rm -rf build
    rm -rf priv
    rm -f licence_audit
    rm -rf .hex-cache

# === CHANGELOG ===

# Create a new changelog entry (for example: just change Fixed "Fix ...")
change kind body:
    mise exec -- trellis changelog new --kind {{quote(kind)}} --body {{quote(body)}}

# Preview pending version changes
[positional-arguments]
changelog-preview *args:
    mise exec -- trellis version plan "$@"

# Check changelog fragments between refs; accepts Trellis output options.
[positional-arguments]
changelog-check *args:
    {{toolchain}} trellis changelog check "$@"

# Apply pending versions and regenerate CHANGELOG.md
[positional-arguments]
changelog *args:
    mise exec -- trellis version apply "$@"

# Prepare or resume release/pending (pushes a branch and creates/updates its PR).
[positional-arguments]
release-pr *args:
    mise exec -- trellis release pr --base main --branch release/pending "$@"

# Create tags for prepared releases; pass --github-release to publish them.
[positional-arguments]
release-tag *args:
    {{toolchain}} trellis tag create "$@"

# Publish prepared releases; accepts Trellis tag selection options.
[positional-arguments]
publish *args:
    {{toolchain}} trellis publish "$@"

# Embed, stage, or check required release notices.
[positional-arguments]
release-notices *args:
    {{toolchain}} {{python}} -B scripts/release_notices.py "$@"

# Collect native runtime notices from Queso's build log.
[positional-arguments]
runtime-notices *args:
    {{toolchain}} {{python}} -B scripts/runtime_notices.py "$@"

# Check Trellis workspace, changelog, version, and tag invariants
doctor:
    mise exec -- trellis doctor

# === SBOM ===

# Generate an SBOM with explicit CLI options from an existing or fresh build.
[positional-arguments]
sbom *args: build
    ./licence_audit sbom "$@"

# Generate a release-ready third-party licence notices file into ./THIRD_PARTY_NOTICES.txt
notices: build
    ./licence_audit notices --output=THIRD_PARTY_NOTICES.txt

# Generate a reproducible CycloneDX 1.6 JSON SBOM into ./dist/sbom.json
sbom-generate: build
    mkdir -p dist
    ./licence_audit sbom --reproducible --output=dist/sbom.json --cache-dir={{hex_cache}}

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
    {{toolchain}} pnpm --dir website install --frozen-lockfile

# Check Astro types and the website routing worker.
website-check:
    {{toolchain}} pnpm --dir website check
    {{toolchain}} pnpm --dir website test

# Build the static website without deploying it.
website-build:
    {{toolchain}} pnpm --dir website build

# === CI ===

# Validate a PR title using the repository's commitlint configuration.
[positional-arguments]
pr-title-check title:
    printf '%s\n' "$1" | {{toolchain}} npx commitlint

# Full validation workflow (matches what CI runs)
ci: doctor vendor-check vendor-test format-check glint test test-notices-filter test-runtime-startup test-env-cache-paths build-strict test-vendor-production docs-check test-docs website-deps website-check website-build sbom-drift-check sbom-validate

alias pr := ci
