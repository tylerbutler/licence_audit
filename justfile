# Gleam licence audit command-line tool

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

# Compile the project. Copies the Rust port binary next to the bundled
# escript so the shipped layout is just `./licence_audit` + the binary
# (no priv/ subdirectory required at runtime).
build: build-port
    mise exec -- gleam build
    mise exec -- gleam run -m gleescript
    cp priv/licence_audit_toml ./licence_audit_toml

# Build everything with warnings treated as errors (used in CI).
build-strict: build-port
    mise exec -- gleam build --warnings-as-errors
    mise exec -- gleam run -m gleescript
    cp priv/licence_audit_toml ./licence_audit_toml

# Build the Rust TOML port binary for the current platform
build-port:
    cd native/licence_audit_toml && mise exec -- cargo build --release
    mkdir -p priv
    cp native/licence_audit_toml/target/release/licence_audit_toml \
       priv/licence_audit_toml

# Run tests
test: test-port
    mise exec -- gleam test

# Run Rust port-binary unit tests
test-port:
    cd native/licence_audit_toml && mise exec -- cargo test --release

# Type check without producing artifacts
check:
    mise exec -- gleam check

# Format code
format:
    mise exec -- gleam format src test

# Check formatting without making changes
format-check:
    mise exec -- gleam format --check src test

# Backwards-compatible alias for format-check
lint: format-check

# Remove build artifacts
clean:
    rm -rf build
    rm -rf native/licence_audit_toml/target
    rm -rf priv
    rm -f licence_audit licence_audit.ps1
    rm -f licence_audit_toml licence_audit_toml.exe
    rm -rf dist

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

# === CI ===

# Full validation workflow (matches what CI runs)
ci: format-check check test build-strict

alias pr := ci

