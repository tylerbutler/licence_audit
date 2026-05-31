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

# Backwards-compatible alias for format-check
lint: format-check

# Remove build artifacts
clean:
    rm -rf build
    rm -rf priv
    rm -f licence_audit
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

