# glint_markdown — Markdown documentation generator for glint CLIs

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

# Compile the project
build:
    mise exec -- gleam build

# Build with warnings treated as errors (used in CI)
build-strict:
    mise exec -- gleam build --warnings-as-errors

# Run tests (Erlang target)
test:
    mise exec -- gleam test

# Run tests on the JavaScript target (nodejs runtime)
test-js:
    mise exec -- gleam test --target javascript --runtime nodejs

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

# === HEX PUBLISHING ===

# Dry-run a Hex publish (does not actually publish)
publish-dry:
    mise exec -- gleam publish --replace --yes

# Publish to Hex. Requires HEX_API_KEY env var (or interactive auth).
publish:
    mise exec -- gleam publish

# === CI ===

# Full validation workflow (matches what CI runs)
ci: format-check glint check test test-js build-strict

alias pr := ci
