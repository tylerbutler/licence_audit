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
    mise exec -- node test/cli_integration.mjs erlang

# Run tests on the JavaScript target (nodejs runtime)
test-js:
    mise exec -- gleam test --target javascript --runtime nodejs
    mise exec -- node test/cli_integration.mjs javascript

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

# Check release configuration and changelog fragments
doctor:
    mise exec -- trellis doctor

# Create a changelog entry: just change Fixed "Describe the change"
change kind body:
    mise exec -- trellis changelog new --kind {{quote(kind)}} --body {{quote(body)}}

# Preview the version bump from unreleased fragments
changelog-preview:
    mise exec -- trellis version plan

# Bump the version, generate CHANGELOG.md, and consume unreleased fragments
changelog:
    mise exec -- trellis version apply

# === GIT RELEASES ===

# Open or update the release PR (requires a clean worktree and GitHub auth)
release-pr:
    mise exec -- trellis release pr --base main --branch release/pending

# === CI ===

# Full validation workflow (matches what CI runs)
ci: doctor format-check glint check test test-js build-strict

alias pr := ci
