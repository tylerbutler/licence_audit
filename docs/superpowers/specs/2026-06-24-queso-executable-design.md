# Queso self-contained executable design

## Goal

`licence_audit` will keep shipping the existing escript and will also attach
fully self-contained Queso executables to each GitHub release. The Queso
artifacts let users run the CLI without installing Erlang/OTP.

The escript remains the default local build output. Queso packaging is opt-in
for contributors and release-only in CI.

## Current state

The project builds `./licence_audit` with `gleescript` through `just build` and
`just build-strict`. CI runs the strict escript build, smoke-tests
`./licence_audit --help`, generates docs, and validates the committed SBOM.

The publish workflow builds one generic escript package. It stages:

- the bare `licence_audit` escript,
- `licence_audit-<tag>.tar.gz`,
- `licence_audit-<tag>.zip`,
- `licence_audit-<tag>.cdx.json`, and
- `checksums.txt`.

The release job attests those artifacts, uploads them to the existing GitHub
release, and appends escript-focused install instructions.

## Architecture

The existing escript path stays unchanged. `just build`, `just build-strict`,
`just ci`, docs generation, SBOM drift checks, and the current bare
`licence_audit` release asset continue to use `gleescript`.

Queso gets a separate path:

1. Add `[tools.queso]` to `gleam.toml`.
2. Set the entry module to `licence_audit`.
3. List all supported Queso targets that the release workflow can build.
4. Add a `just build-queso` recipe that runs `queso build`.
5. Extend the publish workflow with a release-only Queso build and packaging
   step.

Queso writes executables under `build/queso/`. Release packaging will normalize
those output names into predictable assets.

The workflow must use a pinned Queso version. If mise can install the Queso
release binary cleanly, pin it in `.mise.toml`; otherwise install a specific
Queso release in the publish workflow and verify its checksum before use.

## Target policy

The design covers all Queso-supported targets except those that cannot support
NIF dependencies:

- `aarch64-linux-glibc`
- `aarch64-linux-musl`
- `aarch64-macos`
- `x86_64-linux-glibc`
- `x86_64-linux-musl`
- `x86_64-macos`
- `x86_64-windows`

**Excluded — Linux static (`aarch64-linux-static`, `x86_64-linux-static`):**
Queso documents that Linux static binaries do not export the symbols required
for NIF dependencies. This CLI uses Erlang's crypto and SSL NIFs for core
behaviour (SBOM UUID hashing, HTTPS connections to Hex/OSV). Static Linux
binaries would silently fail or crash at runtime. Users on Linux should use
the glibc or musl archives instead.

## Release artifacts

The release will keep the existing generic escript archive and bare escript for
backward compatibility. It will add one Queso archive per target:

```text
licence_audit-<tag>-<target>.tar.gz
licence_audit-<tag>-x86_64-windows.zip
licence_audit-<tag>-aarch64-windows.zip
```

Each target archive contains the self-contained executable and, where present,
`README.md` and `LICENSE`. Windows archives contain the `.exe` executable.
Non-Windows archives contain an executable named `licence_audit`.

`checksums.txt` covers all release assets: the bare escript, escript archives,
Queso archives, and release SBOM. Build provenance and SBOM attestations also
cover the Queso archives.

## Release flow

The publish workflow will:

1. Run the existing CI workflow.
2. Build the escript with `just build-strict`.
3. Generate the CycloneDX release SBOM with the escript.
4. Install Queso and its packaging dependencies.
5. Run `queso build` for the configured targets.
6. Stage the existing escript artifacts.
7. Stage one archive per Queso target.
8. Generate `checksums.txt`.
9. Upload the combined artifact bundle.
10. Attest and publish every release artifact.
11. Append updated install instructions to the GitHub release body.

Queso build failures fail the publish workflow. The workflow must not fall back
to escript-only releases after a Queso failure.

## Local developer workflow

`just build` stays fast and escript-only. Contributors who want a
self-contained executable run:

```sh
just build-queso
```

That recipe depends on Queso's normal package-time tools: Gleam, Erlang, Rust,
and any target-specific cross-compilation tools. If those tools are missing, the
recipe fails with Queso's normal error output.

## Documentation

Update user-facing docs to distinguish the two install paths:

- Self-contained Queso executables do not need Erlang/OTP on the target machine.
- The escript remains available and still needs Erlang/OTP 28.x or newer.
- `mise` installation keeps using the GitHub provider and remains escript-based
  unless the release asset layout later gains a mise-compatible native binary
  mapping.

Update contributor docs to describe `just build-queso`, Queso prerequisites, and
the fact that releases are no longer escript-only.

Update `.github/release-install.md.tmpl` so each release points users first to
the per-target self-contained archive and then to the escript compatibility
option.

Add a changelog fragment because the release artifacts and installation docs
change.

## Validation

Main CI keeps its current escript validation:

- `just format-check`
- `just glint`
- `just check`
- `just build-strict`
- `just test`
- `./licence_audit --help`
- docs and SBOM drift checks
- SBOM schema validation

Release CI validates Queso packaging by building every configured target,
checking that each expected archive exists, adding each archive to
`checksums.txt`, and smoke-testing any Queso executable that can run on the
current runner.

Cross-target executables are validated by successful Queso builds, archive
presence checks, checksums, and attestations.

Queso currently prints hashes for downloaded ERTS archives but does not validate
them automatically. Release logs must retain those hashes. If implementation can
supply verified ERTS archives without making the workflow brittle, prefer that
over Queso's automatic ERTS download.

## Non-goals

This work does not publish the Gleam package to Hex. It does not remove the
escript, change the CLI entry point, change SBOM content, or make Queso part of
the normal PR CI path.
