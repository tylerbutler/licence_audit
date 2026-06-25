# Queso Executables Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Attach self-contained Queso executables to each GitHub release while keeping the existing escript build and install path.

**Architecture:** Keep `gleescript` as the default local and PR-CI build. Add Queso as an opt-in local recipe and a release-only packaging path that builds one native archive per target, then folds those archives into existing checksums, attestations, and release upload steps. Exclude `aarch64-windows` for now because there is no trustworthy pinned prebuilt OTP 28 Windows ARM64 ERTS archive.

**Tech Stack:** Gleam 1.16.0, Erlang/OTP 28.3, gleescript 1.5.2, Queso 0.3.0, mise, just, GitHub Actions, Rust, cargo-zigbuild, Zig, musl-tools, Changie.

## Global Constraints

- Work on branch `feature/queso-executables`.
- Leave unrelated `AGENTS.md` changes untouched.
- Keep `just build`, `just build-strict`, `just ci`, docs generation, SBOM drift checks, and the current bare `licence_audit` release asset on the existing `gleescript` path.
- Add Queso packaging through a separate `just build-queso` recipe.
- Pin Queso to version `0.3.0`.
- Configure Queso with entry module `licence_audit`.
- Build these Queso targets: `aarch64-linux-glibc`, `aarch64-linux-musl`, `aarch64-linux-static`, `aarch64-macos`, `x86_64-linux-glibc`, `x86_64-linux-musl`, `x86_64-linux-static`, `x86_64-macos`, and `x86_64-windows`.
- Exclude `aarch64-windows` because Queso requires `--erts` for that target and there is no trustworthy pinned prebuilt OTP 28 Windows ARM64 ERTS archive.
- Release one archive per Queso target: `.tar.gz` for Linux/macOS and `.zip` for Windows.
- Each non-Windows Queso archive must contain an executable named `licence_audit`; each Windows Queso archive must contain `licence_audit.exe`.
- Keep the existing escript archive and bare escript for compatibility.
- Add Queso archives to `checksums.txt`, build provenance attestations, SBOM attestations, and release uploads.
- Preserve Queso's ERTS download hash output in release logs.
- Update README, DEV docs, release install template, and Changie fragment.

---

## File Structure

- `.mise.toml`: pins Queso 0.3.0 alongside existing mise-managed tools. The publish workflow uses this pin instead of installing an unversioned binary.
- `gleam.toml`: adds `[tools.queso]` with the entry module and configured target list.
- `justfile`: adds `build-queso` without changing `build`, `build-strict`, or `ci`.
- `.github/workflows/publish.yml`: installs release-only Queso packaging dependencies, builds configured Queso targets, stages per-target archives, validates archive presence, and includes the new archives in existing release artifact flows.
- `README.md`: updates install docs to lead with self-contained Queso archives while retaining escript and mise guidance.
- `DEV.md`: documents `just build-queso`, packaging prerequisites, release artifact shape, and the `aarch64-windows` deferral.
- `.github/release-install.md.tmpl`: updates generated release-body install instructions with native archive examples and escript fallback.
- `.changes/unreleased/queso-executables.md`: records the release artifact change.

---

### Task 1: Add Queso configuration and local recipe

**Files:**
- Modify: `.mise.toml`
- Modify: `gleam.toml`
- Modify: `justfile`

**Interfaces:**
- Consumes: Queso's `[tools.queso]` config keys `entry` and `targets`.
- Produces: `just build-queso`, which release CI and contributors can run to build configured Queso targets into `build/queso/`.

- [ ] **Step 1: Write failing config checks**

Run these checks before editing:

```bash
grep -n 'github:jtdowney/queso' .mise.toml
grep -n '\[tools.queso\]' gleam.toml
just --list | grep -E '^ {4}build-queso'
```

Expected: each command fails because Queso is not pinned, configured, or exposed through a just recipe yet.

- [ ] **Step 2: Pin Queso in `.mise.toml`**

Add this line under the existing core tool pins in `[tools]`:

```toml
"github:jtdowney/queso" = "0.3.0"
```

The top of `.mise.toml` should become:

```toml
[tools]
changie = "1.24.0"
erlang = "28.3"
gleam = "1.16.0"
just = "latest"
rebar = "3.26.0"
"github:jtdowney/queso" = "0.3.0"
```

- [ ] **Step 3: Add Queso config to `gleam.toml`**

Insert this section after the existing empty `[tools]` header and before `[tools.glinter]`:

```toml
[tools.queso]
entry = "licence_audit"
targets = [
  "aarch64-linux-glibc",
  "aarch64-linux-musl",
  "aarch64-linux-static",
  "aarch64-macos",
  "x86_64-linux-glibc",
  "x86_64-linux-musl",
  "x86_64-linux-static",
  "x86_64-macos",
  "x86_64-windows",
]
```

Do not include `aarch64-windows`.

- [ ] **Step 4: Add `build-queso` to `justfile`**

Insert this recipe after `build-strict`:

```just
# Build self-contained native executables with Queso into `build/queso/`.
build-queso:
    mise exec -- queso build
```

Do not add `build-queso` as a dependency of `build`, `build-strict`, or `ci`.

- [ ] **Step 5: Run config checks**

Run:

```bash
grep -n 'github:jtdowney/queso' .mise.toml
grep -n '\[tools.queso\]' gleam.toml
just --list | grep -E '^ {4}build-queso'
```

Expected: all three commands succeed. The `just --list` output includes `build-queso`.

- [ ] **Step 6: Verify the existing escript path is unchanged**

Run:

```bash
just build-strict
./licence_audit --help >/dev/null
```

Expected: `just build-strict` succeeds and `./licence_audit --help` exits `0`.

- [ ] **Step 7: Commit**

```bash
git add .mise.toml gleam.toml justfile
git commit -m "build: add Queso native build recipe"
```

---

### Task 2: Package Queso archives in release CI

**Files:**
- Modify: `.github/workflows/publish.yml`

**Interfaces:**
- Consumes: `just build-queso` from Task 1 and Queso output files named `build/queso/licence_audit-<gleam-version>-<target>[.exe]`.
- Produces: per-target release archives named `licence_audit-<tag>-<target>.tar.gz` or `licence_audit-<tag>-x86_64-windows.zip`, all included in `checksums.txt`, artifact upload, provenance attestation, and SBOM attestation.

- [ ] **Step 1: Write failing workflow checks**

Run:

```bash
grep -n 'Install Queso packaging dependencies' .github/workflows/publish.yml
grep -n 'Build Queso executables' .github/workflows/publish.yml
grep -n 'licence_audit-${REF_NAME}-${target}' .github/workflows/publish.yml
```

Expected: each command fails because the publish workflow only stages escript artifacts.

- [ ] **Step 2: Rename the build job for broader scope**

Change:

```yaml
  build-escript:
    needs: test
    runs-on: ubuntu-latest
    name: Build escript archive
```

to:

```yaml
  build-release-artifacts:
    needs: test
    runs-on: ubuntu-latest
    name: Build release artifacts
```

Then change:

```yaml
  release:
    needs: build-escript
```

to:

```yaml
  release:
    needs: build-release-artifacts
```

- [ ] **Step 3: Add release-only Queso dependency setup**

After the existing `Setup environment` step, add:

```yaml
      - name: Install Queso packaging dependencies
        run: |
          set -euo pipefail
          sudo apt-get update
          sudo apt-get install -y musl-tools
          python3 -m pip install --user 'ziglang==0.14.1'
          cargo install --locked cargo-zigbuild --version 0.20.1
          rustup target add \
            aarch64-apple-darwin \
            aarch64-unknown-linux-gnu \
            aarch64-unknown-linux-musl \
            x86_64-apple-darwin \
            x86_64-pc-windows-gnu \
            x86_64-unknown-linux-musl
          mise exec -- queso --version
          python3 -m ziglang version
          cargo zigbuild --version
```

This installs cross-compilation tools only in the release packaging job, not in normal PR CI.

- [ ] **Step 4: Build Queso executables**

After the `Build escript` step, add:

```yaml
      - name: Build Queso executables
        run: just build-queso
```

This step must fail the job if any configured Queso target fails. Do not wrap it in `|| true`.

- [ ] **Step 5: Smoke-test the runner-native Queso executable**

After the Queso build step, add:

```yaml
      - name: Smoke test Queso executable
        env:
          REF_NAME: ${{ github.ref_name }}
        run: |
          set -euo pipefail
          version="${REF_NAME#v}"
          ./build/queso/licence_audit-${version}-x86_64-linux-static --help >/dev/null
```

This validates a self-contained Linux executable on the Ubuntu runner.

- [ ] **Step 6: Replace artifact staging script**

Replace the current `Stage release artifacts` shell body with this script:

```bash
set -euo pipefail
mkdir -p dist

version="${REF_NAME#v}"
escript_stage="licence_audit-${REF_NAME}"
mkdir -p "$escript_stage"
cp licence_audit "$escript_stage/"
[ -f LICENSE ] && cp LICENSE "$escript_stage/" || true
[ -f README.md ] && cp README.md "$escript_stage/" || true
tar -czf "dist/${escript_stage}.tar.gz" "$escript_stage"
(cd "$escript_stage" && zip -qr "../dist/${escript_stage}.zip" .)

# Ship the bare escript alongside the archives so it can be attested
# and downloaded directly.
cp licence_audit dist/

targets=(
  aarch64-linux-glibc
  aarch64-linux-musl
  aarch64-linux-static
  aarch64-macos
  x86_64-linux-glibc
  x86_64-linux-musl
  x86_64-linux-static
  x86_64-macos
  x86_64-windows
)

for target in "${targets[@]}"; do
  archive_stage="licence_audit-${REF_NAME}-${target}"
  mkdir -p "$archive_stage"

  source_path="build/queso/licence_audit-${version}-${target}"
  if [[ "$target" == *-windows ]]; then
    source_path="${source_path}.exe"
    test -f "$source_path"
    cp "$source_path" "$archive_stage/licence_audit.exe"
  else
    test -f "$source_path"
    cp "$source_path" "$archive_stage/licence_audit"
    chmod +x "$archive_stage/licence_audit"
  fi

  [ -f LICENSE ] && cp LICENSE "$archive_stage/" || true
  [ -f README.md ] && cp README.md "$archive_stage/" || true

  if [[ "$target" == *-windows ]]; then
    (cd "$archive_stage" && zip -qr "../dist/${archive_stage}.zip" .)
  else
    tar -czf "dist/${archive_stage}.tar.gz" "$archive_stage"
  fi
done

test -f "dist/licence_audit-${REF_NAME}.tar.gz"
test -f "dist/licence_audit-${REF_NAME}.zip"
test -f "dist/licence_audit-${REF_NAME}-x86_64-windows.zip"
test -f "dist/licence_audit-${REF_NAME}-x86_64-linux-static.tar.gz"
test ! -e "dist/licence_audit-${REF_NAME}-aarch64-windows.zip"

(cd dist && sha256sum licence_audit *.tar.gz *.zip *.cdx.json > checksums.txt)
ls -la dist
```

The full workflow step should still be:

```yaml
      - name: Stage release artifacts
        env:
          REF_NAME: ${{ github.ref_name }}
        run: |
          set -euo pipefail
          mkdir -p dist

          version="${REF_NAME#v}"
          escript_stage="licence_audit-${REF_NAME}"
          mkdir -p "$escript_stage"
          cp licence_audit "$escript_stage/"
          [ -f LICENSE ] && cp LICENSE "$escript_stage/" || true
          [ -f README.md ] && cp README.md "$escript_stage/" || true
          tar -czf "dist/${escript_stage}.tar.gz" "$escript_stage"
          (cd "$escript_stage" && zip -qr "../dist/${escript_stage}.zip" .)

          # Ship the bare escript alongside the archives so it can be attested
          # and downloaded directly.
          cp licence_audit dist/

          targets=(
            aarch64-linux-glibc
            aarch64-linux-musl
            aarch64-linux-static
            aarch64-macos
            x86_64-linux-glibc
            x86_64-linux-musl
            x86_64-linux-static
            x86_64-macos
            x86_64-windows
          )

          for target in "${targets[@]}"; do
            archive_stage="licence_audit-${REF_NAME}-${target}"
            mkdir -p "$archive_stage"

            source_path="build/queso/licence_audit-${version}-${target}"
            if [[ "$target" == *-windows ]]; then
              source_path="${source_path}.exe"
              test -f "$source_path"
              cp "$source_path" "$archive_stage/licence_audit.exe"
            else
              test -f "$source_path"
              cp "$source_path" "$archive_stage/licence_audit"
              chmod +x "$archive_stage/licence_audit"
            fi

            [ -f LICENSE ] && cp LICENSE "$archive_stage/" || true
            [ -f README.md ] && cp README.md "$archive_stage/" || true

            if [[ "$target" == *-windows ]]; then
              (cd "$archive_stage" && zip -qr "../dist/${archive_stage}.zip" .)
            else
              tar -czf "dist/${archive_stage}.tar.gz" "$archive_stage"
            fi
          done

          test -f "dist/licence_audit-${REF_NAME}.tar.gz"
          test -f "dist/licence_audit-${REF_NAME}.zip"
          test -f "dist/licence_audit-${REF_NAME}-x86_64-windows.zip"
          test -f "dist/licence_audit-${REF_NAME}-x86_64-linux-static.tar.gz"
          test ! -e "dist/licence_audit-${REF_NAME}-aarch64-windows.zip"

          (cd dist && sha256sum licence_audit *.tar.gz *.zip *.cdx.json > checksums.txt)
          ls -la dist
```

- [ ] **Step 7: Verify attestation coverage**

Confirm these existing subject globs remain in both attestation steps:

```yaml
            dist/*.tar.gz
            dist/*.zip
```

Those globs cover the new Queso archives. Keep `dist/licence_audit` for the bare escript and `dist/checksums.txt` for build provenance.

- [ ] **Step 8: Run workflow syntax checks**

Run:

```bash
grep -n 'build-release-artifacts' .github/workflows/publish.yml
grep -n 'Install Queso packaging dependencies' .github/workflows/publish.yml
grep -n 'Build Queso executables' .github/workflows/publish.yml
grep -n 'aarch64-windows' .github/workflows/publish.yml || true
```

Expected: the first three commands print matches; the final command prints no matches.

If `actionlint` is available locally, run:

```bash
actionlint .github/workflows/publish.yml
```

Expected: no errors. If `actionlint` is not installed, skip it; do not add it as a dependency.

- [ ] **Step 9: Commit**

```bash
git add .github/workflows/publish.yml
git commit -m "ci: package Queso release archives"
```

---

### Task 3: Update install and contributor documentation

**Files:**
- Modify: `README.md`
- Modify: `DEV.md`
- Modify: `.github/release-install.md.tmpl`
- Create: `.changes/unreleased/queso-executables.md`

**Interfaces:**
- Consumes: release archive names from Task 2.
- Produces: user and contributor docs that explain native Queso archives, escript fallback, mise behavior, and the `aarch64-windows` deferral.

- [ ] **Step 1: Write failing docs checks**

Run:

```bash
grep -n 'self-contained executable' README.md
grep -n 'just build-queso' DEV.md
grep -n 'x86_64-linux-static' .github/release-install.md.tmpl
test -f .changes/unreleased/queso-executables.md
```

Expected: these checks fail before documentation changes.

- [ ] **Step 2: Update `README.md` install section**

Replace lines 15-42 with:

```markdown
## Install

### From a GitHub Release

Prebuilt archives are attached to each
[release](https://github.com/tylerbutler/licence_audit/releases).

For most users, download the self-contained archive for your platform, extract
it, and put `licence_audit` on your `PATH`. These Queso-built executables bundle
the Erlang runtime, so Erlang/OTP does not need to be installed on the target
machine.

The release also keeps the original escript archive and bare `licence_audit`
escript for compatibility. The escript runs on any platform with Erlang/OTP 28.x
or newer. Older OTP releases cannot reattach stdin in raw mode, which breaks
keyboard input for `licence_audit update`.

Windows ARM64 (`aarch64-windows`) is not published yet because Queso requires an
explicit Windows ARM64 ERTS and there is no trustworthy pinned prebuilt OTP 28
archive for that target.

### With mise

If you use [mise](https://mise.jdx.dev/), install `licence_audit` with the
`github:` provider:

```sh
mise use -g "github:tylerbutler/licence_audit@latest[asset_pattern=licence_audit,bin=licence_audit]"
```

Replace `latest` with a release tag, such as `v0.6.0`, to pin a version. The
`asset_pattern=licence_audit` option selects the bare escript asset, avoiding
ambiguity with per-arch Queso archives. For a project-local install, omit `-g`.
This mise path uses the escript and still needs Erlang/OTP 28.x or newer on your `PATH`; if you manage Erlang with
mise, install it too:

```sh
mise use -g erlang@28
```

To build from source, see [DEV.md](./DEV.md).
```

- [ ] **Step 3: Update `DEV.md` build section**

Replace lines 20-28 with:

```markdown
## Build from source

```sh
just build
```

`just build` compiles the Gleam project and produces the escript at
`./licence_audit`.

To build self-contained native executables with Queso, install Queso's
package-time dependencies for your target and run:

```sh
just build-queso
```

Queso writes executables to `build/queso/`. The recipe is opt-in so normal local
builds and PR CI stay fast.
```

Then replace lines 120-125 with:

```markdown
Releases are produced by the `release.yml` and `publish.yml` GitHub Actions
workflows; do not edit `CHANGELOG.md` or bump the version in `gleam.toml` by
hand.

Releases include the existing escript artifacts plus self-contained Queso
archives for Linux, macOS, and Windows x86_64 targets. The `aarch64-windows`
target is deferred because Queso requires an explicit Windows ARM64 ERTS and
there is no trustworthy pinned prebuilt OTP 28 archive for that target.
```

- [ ] **Step 4: Update release install template**

Replace `.github/release-install.md.tmpl` with:

```markdown
<!-- install-instructions -->
## Installation

Download the self-contained archive for your platform, extract it, and place
`licence_audit` somewhere on your `PATH`. These Queso-built executables bundle
the Erlang runtime, so Erlang/OTP does not need to be installed on the target
machine.

Windows ARM64 (`aarch64-windows`) is not published yet because Queso requires an
explicit Windows ARM64 ERTS and there is no trustworthy pinned prebuilt OTP 28
archive for that target.

### Linux x86_64 static

```sh
curl -fsSL -o licence_audit.tar.gz \
  "https://github.com/${REPO}/releases/download/${REF_NAME}/licence_audit-${REF_NAME}-x86_64-linux-static.tar.gz"
tar -xzf licence_audit.tar.gz --strip-components=1
chmod +x licence_audit
./licence_audit --help
```

### Windows x86_64

```powershell
Invoke-WebRequest `
  -Uri "https://github.com/${REPO}/releases/download/${REF_NAME}/licence_audit-${REF_NAME}-x86_64-windows.zip" `
  -OutFile licence_audit.zip
Expand-Archive licence_audit.zip -DestinationPath .
.\licence_audit.exe --help
```

### Escript compatibility install

The release also keeps the original escript archive and bare `licence_audit`
escript. The escript runs on any platform with Erlang/OTP 28.x or newer.

```sh
curl -fsSL -o licence_audit-escript.tar.gz \
  "https://github.com/${REPO}/releases/download/${REF_NAME}/licence_audit-${REF_NAME}.tar.gz"
tar -xzf licence_audit-escript.tar.gz --strip-components=1
chmod +x licence_audit
./licence_audit --help
```

### With mise

If you use [mise](https://mise.jdx.dev/), install this release with the
`github:` provider:

```sh
mise use -g "github:${REPO}@${REF_NAME}"
```

For a project-local install, omit `-g`. The mise install path uses the escript
and still needs Erlang/OTP 28.x or newer on your `PATH`; if you manage Erlang
with mise, install it too:

```sh
mise use -g erlang@28
```

### Verify the download

```sh
# Checksums (run from the directory containing the artifacts)
sha256sum -c checksums.txt

# Build provenance + SBOM attestations for a native archive...
gh attestation verify licence_audit-${REF_NAME}-x86_64-linux-static.tar.gz --repo ${REPO}

# ...or for the bare escript binary
gh attestation verify licence_audit --repo ${REPO}
```
```

- [ ] **Step 5: Add Changie fragment**

Create `.changes/unreleased/queso-executables.md` with:

```markdown
kind: Added
body: Added self-contained Queso release archives for Linux, macOS, and Windows x86_64 targets while keeping the existing escript artifacts.
time: 2026-06-24T17:37:19.372-07:00
```

- [ ] **Step 6: Run docs checks**

Run:

```bash
grep -n 'self-contained archive' README.md
grep -n 'just build-queso' DEV.md
grep -n 'x86_64-linux-static' .github/release-install.md.tmpl
grep -n 'aarch64-windows' README.md DEV.md .github/release-install.md.tmpl
test -f .changes/unreleased/queso-executables.md
```

Expected: all commands succeed.

- [ ] **Step 7: Commit**

```bash
git add README.md DEV.md .github/release-install.md.tmpl .changes/unreleased/queso-executables.md
git commit -m "docs: document Queso release archives"
```

---

### Task 4: Validate the complete integration

**Files:**
- Read: `.mise.toml`
- Read: `gleam.toml`
- Read: `justfile`
- Read: `.github/workflows/publish.yml`
- Read: `README.md`
- Read: `DEV.md`
- Read: `.github/release-install.md.tmpl`
- Read: `.changes/unreleased/queso-executables.md`

**Interfaces:**
- Consumes: all changes from Tasks 1-3.
- Produces: final confidence that escript behavior is preserved, Queso packaging is wired into release CI, and docs match the artifact layout.

- [ ] **Step 1: Verify the branch and unrelated file state**

Run:

```bash
git branch --show-current
git --no-pager status --short
```

Expected: branch is `feature/queso-executables`. `AGENTS.md` may still appear as modified; do not stage or edit it.

- [ ] **Step 2: Run standard validation**

Run:

```bash
just format-check
just check
just build-strict
just test
./licence_audit --help >/dev/null
```

Expected: all commands succeed.

- [ ] **Step 3: Verify docs generation still matches**

Run:

```bash
just docs-check
```

Expected: command succeeds with no docs drift.

- [ ] **Step 4: Verify Queso tool availability**

Run:

```bash
mise exec -- queso --version
```

Expected: output contains `queso 0.3.0`.

- [ ] **Step 5: Run a host-only Queso smoke build if local prerequisites exist**

Run:

```bash
mise exec -- queso build --target x86_64-linux-static
./build/queso/licence_audit-0.6.0-x86_64-linux-static --help >/dev/null
```

Expected: both commands succeed on a Linux x86_64 machine with Rust and musl prerequisites installed.

If this fails only because Rust, `musl-tools`, Zig, or `cargo-zigbuild` is missing locally, record the missing prerequisite in the final handoff and rely on the release workflow setup from Task 2. Do not weaken the workflow.

- [ ] **Step 6: Verify release target list excludes Windows ARM64**

Run:

```bash
grep -n 'aarch64-windows' gleam.toml .github/workflows/publish.yml && exit 1 || true
grep -n 'aarch64-windows' README.md DEV.md .github/release-install.md.tmpl
```

Expected: no `aarch64-windows` match in `gleam.toml` or `publish.yml`; explanatory matches in docs.

- [ ] **Step 7: Verify release archive coverage**

Run:

```bash
grep -n 'dist/\\*.tar.gz' .github/workflows/publish.yml
grep -n 'dist/\\*.zip' .github/workflows/publish.yml
grep -n 'sha256sum licence_audit \\*.tar.gz \\*.zip \\*.cdx.json' .github/workflows/publish.yml
```

Expected: all commands print matches.

- [ ] **Step 8: Commit validation notes only if validation changed files**

Run:

```bash
git --no-pager status --short
```

Expected: no new tracked changes from validation. If `just docs-check` or another command changed tracked files, inspect them and commit only relevant generated updates:

```bash
git add README.md docs/check.md docs/sbom.md docs/update.md docs/vulns.md
git commit -m "chore: sync generated artifacts"
```

- [ ] **Step 9: Final review**

Run:

```bash
git --no-pager log --oneline --decorate -5
git --no-pager status --short
```

Expected: the recent commits are on `feature/queso-executables`. `AGENTS.md` may remain modified and unstaged because it pre-existed this work.
