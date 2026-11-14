---
name: setup-licence-audit
description: Use when setting up licence_audit in a Gleam project, adding local license or licence checks, checking dependencies for OSV vulnerabilities, or adding an optional CI licence and vulnerability gate. Also use for requests to configure an existing licence_audit policy or install the tool for a project.
---

# Set up licence_audit

Configure the user's Gleam project for local licence and vulnerability checks.
Add CI enforcement only when the user requests it. Preserve existing policy,
tool versions, comments, and unrelated files.

## 1. Inspect the target project

Read the project's instructions, `gleam.toml`, `manifest.toml`, tool version
files, task runner, and relevant CI files. Find the Gleam project directory;
it may be below the repository root. Run audit commands from that directory
so they use the correct manifest and configuration.

Confirm that the target has `gleam.toml` before running Gleam commands. Stop
and explain the mismatch if this is not a Gleam project; the tool does not
audit npm, Cargo, or other lockfile formats. If `manifest.toml` is missing,
use the project's existing dependency-download command (otherwise
`gleam deps download`). Do not upgrade dependencies as part of setup.

Use the [documentation](https://licence-audit.tylerbutler.com/docs/) and
[repository README](https://github.com/tylerbutler/licence_audit#readme) to
confirm current behavior. Consult `--help` and `check --help` through the
selected invocation below; an older installed release may lack newer flags.

## 2. Install a pinned CLI

Reuse a compatible project installation and pin. Otherwise, resolve a
published stable release
from [GitHub Releases](https://github.com/tylerbutler/licence_audit/releases)
and record its exact tag. Do not leave `latest` in committed configuration.
For example, `gh release view --repo tylerbutler/licence_audit --json tagName,assets`
shows the release and its assets. Check that the selected release supports the
required commands before using it.

### Gleam module for compatible projects

Prefer running the CLI as a Gleam module when the project has a compatible
Gleam compiler and Erlang/OTP, supports Git dependencies, and can compile its
source and dependencies for the Erlang target. This uses the project's
toolchain without a separate CLI installation. Do not change the project's
default target or upgrade its compiler, OTP, or unrelated dependencies to
make this work. For a JavaScript-only project, an incompatible dependency
graph, or an environment without the required build tools, use a standalone
release below.

Add `licence_audit` to the existing `[dev_dependencies]` table in `gleam.toml`.
Reuse an existing dependency instead of adding it to both dependency tables.
The package is not currently published on Hex; do not assume
`gleam add --dev licence_audit` will work. Use a Git dependency pinned to the
commit for the selected stable release. Resolve the tag through GitHub's Git
refs API, then follow an annotated tag's object until you reach its commit;
do not use a branch name or an annotated tag object's SHA as the commit pin.

For example, this pin is the commit for the published `v0.15.0` release.
Replace it with the verified commit for the selected version:

```toml
[dev_dependencies]
licence_audit = { git = "https://github.com/tylerbutler/licence_audit", ref = "b522f53cc67d2accc0c7931ff1358a6e8eff1085" }
```

Use the project's dependency-download command (otherwise `gleam deps download`)
and retain the resulting `manifest.toml` changes with the dependency pin.
Review new dependencies and any resolver conflicts; use a standalone release
if setup would require unrelated dependency upgrades. No application imports
or extra `[erlang]` settings are needed in the target project.

From the Gleam project directory, run:

```sh
gleam run --target erlang -m licence_audit -- --version
gleam run --target erlang -m licence_audit -- --help
gleam run --target erlang -m licence_audit -- check --help
```

The `--` separates Gleam options from CLI arguments. Use the explicit Erlang
target even if the project defaults to JavaScript; module execution requires
an Erlang-compatible project. This invokes the CLI entry point, not a
supported library API. Keep the dev dependency available when running audits.

### Standalone release

Preserve an existing standalone installation, or use one when module execution
is unsuitable or the user requests a separate executable. Prefer the project's
existing installation method:

- **mise:** add a project-local pin. The following example uses a published
  release; replace its tag with the selected version.

  ```sh
  mise use github:tylerbutler/licence_audit@v0.9.0
  mise exec -- licence_audit --version
  ```

  mise selects the self-contained archive for the host operating system, CPU
  architecture, and, on Linux, libc. It does not require Erlang/OTP.
- **Other setups:** use a self-contained archive for the host
  OS, CPU architecture, and, on Linux, libc. These archives bundle Erlang.
  Inspect the release asset list rather than guessing a filename or assuming
  every platform has a build. Verify the archive against the release's
  `checksums.txt`, then extract it to an appropriate user-local tool directory.
  Follow the project's existing executable/PATH convention. Keep downloaded
  binaries and archives out of git.

Do not introduce mise, just, or a global tool installation into a project that
does not use them. If a tool or release is unavailable, report the blocker;
do not claim an installation succeeded.

## 3. Configure the policy

Inspect `[tools.licence_audit]` in `gleam.toml`, or the project's existing
explicit `--config` file. Reuse that file and pass `--config` to policy-aware
commands if needed. Merge requested settings into the existing section
without replacing unrelated settings or creating a duplicate TOML table.

Preserve existing allow/deny decisions. If the user supplies a policy, apply
it. If no policy exists and the user has not chosen one, set up reports and
explain that licence enforcement still needs an approved policy. Do not
approve all discovered licences, copy this tool's own policy, or invent a
permissive allow list to obtain a successful check.

`licence_audit update` lets a person review discovered licences in an
interactive terminal. Offer it as a manual step when policy decisions remain.
Do not run it with non-interactive stdin or in CI. If the user supplied the
decisions, edit the configuration without invoking the picker.

Vulnerability gating defaults to `high` and does not block unknown severity.
Retain those defaults unless the project or user specifies otherwise. Store
requested overrides in the same policy section, for example:

```toml
[tools.licence_audit]
# Retain the project's approved allow/deny entries here.
vuln_severity = "medium"
vuln_block_unknown = true
```

This is an example of vulnerability settings, not a complete licence policy.
The settings do not enable OSV checks on their own; the command needs `--vulns`.

## 4. Add local commands

Use the column for the selected installation:

| Purpose | Gleam module | Standalone |
| --- | --- | --- |
| Licence report or policy preview | `gleam run --target erlang -m licence_audit` | `licence_audit` |
| Vulnerability report | `gleam run --target erlang -m licence_audit -- vulns` | `licence_audit vulns` |
| Enforce licence policy | `gleam run --target erlang -m licence_audit -- check` | `licence_audit check` |
| Enforce licences and vulnerability threshold | `gleam run --target erlang -m licence_audit -- check --vulns` | `licence_audit check --vulns` |

For the manual policy picker, use
`gleam run --target erlang -m licence_audit -- update` with a module setup,
or `licence_audit update` with a standalone setup. Put policy flags such as
`--config` after `--` in module commands.

Report commands do not fail because they find violations or vulnerabilities.
Use the combined `check --vulns` command for enforcement. It returns `1` for
gate failures and `2` for input, configuration, or network errors. Do not hide
these failures with `|| true` or equivalent settings.

Add distinct tasks such as `audit-licences`, `audit-vulns`, and `audit-check`
to the existing task runner, or document shell commands if there is none.
Reuse existing matching tasks and tool execution wrappers (such as
`mise exec --`); do not overwrite a generic `check` task. Keep local and CI
commands on the same policy and version. Do not add severity flags that
override the configured policy. Use `--prod-only` only when requested.

Licence auditing covers locked Hex packages. Vulnerability checks cover Hex
and GitHub dependencies; other sources are skipped and reported. Surface
skipped packages rather than claiming complete dependency coverage. Hex
metadata can be cached; OSV advisories require network access and are not
cached. An unavailable OSV service is an incomplete check, not a clean result.
Adding the tool as a dev dependency also adds it and its dependencies to the
lockfile being audited. Do not hide these packages or add `--prod-only` to
remove them unless the user requests production-only coverage.

## 5. Add CI only on request

For CI setup, read [references/ci.md](references/ci.md). Otherwise, leave CI
files unchanged. Do not add SBOM generation, notices, scheduled workflows,
or dependency upgrades unless requested.

## 6. Verify and hand off

Run the installed version command and the local report commands. Run the
combined gate when a licence policy exists, using the new task if one was
added. Review the diff for preserved policy, task names, and working
directories. A second setup pass should not add duplicate tables, tasks, or
CI jobs.

For CI, check the workflow syntax using the project's existing tools and
confirm that dependency preparation precedes enforcement. If network access,
installation, or policy decisions block a step, state what remains.

Summarize the changed files, selected invocation, pinned version (and source
commit for a Git dependency), local commands, and whether CI was added.
Distinguish successful setup from a clean audit: report gate
failures and incomplete checks without weakening the policy.
