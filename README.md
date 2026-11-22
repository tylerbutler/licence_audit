# licence_audit

When you ship a Gleam project, you also ship its dependencies, their licences,
and their known vulnerabilities. licence_audit is a CLI that tells you what
those are. It reads the locked dependencies in `manifest.toml`, reports the
Hex package licences, and can then enforce a licence policy in CI. From the
same lockfile, it also creates CycloneDX or SPDX SBOMs and third-party notices,
and it checks OSV.dev for known vulnerabilities.

The licence answers come from the archives that you actually lock, not from
the latest release on Hex. For each package, licence_audit downloads the locked
archive, verifies its SHA-256 against `manifest.toml`, and reads the declared
licences. A checksum always identifies the same archive, so its metadata never
changes. Thus only the first scan downloads the archives; later scans reuse the
cached metadata without expiry.

## Install

Download a self-contained archive for your platform from the
[releases](https://github.com/tylerbutler/licence_audit/releases), extract it,
and put `licence_audit` on your `PATH`. These executables include the Erlang
runtime; you do not need to install Erlang/OTP. Prefer them for CI.

With [mise](https://mise.jdx.dev/):

```sh
mise use -g github:tylerbutler/licence_audit@latest
```

To pin a version, replace `latest` with an exact release tag (`vX.Y.Z`).
Choose a tag from a [published release](https://github.com/tylerbutler/licence_audit/releases/latest).
Omit `-g` for a project-local install.

The release also provides escript archives and a bare escript. **The escript
requires Erlang/OTP 28 or newer for all commands.** Windows ARM64 archives
are not published.

On OTP 27, the VM can fail to load the escript with `corrupt atom table`
and exit `127`, before any command runs. This unsupported-runtime failure is
outside the [CLI exit-code contract](https://licence-audit.tylerbutler.com/docs/compatibility#exit-codes-and-output-streams).

Source builds require Gleam 1.19.2 or newer. See [DEV.md](./DEV.md).

## First run

Start with a report. Run `licence_audit` (or `licence_audit report`, which is
the same command) in a project that has a `manifest.toml`. The report shows
each locked licence and previews policy findings. Findings do not fail the
report, so you can run it at any time.

Next, decide which licences you accept. `licence_audit update` writes `allow`
and `deny` lists to `[tools.licence_audit]` in `gleam.toml`. When you need a
different policy, for example for a release, select it with
`--config=policies/release.toml`.

Then enforce the policy with `licence_audit check`. It runs the same scan as
the report, but it returns exit code `1` when a dependency violates the policy.
Add `--checks=all` to also fail on known vulnerabilities.

Reports, `check`, and `vulns` scan all dependencies by default. To scan only the
dependencies that you ship, add `--scope=prod`. `notices` is the exception: it
describes a release, so it starts with production dependencies and accepts
`--scope=all`. `sbom` always describes the full graph.

To write `sbom` or `notices` output to a file, use `-o PATH`. For the options
in your installed version, run `licence_audit --help` or
`licence_audit <command> --help`.

If your scripts use removed flags, read the migration notes for
[`--allow` and `--deny`](https://licence-audit.tylerbutler.com/docs/compatibility#migration-before-10)
or for [`--prod-only` and `--include-dev`](https://licence-audit.tylerbutler.com/docs/compatibility#pre-10-dependency-scope-migration).

## Documentation

The [website](https://licence-audit.tylerbutler.com/docs) is the canonical user
documentation. After your first run, the website explains each command in full, with flag tables that are generated from the CLI:

- [Quick start](https://licence-audit.tylerbutler.com/docs)
- [Licence reports](https://licence-audit.tylerbutler.com/docs/report)
- [GitHub Actions](https://licence-audit.tylerbutler.com/docs#optional-github-actions-usage)
- [Licence policy and checks](https://licence-audit.tylerbutler.com/docs/check)
- [Create a policy](https://licence-audit.tylerbutler.com/docs/update)
- [SBOMs](https://licence-audit.tylerbutler.com/docs/sbom)
- [Third-party notices](https://licence-audit.tylerbutler.com/docs/notices)
- [Vulnerability reports](https://licence-audit.tylerbutler.com/docs/vulns)
- [Configuration discovery](https://licence-audit.tylerbutler.com/docs/configuration#discovery)
- [Compatibility policy](https://licence-audit.tylerbutler.com/docs/compatibility)

## Contributing and security

See [DEV.md](./DEV.md) for development commands and [SECURITY.md](./SECURITY.md)
for supported versions and private vulnerability reporting.
