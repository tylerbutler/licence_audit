# licence_audit

A CLI for the locked dependencies in a Gleam project. It reports Hex package
licences, previews or enforces a licence policy, creates CycloneDX SBOMs and
third-party notices, and checks for known vulnerabilities through OSV.dev.

## Install

Download a self-contained archive for your platform from the
[releases](https://github.com/tylerbutler/licence_audit/releases), extract it,
and put `licence_audit` on your `PATH`. These executables include the Erlang
runtime; you do not need to install Erlang/OTP. Prefer them for CI.

With [mise](https://mise.jdx.dev/):

```sh
mise use -g github:tylerbutler/licence_audit@latest
```

Replace `latest` with a release tag to select a fixed version. Omit `-g` for
a project-local install.

The release also provides escript archives and a bare escript. **The escript
requires Erlang/OTP 28 or newer for all commands.** Windows ARM64 archives
are not published.

On OTP 27, the VM can fail to load the escript with `corrupt atom table`
and exit `127`, before any command runs. This unsupported-runtime failure is
outside the [CLI exit-code contract](https://licence-audit.tylerbutler.com/docs/compatibility#exit-codes-and-output-streams).

For source builds, see [DEV.md](./DEV.md).

## Documentation

The [website](https://licence-audit.tylerbutler.com/docs) is the canonical user
documentation. It contains installation and setup guidance, generated CLI
usage and flag tables, and command behavior:

- [Quick start](https://licence-audit.tylerbutler.com/docs)
- [Licence policy and checks](https://licence-audit.tylerbutler.com/docs/check)
- [Create a policy](https://licence-audit.tylerbutler.com/docs/update)
- [SBOMs](https://licence-audit.tylerbutler.com/docs/sbom)
- [Third-party notices](https://licence-audit.tylerbutler.com/docs/notices)
- [Vulnerability reports](https://licence-audit.tylerbutler.com/docs/vulns)
- [Configuration discovery](https://licence-audit.tylerbutler.com/docs/configuration#discovery)
- [Compatibility policy](https://licence-audit.tylerbutler.com/docs/compatibility)

Use `licence_audit --help` or `licence_audit <command> --help` for the CLI
options in your installed version.

## Contributing and security

See [DEV.md](./DEV.md) for development commands and [SECURITY.md](./SECURITY.md)
for supported versions and private vulnerability reporting.
