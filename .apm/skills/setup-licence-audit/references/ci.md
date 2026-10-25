# Optional CI enforcement

Configure CI only when requested. Use the existing provider and repository
conventions; do not add GitHub Actions alongside another provider by default.
Use the same CLI release, configuration file, project directory, and
vulnerability settings as the local setup.

Before adding a gate, establish the user's approved licence policy. If that
decision is pending, explain the blocker rather than calling a report an
enforced licence policy.

## GitHub Actions

Reuse the existing checkout, tool installation, and dependency-download
steps. If the pinned CLI is already installed by the project's mise setup,
call its task or `mise exec -- licence_audit check --vulns`; a second install
action is unnecessary.

Otherwise, use
[`tylerbutler/actions/setup-licence-audit`](https://github.com/tylerbutler/actions/tree/v1/setup-licence-audit).
Confirm the action's current `action.yml` inputs before editing:

| Input | Value |
| --- | --- |
| `version` | Required exact release tag, matching the local pin |
| `setup-beam` | Default `"true"`; use `"false"` only when OTP 28 or newer is already available |
| `otp-version` | Erlang version to install when `setup-beam` is `"true"` |

The action installs the escript, not a self-contained executable. Preserve a
project's older OTP requirement: use a separate audit job with OTP 28 or
newer, or install a self-contained release. Do not replace the runtime in an
existing test job.

These steps assume checkout, Gleam, OTP 28 or newer, and the locked
dependencies are already present. Replace the example release tag with the
selected local version. Match the repository's action pinning convention;
resolve and verify commit SHAs if it requires immutable action references.

```yaml
- name: Install licence_audit
  uses: tylerbutler/actions/setup-licence-audit@v1
  with:
    version: v0.9.0
    setup-beam: "false"

- name: Check licences and vulnerabilities
  run: licence_audit check --vulns
```

Prefer the existing local audit task over a duplicate command. For a nested
Gleam project, set `working-directory` on shell steps, or use a task that
changes to that directory. Carry an existing explicit `--config` path into
the policy-aware command.

If there is no workflow, create one for pull requests and pushes to the
repository's default branch, with `permissions: contents: read`. Include
checkout, the project's pinned Gleam/runtime setup, dependency download,
CLI installation, and the gate. Do not assume `.tool-versions` exists when
choosing a Gleam setup action. Do not add schedules or write permissions
without a requirement.

Do not use `licence_audit vulns` as a gate: it reports vulnerabilities but
does not fail because it finds them. Do not run interactive `update`, use
`continue-on-error`, suppress shell exit codes, or skip the gate when OSV
is unavailable. Keep policy settings in the configuration instead of
overriding them with CI-only flags.

## Other CI providers

Reuse their existing job and installation conventions. Prepare the committed
Gleam lockfile, install the same pinned CLI and any required runtime, and
run the local audit task with its exit status intact. Consult that provider's
documentation instead of translating GitHub-specific action inputs.
