---
name: changelog-fragment
description: >-
  Create a Trellis changelog fragment in `.changes/unreleased/` for this repository.
  Use for user-facing features, fixes, behavior changes, removals, and security fixes;
  when the user asks for a changelog entry or change fragment; and when preparing a PR.
---

# Trellis changelog fragments

Create the fragment with Trellis:

```sh
just change Fixed "Fix ..."
```

The package is optional because this workspace has one releasable package. Trellis writes
a TOML file with `package`, `kind`, and `body` under `.changes/unreleased/`.

Use one of these kinds:

| Kind | Use | Bump |
| --- | --- | --- |
| `Added` | New user-visible behavior | minor |
| `Changed` | Changed existing behavior | minor |
| `Deprecated` | Discouraged behavior that remains available | minor |
| `Removed` | Removed behavior | major |
| `Fixed` | Corrected behavior | patch |
| `Security` | Vulnerability fixes or hardening | patch |

Write a concrete, self-contained body that describes the user-visible effect. Name the
affected command, flag, or output and use backticks for code. Do not add fragments for
test-only changes, refactors with no behavior change, formatting, CI, or internal docs.

Verify the fragment and version plan:

```sh
mise exec -- trellis doctor
just changelog-preview
```
