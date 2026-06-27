---
name: changelog-fragment
description: >-
  Create a changie changelog fragment in `.changes/unreleased/` for this repository.
  Use this skill whenever you make a user-facing code change (a feature, fix, behavior
  change, removal, or security fix) and need to record it for the changelog, whenever the
  user asks to "add a changelog entry", "add a change fragment", "run just change", or
  mentions changie, and whenever you are preparing a PR — this repo's PR CI fails when a
  commit uses a conventional-commit type that needs an entry but no fragment is present.
  Reach for this skill even if the user only says "note this in the changelog" without
  naming changie or fragments.
---

# Changelog fragments (changie)

This repository tracks unreleased changes as individual **changie** fragments under
`.changes/unreleased/`. At release time `changie merge` rolls every fragment into
`CHANGELOG.md` and deletes them. Your job here is to add one correct fragment per
meaningful change so nothing is lost and the release notes read well.

The PR workflow (`.github/workflows/pr.yml`, `changie-check`) inspects commit types and
comments "Missing Changelog Entry" when a `feat:`/`fix:`/etc. commit lands without a
fragment. Adding the fragment as part of your change keeps CI green.

## What a fragment looks like

A fragment is a small YAML file with exactly three keys:

```yaml
kind: Added
body: Added `just ort-*` recipes that generate a reference CycloneDX SBOM to cross-check ours.
time: 2026-06-26T21:32:16.000-07:00
```

- **kind** — one of the kinds below; categorizes the entry and drives the auto version bump.
- **body** — a single line of prose that becomes one changelog bullet (`* {{body}}`).
- **time** — RFC 3339 timestamp; changie uses it to order entries within a release.

## How to create one

The interactive way is `just change` (which runs `mise exec -- changie new` and prompts
for kind and body). That prompt flow does not work well non-interactively, so when you are
making the change yourself, **write the file directly** in the format above — just match
changie's schema exactly.

1. **Pick a descriptive, kebab-case filename** ending in `.yaml`, named after the change
   topic — e.g. `sbom-git-package-enrichment.yaml`, `queso-executables.yaml`. This repo
   deliberately uses meaningful names rather than changie's default timestamp names,
   because they make the `unreleased/` directory readable at a glance and reduce merge
   conflicts. Do **not** use the `.md` extension — changie only reads `.yaml` fragments,
   so a `.md` file is silently ignored (the version file uses `.md` via `versionExt`, but
   that is a separate thing; fragments are always `.yaml`).

2. **Choose the kind** (see below).

3. **Write the body** (see style guidance below).

4. **Set the time** to now in RFC 3339 with a timezone offset. Generate it with:

   ```bash
   python3 -c "import datetime;print(datetime.datetime.now().astimezone().isoformat(timespec='milliseconds'))"
   ```

   This prints e.g. `2026-06-26T22:54:08.241-07:00`. The exact value is not load-bearing — it only orders entries — so any current,
   well-formed timestamp is fine.

5. **Verify** the fragment parses and renders by previewing the merged changelog:

   ```bash
   just changelog-preview
   ```

   Your new bullet should appear under the right heading with no error.

## Choosing the kind

The kinds map to Keep a Changelog sections and to an automatic semver bump:

| kind         | use for                                              | version bump |
| ------------ | ---------------------------------------------------- | ------------ |
| `Added`      | new features, recipes, commands, outputs             | minor        |
| `Changed`    | changes to existing behavior that aren't fixes       | minor        |
| `Deprecated` | features still present but discouraged               | minor        |
| `Removed`    | features, flags, or outputs taken away               | major        |
| `Fixed`      | bug fixes — wrong behavior corrected                 | patch        |
| `Security`   | vulnerability fixes or security-hardening changes    | patch        |

When a change spans categories (e.g. a fix that also adds a flag), prefer one fragment per
distinct, separately-describable change rather than cramming several ideas into one bullet.

## Writing the body

The body is read by users skimming release notes, so make it self-contained and concrete.

- Start with a past-tense verb that fits the kind: "Added…", "Fixed…", "Removed…",
  "SBOM generation no longer…". The leading verb need not literally repeat the kind word,
  but it should make the nature of the change obvious.
- Describe the user-visible effect and the "why" when it isn't obvious, not the
  implementation diff. Name the affected command, flag, recipe, or file so readers can
  find it — wrap code-ish things in backticks (`just change`, `--vulns`,
  `dist/sbom.json`).
- Keep it to one line of YAML. It can be a long sentence or two; just don't hard-wrap it
  into multiple YAML lines. If you need characters like `:` early in the string, quote the
  whole value so YAML stays valid.
- No trailing period is required, but matching the surrounding entries (most end without
  one mid-thought and with one for full sentences) keeps the changelog tidy.

**Example — a feature:**

```yaml
kind: Added
body: Added self-contained Queso release archives for Linux (glibc and musl), macOS, and Windows x86_64 targets while keeping the existing escript artifacts.
time: 2026-06-24T17:37:19.372-07:00
```

**Example — a fix that explains the why:**

```yaml
kind: Fixed
body: SBOM generation no longer silently drops package enrichment when a Hex metadata fetch fails; the cache now falls back to a stale entry and surfaces a warning with the underlying reason.
time: 2026-06-26T18:45:00.000-07:00
```

## When you do not need a fragment

Pure-internal changes with no user-visible effect generally don't need an entry: test-only
changes, refactors that preserve behavior, formatting, CI tweaks, or docs. If you're unsure
whether a change is user-facing, lean toward adding a fragment — a missing entry is the
failure mode CI is guarding against, and an extra small note is cheap to drop later.
