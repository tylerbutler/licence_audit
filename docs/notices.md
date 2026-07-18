# `licence_audit notices`

Generate a release-ready `THIRD_PARTY_NOTICES`-style file from locked dependencies. The output inventories each product, includes its applicable licence text, and preserves package-specific NOTICE attribution. Products with identical licence text are grouped so the shared text is emitted once. Each package's own source archive is used first; when it ships no licence text the command falls back to the declared repository (GitHub, Codeberg, or GitLab, at an immutable tag commit) and then to canonical SPDX License List text. A transient repository failure is non-fatal: it warns and continues to the SPDX fallback.

**Usage:**

```
licence_audit notices [--flags]
```

**Flags:**

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `--cache-path` | `STRING` | `__licence_audit_absent_string_flag__` | Override the licence metadata cache file location |
| `--include-dev` | `BOOL` | `false` | Include dev-only dependencies in the notice file |
| `--manifest` | `STRING` | `__licence_audit_absent_string_flag__` | Read manifest from PATH |
| `--no-cache` | `BOOL` | `false` | Bypass the on-disk licence metadata cache |
| `--output` | `STRING` | `__licence_audit_absent_string_flag__` | Write notices to PATH instead of stdout |
| `--quiet` | `BOOL` | `false` | Suppress progress output |
| `--verbose` | `BOOL` | `false` | Show detailed progress output (alias: -v) |
