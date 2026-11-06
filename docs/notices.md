<a id="command-licence-audit-notices"></a>

# `licence_audit notices`

Generate a release-ready `THIRD_PARTY_NOTICES`-style file from locked dependencies. The output inventories each product, includes its applicable licence text, and preserves package-specific NOTICE attribution. Products with identical licence text are grouped so the shared text is emitted once. Each package's own source archive is used first; when it ships no licence text the command falls back to the declared repository (GitHub, Codeberg, or GitLab, at an immutable tag commit) and then to canonical SPDX License List text. A transient repository failure is non-fatal: it warns and continues to the SPDX fallback. Output stays plain in every color mode. Configuration reads only notices include/exclude settings; a missing notices section means no filters.

**Usage:**

```
licence_audit notices [--flags]
```

**Flags:**

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `--cache-path` | `STRING` |  | Override the licence metadata cache location |
| `--color` | `STRING` | `auto` | Colorize output: auto\|always\|never (default auto; alias: --colour) |
| `--config` | `STRING` |  | Read configuration from PATH |
| `--ignore-config` | `BOOL` | `false` | Ignore configuration files |
| `--include-dev` | `BOOL` | `false` | Include dev-only dependencies in the notice file |
| `--manifest` | `STRING` |  | Read manifest from PATH |
| `--no-cache` | `BOOL` | `false` | Bypass the on-disk caches |
| `--output` | `STRING` |  | Write notices to PATH instead of stdout |
| `--quiet` | `BOOL` | `false` | Suppress progress output (alias: -q) |
| `--verbose` | `BOOL` | `false` | Show detailed progress output (alias: -v) |
