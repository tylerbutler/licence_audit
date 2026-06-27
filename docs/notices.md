# `licence_audit notices`

Generate a release-ready third-party licence notices text file from locked dependencies.

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
