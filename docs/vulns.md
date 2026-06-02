# `licence_audit vulns`

Report known vulnerabilities for locked dependencies using the OSV.dev database. Does not evaluate licence policy.

**Usage:**

```
licence_audit vulns [--flags]
```

**Flags:**

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `--color` | `STRING` | `auto` | Colorize output: auto\|always\|never (default auto; alias: --colour) |
| `--manifest` | `STRING` | `__licence_audit_absent_string_flag__` | Read manifest from PATH |
| `--no-cache` | `BOOL` | `false` | Bypass the on-disk licence metadata cache |
| `--quiet` | `BOOL` | `false` | Suppress progress output |
| `--verbose` | `BOOL` | `false` | Show detailed progress output |
