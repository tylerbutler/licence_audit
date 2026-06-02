# `licence_audit check`

Report Hex package licence metadata and enforce the configured licence policy, exiting non-zero on violations.

**Usage:**

```
licence_audit check [--flags]
```

**Flags:**

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `--allow` | `STRING_LIST` | `` | Allow licences, comma-separated |
| `--cache-path` | `STRING` | `__licence_audit_absent_string_flag__` | Override the licence metadata cache file location |
| `--color` | `STRING` | `auto` | Colorize output: auto\|always\|never (default auto; alias: --colour) |
| `--config` | `STRING` | `__licence_audit_absent_string_flag__` | Read configuration from PATH |
| `--deny` | `STRING_LIST` | `` | Deny licences, comma-separated |
| `--ignore-config` | `BOOL` | `false` | Ignore configuration files |
| `--manifest` | `STRING` | `__licence_audit_absent_string_flag__` | Read manifest from PATH |
| `--no-cache` | `BOOL` | `false` | Bypass the on-disk licence metadata cache |
| `--prod-only` | `BOOL` | `false` | Only audit production dependencies; ignore dev-dependency violations |
| `--quiet` | `BOOL` | `false` | Suppress progress output |
| `--verbose` | `BOOL` | `false` | Show detailed progress output |
| `--vuln-severity` | `STRING` | `__licence_audit_absent_string_flag__` | Minimum severity that triggers `check --vulns` failure: low\|medium\|high\|critical (default high) |
| `--vulns` | `BOOL` | `false` | When used with `check`, also query OSV.dev and fail on vulnerabilities at or above --vuln-severity |
