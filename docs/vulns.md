<a id="command-licence-audit-vulns"></a>

# `licence_audit vulns`

Report known vulnerabilities for locked dependencies using the OSV.dev database. Does not evaluate licence policy. Includes dev dependencies unless --prod-only is set. Queries OSV directly and uses no on-disk cache.

**Usage:**

```
licence_audit vulns [--flags]
```

**Flags:**

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `--color` | `STRING` | `auto` | Colorize output: auto\|always\|never (default auto; alias: --colour) |
| `--config` | `STRING` |  | Read configuration from PATH |
| `--ignore-config` | `BOOL` | `false` | Ignore configuration files |
| `--manifest` | `STRING` |  | Read manifest from PATH |
| `--prod-only` | `BOOL` | `false` | Only scan production dependencies; exclude dev dependencies |
| `--quiet` | `BOOL` | `false` | Suppress progress output (alias: -q) |
| `--verbose` | `BOOL` | `false` | Show detailed progress output (alias: -v) |
