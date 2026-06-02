# `licence_audit update`

Interactively review discovered licences and write an updated [tools.licence_audit] policy to gleam.toml.

**Usage:**

```
licence_audit update [--flags]
```

**Flags:**

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `--cache-path` | `STRING` | `__licence_audit_absent_string_flag__` | Override the licence metadata cache file location |
| `--color` | `STRING` | `auto` | Colorize output: auto\|always\|never (default auto; alias: --colour) |
| `--config` | `STRING` | `__licence_audit_absent_string_flag__` | Read configuration from PATH |
| `--ignore-config` | `BOOL` | `false` | Ignore configuration files |
| `--manifest` | `STRING` | `__licence_audit_absent_string_flag__` | Read manifest from PATH |
| `--no-cache` | `BOOL` | `false` | Bypass the on-disk licence metadata cache |
| `--quiet` | `BOOL` | `false` | Suppress progress output |
| `--verbose` | `BOOL` | `false` | Show detailed progress output |
