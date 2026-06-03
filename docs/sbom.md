# `licence_audit sbom`

Generate a CycloneDX 1.6 JSON SBOM from manifest.toml. Does not evaluate licence policy.

**Usage:**

```
licence_audit sbom [--flags]
```

**Flags:**

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `--cache-path` | `STRING` | `__licence_audit_absent_string_flag__` | Override the licence metadata cache file location |
| `--manifest` | `STRING` | `__licence_audit_absent_string_flag__` | Read manifest from PATH |
| `--no-cache` | `BOOL` | `false` | Bypass the on-disk licence metadata cache |
| `--offline` | `BOOL` | `false` | Skip Hex metadata fetch; omit license fields |
| `--output` | `STRING` | `__licence_audit_absent_string_flag__` | Write SBOM to PATH instead of stdout |
| `--quiet` | `BOOL` | `false` | Suppress progress output |
| `--reproducible` | `BOOL` | `false` | Deterministic output: serialNumber is a hash of the content and the timestamp comes from SOURCE_DATE_EPOCH (default 1970-01-01T00:00:00Z) |
| `--verbose` | `BOOL` | `false` | Show detailed progress output |
| `--vulns` | `BOOL` | `false` | Query OSV.dev and embed a CycloneDX vulnerabilities array (requires network; conflicts with --offline) |
