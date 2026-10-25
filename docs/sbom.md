<a id="command-licence-audit-sbom"></a>

# `licence_audit sbom`

Generate a CycloneDX 1.6 or SPDX 2.3 JSON SBOM from manifest.toml. Does not evaluate licence policy.

**Usage:**

```
licence_audit sbom [--flags]
```

**Flags:**

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `--cache-path` | `STRING` |  | Override the licence metadata cache location |
| `--format` | `STRING` | `cyclonedx-json` | Output format: cyclonedx-json or spdx-json |
| `--manifest` | `STRING` |  | Read manifest from PATH |
| `--no-cache` | `BOOL` | `false` | Bypass the on-disk caches |
| `--offline` | `BOOL` | `false` | Skip Hex metadata fetch; leave Hex dependency licences unknown; with --reproducible, skip all dependency enrichment including Git |
| `--output` | `STRING` |  | Write SBOM to PATH instead of stdout |
| `--quiet` | `BOOL` | `false` | Suppress progress output |
| `--reproducible` | `BOOL` | `false` | Reproducible output from locked package archives (unless --offline): serialNumber is a content hash and timestamp comes from SOURCE_DATE_EPOCH (default 1970-01-01T00:00:00Z) |
| `--verbose` | `BOOL` | `false` | Show detailed progress output (alias: -v) |
| `--vulns` | `BOOL` | `false` | Query OSV.dev and embed a CycloneDX vulnerabilities array (requires network; conflicts with --offline and --reproducible) |
