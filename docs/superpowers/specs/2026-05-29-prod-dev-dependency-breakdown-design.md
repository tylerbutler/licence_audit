# Project B: Prod vs Dev dependency breakdown

**Date:** 2026-05-29
**Status:** Approved design, **blocked on [Project A](./2026-05-29-toml-tomlet-migration-design.md)**.
Implement A first; B is built on the `tomlet`-only foundation and the renamed
`licence_audit/toml` facade.

## Goal

Break down audited dependencies by **production** vs **development** scope and
surface that distinction across all four output surfaces: the licence report,
the SBOM, the `check` policy evaluation, and the `vulns` report.

## Signal source

The prod/dev split comes from the target project's `gleam.toml`:

- keys under `[dependencies]` → **prod** direct deps
- keys under `[dev-dependencies]` → **dev** direct deps

The lockfile (`manifest.toml`) remains the source of the resolved dependency
graph; it does **not** encode dev/prod. All `gleam.toml` reads go through the
`licence_audit/toml` facade (`get_table_keys`), per Project A.

## New type

In `manifest.gleam`:

```gleam
pub type Scope {
  Prod
  Dev
}
```

No `Unknown` variant. Per the fallback decision below, a missing or unreadable
`gleam.toml` makes every direct dep prod, so everything resolves to `Prod`.

## Classification: prod-wins reachability

1. Parse prod direct names from `gleam.toml`:
   `toml.get_table_keys(doc, ["dependencies"])`.
2. `dep_scopes(locked, prod_direct_names) -> Dict(String, Scope)`:
   multi-source BFS from the prod direct names over `locked.graph` (reusing the
   same BFS machinery as `dep_paths`). Every reachable node ⇒ `Prod`; every
   other node in the graph ⇒ `Dev`.

A package reachable via **both** a prod and a dev path is `Prod` ("prod wins" —
it reflects what actually ships). Example: `gleam_stdlib`, pulled by both prod
deps and `gleeunit`, is `Prod`.

### Fallback (gleam.toml missing/unreadable)

Callers pass `locked.direct_names` (all directs) as the prod seed ⇒ all nodes
reachable ⇒ everything `Prod`. `--prod-only` (below) becomes a no-op. This is
the safest behavior for "what ships": nothing is wrongly excluded.

## Surfaces

### 1. Report (`report.gleam`) — separate prod/dev sections

- Add `scope: Scope` to `Row`.
- Render the report as **two grouped sections**: a "Production dependencies"
  section followed by a "Development dependencies" section, each containing its
  own dependency tree/table. (Not an inline per-row tag.)
- Build sites in `licence_audit.gleam` look up each package's scope from the
  `dep_scopes` dict when constructing rows.
- A section with no members is omitted.

### 2. SBOM (`sbom_json.gleam`) — property only

- Tag each component with a custom property:
  `licence_audit:scope = "prod" | "dev"`.
- Do **not** set the CycloneDX `component.scope` (required/optional/excluded)
  field — property-only, to avoid overloading CycloneDX semantics.
- `sbom` now reads `gleam.toml` for the scope signal (it previously read only
  `manifest.toml`); apply the missing-`gleam.toml` fallback (all `prod`).

### 3. `check` — `--prod-only` flag

- New CLI flag `--prod-only` in `cli.gleam`, threaded into the check flow.
- Default behavior **unchanged**: audit every package, dev violations still
  affect the exit code.
- When `--prod-only` is set: drop `Dev`-scoped packages before policy
  evaluation so they do not affect the exit code or the failing-tree output.

### 4. `vulns` — scope labels

- Label each reported package with its scope in the `vulns` output.
- No filtering flag for `vulns` in this project (could add `--prod-only` later;
  out of scope now).

## Data flow

```
load gleam.toml
  → toml.get_table_keys(doc, ["dependencies"])   (or all-direct fallback)
  → dep_scopes(locked, prod_seed)                 : Dict(name → Scope)
  → threaded into report rows / sbom entries / check filter / vulns rows
```

## Testing (TDD)

- `manifest_test`:
  - `get_table_keys` for `[dependencies]` (prod-only, dev-only, both tables,
    missing tables, inline-table dependency values).
  - `dep_scopes`: direct-prod, direct-dev, transitive-via-prod,
    transitive-via-dev, **shared transitive reachable via both ⇒ Prod**, and
    the all-prod fallback (empty/all-direct seed).
- `report_test`: prod and dev sections render with the correct members; empty
  section omitted.
- `sbom_test`: prod and dev components carry `licence_audit:scope` with the
  right value; fallback yields all `prod`.
- Integration (`integration_test`): `check --prod-only` exits 0 when only a dev
  dependency violates policy, while the default run still fails; non-flagged
  behavior is unchanged.

## Open / deferred

- `vulns --prod-only` filtering — deferred.
- Surfacing scope in any machine-readable non-SBOM output — none today; n/a.
