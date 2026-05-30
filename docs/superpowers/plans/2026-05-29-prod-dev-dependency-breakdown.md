# Prod vs Dev Dependency Breakdown Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Classify every audited dependency as production or development scope (prod-wins reachability) and surface that across the report, SBOM, `check`, and `vulns`.

**Architecture:** A `manifest.Scope` type plus a reachability classifier (`dep_scopes`/`sbom_scopes`) seeded from the prod direct deps parsed out of `gleam.toml`'s `[dependencies]` table (via the `licence_audit/toml` facade from Project A). The computed `Dict(String, Scope)` is threaded into report rows (rendered as separate prod/dev sections), SBOM components (a `licence_audit:scope` property), the `vulns` output (a scope label), and the `check` flow (a `--prod-only` filter).

**Tech Stack:** Gleam, `tomlet` (via `licence_audit/toml`), `gleam/json`, `glam`, `glint`, `gleeunit`.

**Spec:** `docs/superpowers/specs/2026-05-29-prod-dev-dependency-breakdown-design.md`

**Depends on:** Project A (`licence_audit/toml` facade with `parse` + `table_keys`). This plan assumes branch `refactor/toml-tomlet-migration` (or its successor) is the base.

**Key design facts (verified against the code):**
- Prod seed = keys of `gleam.toml` `[dependencies]`. We never parse the dev table; a direct dep not reachable from prod is Dev by definition. (The repo even spells it `[dev_dependencies]` — irrelevant to us.)
- Fallback when `gleam.toml` is missing/unreadable or has no `[dependencies]`: seed with **all** direct names ⇒ everything Prod. `--prod-only` then becomes a no-op.
- Report path uses `manifest.LockedPackages` (has `.graph`). SBOM and vulns paths use `manifest.SbomManifest` (entries + `root_requirements`). Both need a classifier.
- `project_root` is always `"."` in tests (no `--project-root` flag). The `--prod-only` integration test exploits that `gleam_stdlib ∈ [dependencies]` (prod) while `gleeunit ∉ [dependencies]` (dev) in the repo's own `gleam.toml`.

---

## File Structure

- `src/licence_audit/manifest.gleam` — **modify**: add `Scope`, `prod_direct_names`, `dep_scopes`, `sbom_scopes`, `scope_label`, and a private `scope_map` reusing the existing `bfs_loop`.
- `src/licence_audit/report.gleam` — **modify**: `Row` gains `scope`; `format` renders separate prod/dev sections.
- `src/licence_audit/sbom.gleam` — **modify**: `SbomInput` gains `scopes`; `build_component` emits a `properties` array with `licence_audit:scope`.
- `src/licence_audit.gleam` — **modify**: compute scopes from `gleam.toml`, thread into the audit/sbom/vulns flows, add `scope_for`/`compute_scopes`/`resolve_prod_seed` helpers, apply `--prod-only` filtering, label vulns rows.
- `src/licence_audit/cli.gleam` — **modify**: `Options` gains `prod_only`; add `--prod-only` flag to the default and `check` commands.
- Tests: `manifest_test.gleam`, `report_test.gleam`, `sbom_test.gleam`, `integration_test.gleam`; new fixture `test/fixtures/prod_dev_manifest.toml`.

---

## Task 1: Scope classification core in `manifest.gleam`

**Files:**
- Modify: `src/licence_audit/manifest.gleam`
- Test: `test/licence_audit/manifest_test.gleam`

- [ ] **Step 1: Baseline**

Run: `gleam test`
Expected: PASS.

- [ ] **Step 2: Write failing tests**

Append to `test/licence_audit/manifest_test.gleam`:

```gleam
const scope_fixture = "packages = [
  { name = \"app_a\", version = \"1.0.0\", source = \"hex\", requirements = [\"lib_b\"] },
  { name = \"lib_b\", version = \"2.0.0\", source = \"hex\", requirements = [\"shared\"] },
  { name = \"test_helper\", version = \"1.0.0\", source = \"hex\", requirements = [\"shared\"] },
  { name = \"shared\", version = \"3.0.0\", source = \"hex\", requirements = [] },
]

[requirements]
app_a = { version = \">= 1.0.0\" }
test_helper = { version = \">= 1.0.0\" }
"

pub fn prod_direct_names_reads_dependencies_table_test() {
  let input =
    "[dependencies]\napp_a = \">= 1.0.0\"\n\n[dev_dependencies]\ntest_helper = \">= 1.0.0\"\n"
  should.equal(manifest.prod_direct_names(input), Ok(["app_a"]))
}

pub fn prod_direct_names_missing_table_is_error_test() {
  should.equal(manifest.prod_direct_names("name = \"x\"\n"), Error(Nil))
}

pub fn prod_direct_names_malformed_is_error_test() {
  should.equal(manifest.prod_direct_names("packages = ["), Error(Nil))
}

pub fn dep_scopes_classifies_prod_wins_test() {
  let assert Ok(locked) = manifest.parse(scope_fixture)
  let scopes = manifest.dep_scopes(locked, ["app_a"])

  should.equal(dict.get(scopes, "app_a"), Ok(manifest.Prod))
  should.equal(dict.get(scopes, "lib_b"), Ok(manifest.Prod))
  // reachable via app_a -> lib_b -> shared AND via test_helper: prod wins.
  should.equal(dict.get(scopes, "shared"), Ok(manifest.Prod))
  // reachable only from the dev direct dep.
  should.equal(dict.get(scopes, "test_helper"), Ok(manifest.Dev))
}

pub fn dep_scopes_all_prod_fallback_test() {
  let assert Ok(locked) = manifest.parse(scope_fixture)
  let scopes = manifest.dep_scopes(locked, locked.direct_names)

  should.equal(dict.get(scopes, "app_a"), Ok(manifest.Prod))
  should.equal(dict.get(scopes, "test_helper"), Ok(manifest.Prod))
  should.equal(dict.get(scopes, "shared"), Ok(manifest.Prod))
}

pub fn scope_label_test() {
  should.equal(manifest.scope_label(manifest.Prod), "prod")
  should.equal(manifest.scope_label(manifest.Dev), "dev")
}
```

(`manifest_test.gleam` already imports `gleam/dict` and `gleeunit/should`.)

- [ ] **Step 3: Run tests to verify they fail**

Run: `gleam test`
Expected: FAIL — `manifest.Scope`, `manifest.prod_direct_names`, etc. unknown.

- [ ] **Step 4: Implement the classifier**

In `src/licence_audit/manifest.gleam`, add the `Scope` type just after the `Kind` type:

```gleam
/// Whether a package is part of the production dependency tree (`Prod`) or only
/// reachable through development dependencies (`Dev`). Prod wins: a package
/// reachable from any production direct dependency is `Prod`.
pub type Scope {
  Prod
  Dev
}
```

Add these public functions (place them after `dep_paths`, before the private BFS helpers so `bfs_loop` is in scope):

```gleam
/// Parse the names of direct production dependencies from `gleam.toml` source:
/// the keys of the `[dependencies]` table. `Error(Nil)` when the TOML cannot be
/// parsed or has no `[dependencies]` table — callers treat that as "cannot
/// determine" and fall back to classifying everything as production.
pub fn prod_direct_names(gleam_toml: String) -> Result(List(String), Nil) {
  case toml.parse(gleam_toml) {
    Error(_) -> Error(Nil)
    Ok(document) -> toml.table_keys(document, ["dependencies"])
  }
}

/// Classify every package in the locked graph as `Prod` or `Dev`, seeded from
/// the production direct dependency names.
pub fn dep_scopes(
  locked: LockedPackages,
  prod_direct_names: List(String),
) -> Dict(String, Scope) {
  scope_map(graph_pairs(locked.graph), prod_direct_names)
}

/// Classify every entry in an SBOM manifest graph (used by `sbom` and `vulns`).
pub fn sbom_scopes(
  manifest: SbomManifest,
  prod_direct_names: List(String),
) -> Dict(String, Scope) {
  let pairs =
    list.map(manifest.entries, fn(entry) { #(entry.name, entry.requirements) })
  scope_map(pairs, prod_direct_names)
}

/// String label for a scope, used in SBOM properties and CLI output.
pub fn scope_label(scope: Scope) -> String {
  case scope {
    Prod -> "prod"
    Dev -> "dev"
  }
}

fn graph_pairs(graph: List(GraphNode)) -> List(#(String, List(String))) {
  list.map(graph, fn(node) { #(node.name, node.requirements) })
}

/// Multi-source BFS over `pairs` from the production sources; every reachable
/// node is `Prod`, every other node is `Dev`.
fn scope_map(
  pairs: List(#(String, List(String))),
  prod_direct_names: List(String),
) -> Dict(String, Scope) {
  let edges =
    list.fold(pairs, dict.new(), fn(acc, pair) {
      dict.insert(acc, pair.0, pair.1)
    })
  let nodes =
    list.fold(pairs, dict.new(), fn(acc, pair) { dict.insert(acc, pair.0, Nil) })
  let sources =
    list.filter(prod_direct_names, fn(name) { dict.has_key(nodes, name) })
  let visited =
    list.fold(sources, dict.new(), fn(acc, name) { dict.insert(acc, name, Nil) })
  let #(prod_set, _parents) = bfs_loop(sources, edges, visited, dict.new())
  list.fold(pairs, dict.new(), fn(acc, pair) {
    let scope = case dict.has_key(prod_set, pair.0) {
      True -> Prod
      False -> Dev
    }
    dict.insert(acc, pair.0, scope)
  })
}
```

Note: `manifest.gleam` already imports `licence_audit/toml`, `gleam/dict`, and `gleam/list` from Project A, and `bfs_loop` already exists with signature `bfs_loop(frontier, edges, visited, parents) -> #(visited, parents)`.

- [ ] **Step 5: Run tests to verify they pass**

Run: `gleam test`
Expected: PASS (existing + 6 new).

- [ ] **Step 6: Lint and commit**

```bash
gleam format && gleam check
git add src/licence_audit/manifest.gleam test/licence_audit/manifest_test.gleam
git commit -m "feat: classify dependencies by prod/dev scope in manifest"
```

---

## Task 2: Render separate prod/dev sections in the report

**Files:**
- Modify: `src/licence_audit/report.gleam`
- Modify: `src/licence_audit.gleam` (thread scopes into row construction)
- Test: `test/licence_audit/report_test.gleam`

### 2a — `report.gleam`: add `scope` to `Row` and section rendering

- [ ] **Step 1: Add `scope` to `Row`**

In `src/licence_audit/report.gleam`, change the `Row` type:

```gleam
pub type Row {
  Row(
    package: String,
    version: String,
    licences: List(String),
    status: Status,
    kind: manifest.Kind,
    scope: manifest.Scope,
    path: List(String),
  )
}
```

- [ ] **Step 2: Rewrite `format` to partition into sections**

Replace the existing `format` function with:

```gleam
pub fn format(
  rows: List(Row),
  summary: Summary,
  mode: Mode,
  palette: color.Palette,
) -> String {
  let widths = widths(rows)
  let #(prod_rows, dev_rows) =
    list.partition(rows, fn(r) { r.scope == manifest.Prod })
  let sections =
    [#("Production dependencies", prod_rows), #("Development dependencies", dev_rows)]
    |> list.filter(fn(section) { section.1 != [] })
    |> list.map(fn(section) {
      section_doc(section.0, section.1, widths, mode, palette)
    })
  let summary_line =
    doc.from_string(
      "Skipped non-Hex packages: " <> int.to_string(summary.skipped_non_hex),
    )

  doc.concat([
    header(widths, mode),
    doc.line,
    doc.join(sections, with: doc.line),
    doc.line,
    summary_line,
    doc.line,
  ])
  |> doc.to_string(glam_line_width)
}

fn section_doc(
  title: String,
  rows: List(Row),
  widths: Widths,
  mode: Mode,
  palette: color.Palette,
) -> Document {
  let tree = build_tree(rows)
  let body = tree_text(tree, widths, mode, palette)
  doc.concat([doc.from_string(title), doc.line, body])
}
```

`widths`, `header`, `build_tree`, `tree_text`, and `row_text` are unchanged: widths are computed over all rows so the two sections stay column-aligned. `list.partition` and `manifest` are already imported in `report.gleam`.

- [ ] **Step 3: Add `scope` to every `Row` in `report_test.gleam`**

There are 12 `report.Row(` literals. Add `scope: manifest.Prod,` after each `kind:` line. Run this to find them:

Run: `rg -n 'kind: manifest\.' test/licence_audit/report_test.gleam`

For each, insert the scope field. Example (the first one) becomes:

```gleam
report.Row(
  package: "gleam_stdlib",
  version: "1.0.0",
  licences: ["MIT"],
  status: report.Checked(policy.Allowed),
  kind: manifest.Direct,
  scope: manifest.Prod,
  path: [],
),
```

- [ ] **Step 4: Add a section-rendering test**

Append to `test/licence_audit/report_test.gleam`:

```gleam
pub fn report_groups_prod_and_dev_sections_test() {
  let output =
    report.format(
      [
        report.Row(
          package: "prod_pkg",
          version: "1.0.0",
          licences: ["MIT"],
          status: report.NotChecked,
          kind: manifest.Direct,
          scope: manifest.Prod,
          path: [],
        ),
        report.Row(
          package: "dev_pkg",
          version: "2.0.0",
          licences: ["MIT"],
          status: report.NotChecked,
          kind: manifest.Direct,
          scope: manifest.Dev,
          path: [],
        ),
      ],
      report.Summary(skipped_non_hex: 0),
      report.Default,
      off,
    )

  assert string.contains(output, "Production dependencies")
  assert string.contains(output, "Development dependencies")
  assert string.contains(output, "prod_pkg")
  assert string.contains(output, "dev_pkg")
}

pub fn report_omits_empty_dev_section_test() {
  let output =
    report.format(
      [
        report.Row(
          package: "prod_pkg",
          version: "1.0.0",
          licences: ["MIT"],
          status: report.NotChecked,
          kind: manifest.Direct,
          scope: manifest.Prod,
          path: [],
        ),
      ],
      report.Summary(skipped_non_hex: 0),
      report.Default,
      off,
    )

  assert string.contains(output, "Production dependencies")
  assert !string.contains(output, "Development dependencies")
}
```

- [ ] **Step 5: Verify `report.gleam` + tests compile/fail appropriately**

Run: `gleam build`
Expected: FAIL — `src/licence_audit.gleam` still constructs `report.Row` without `scope`. That is fixed in 2b. (The compile error confirms every construction site is accounted for.)

### 2b — `licence_audit.gleam`: compute and thread scopes

- [ ] **Step 6: Add scope helpers**

In `src/licence_audit.gleam`, add these helpers (near `load_policy`):

```gleam
fn compute_scopes(
  project_root: String,
  locked: manifest.LockedPackages,
) -> dict.Dict(String, manifest.Scope) {
  manifest.dep_scopes(locked, resolve_prod_seed(project_root, locked.direct_names))
}

/// Production direct dependency names from `<project_root>/gleam.toml`, or
/// `all_direct` (so everything classifies as prod) when it is missing,
/// unreadable, or has no `[dependencies]` table.
fn resolve_prod_seed(
  project_root: String,
  all_direct: List(String),
) -> List(String) {
  case simplifile.read(from: project_root <> "/gleam.toml") {
    Ok(contents) ->
      case manifest.prod_direct_names(contents) {
        Ok(names) -> names
        Error(_) -> all_direct
      }
    Error(_) -> all_direct
  }
}

fn scope_for(
  scopes: dict.Dict(String, manifest.Scope),
  name: String,
) -> manifest.Scope {
  case dict.get(scopes, name) {
    Ok(scope) -> scope
    Error(_) -> manifest.Prod
  }
}
```

- [ ] **Step 7: Return scopes from `prepare_audit`**

Change `prepare_audit`'s return type and final `Ok`:

```gleam
fn prepare_audit(
  options: cli.Options,
  manifest_path: String,
  project_root: String,
  reporter: progress.Reporter,
) -> Result(
  #(
    config.Policy,
    policy.Policy,
    manifest.LockedPackages,
    dict.Dict(String, manifest.Scope),
    progress.Reporter,
  ),
  #(RunResult, progress.Reporter),
) {
```

and replace the final line `Ok(#(config_policy, audit_policy, locked, reporter))` with:

```gleam
  let scopes = compute_scopes(project_root, locked)
  Ok(#(config_policy, audit_policy, locked, scopes, reporter))
```

- [ ] **Step 8: Destructure scopes in `run_options_with_clients`**

Replace the `Ok(#(...)) ->` arm:

```gleam
    Ok(#(config_policy, audit_policy, locked, scopes, reporter)) ->
      audit_locked(
        options,
        config_policy,
        audit_policy,
        locked,
        scopes,
        fetcher,
        osv_batch_fetcher,
        osv_detail_fetcher,
        reporter,
        palette,
      )
```

- [ ] **Step 9: Add the `scopes` parameter to `audit_locked`**

Change the signature to insert `scopes` after `locked`:

```gleam
fn audit_locked(
  options: cli.Options,
  config_policy: config.Policy,
  audit_policy: policy.Policy,
  locked: manifest.LockedPackages,
  scopes: dict.Dict(String, manifest.Scope),
  fetcher: fn(String) -> Result(hex.PackageMetadata, hex.Error),
  osv_batch_fetcher: fn(List(String)) -> Result(List(osv.BatchEntry), osv.Error),
  osv_detail_fetcher: fn(String) -> Result(osv.Vulnerability, osv.Error),
  reporter: progress.Reporter,
  palette: color.Palette,
) -> #(RunResult, progress.Reporter) {
```

Then thread `scopes` into the two row-building calls. Replace the `fetch_packages(...)` call's argument list to pass `scopes` (insert after `dep_paths`):

```gleam
  let result =
    fetch_packages(
      locked.packages,
      cached_fetcher,
      audit_policy,
      evaluate_policy,
      dep_paths,
      scopes,
      reporter,
      [],
      False,
      False,
    )
```

and the skipped-rows call:

```gleam
  let skipped_rows = build_skipped_rows(locked.skipped_packages, dep_paths, scopes)
```

- [ ] **Step 10: Add `scopes` to `fetch_packages` and set `Row.scope`**

Add the `scopes` parameter to `fetch_packages` (insert after `paths`):

```gleam
  paths: dict.Dict(String, List(String)),
  scopes: dict.Dict(String, manifest.Scope),
  reporter: progress.Reporter,
```

Thread `scopes` unchanged through both recursive `fetch_packages(...)` calls (insert `scopes,` after the `paths`/`reporter` argument — match the new parameter position). In the two `report.Row(` literals, add `scope: scope_for(scopes, package.name),` after the `kind:` line. The error-path row:

```gleam
              report.Row(
                package: package.name,
                version: package.version,
                licences: [],
                status: report.Failed(message),
                kind: package.kind,
                scope: scope_for(scopes, package.name),
                path: path,
              ),
```

and the success-path row identically (with its `licences`/`status`).

- [ ] **Step 11: Add `scopes` to `build_skipped_rows` and set `Row.scope`**

```gleam
fn build_skipped_rows(
  skipped: List(manifest.SkippedPackage),
  paths: dict.Dict(String, List(String)),
  scopes: dict.Dict(String, manifest.Scope),
) -> List(report.Row) {
  list.map(skipped, fn(pkg) {
    let path = case dict.get(paths, pkg.name) {
      Ok(p) -> p
      Error(_) -> [pkg.name]
    }
    report.Row(
      package: pkg.name,
      version: pkg.version,
      licences: [],
      status: report.Skipped(pkg.source),
      kind: pkg.kind,
      scope: scope_for(scopes, pkg.name),
      path: path,
    )
  })
}
```

- [ ] **Step 12: Build, test, lint**

Run: `gleam test`
Expected: PASS — report_test (incl. the 2 new section tests) and all integration tests green. Integration tests assert with `string.contains`, so the added section headers do not break them.

Run: `gleam format && gleam check`
Expected: clean.

- [ ] **Step 13: Commit**

```bash
git add src/licence_audit/report.gleam src/licence_audit.gleam test/licence_audit/report_test.gleam
git commit -m "feat: group report into prod and dev dependency sections"
```

---

## Task 3: Tag SBOM components with a scope property

**Files:**
- Modify: `src/licence_audit/sbom.gleam`
- Modify: `src/licence_audit.gleam` (`run_sbom_options`)
- Test: `test/licence_audit/sbom_test.gleam`

- [ ] **Step 1: Baseline**

Run: `gleam test`
Expected: PASS.

- [ ] **Step 2: Add `scopes` to `SbomInput`**

In `src/licence_audit/sbom.gleam`, add a field to `SbomInput` (after `license_metadata`):

```gleam
pub type SbomInput {
  SbomInput(
    manifest: manifest.SbomManifest,
    root: RootComponent,
    tool_version: String,
    serial_number: String,
    timestamp: String,
    license_metadata: Dict(String, List(String)),
    scopes: Dict(String, manifest.Scope),
  )
}
```

- [ ] **Step 3: Pass scopes into `build_component` and emit the property**

In `try_render`, pass scopes to `build_component`:

```gleam
  use components <- result.try(
    list.try_map(input.manifest.entries, fn(entry) {
      build_component(entry, input.license_metadata, input.scopes)
    }),
  )
```

Change `build_component` to take `scopes` and append a `properties` field. Replace the final `Ok(json.object(final_fields))` with the property-appending version:

```gleam
fn build_component(
  entry: manifest.SbomEntry,
  license_metadata: Dict(String, List(String)),
  scopes: Dict(String, manifest.Scope),
) -> Result(json.Json, error.Error) {
```

```gleam
  let scope = case dict.get(scopes, entry.name) {
    Ok(scope) -> scope
    Error(_) -> manifest.Prod
  }
  let with_properties =
    list.append(final_fields, [
      #(
        "properties",
        json.preprocessed_array([
          json.object([
            #("name", json.string("licence_audit:scope")),
            #("value", json.string(manifest.scope_label(scope))),
          ]),
        ]),
      ),
    ])
  Ok(json.object(with_properties))
```

(`final_fields` is the existing local that currently feeds `json.object`. `manifest`, `dict`, `json`, `list` are already imported.)

- [ ] **Step 4: Update `sbom_test.gleam` constructions and add a property assertion**

Add `scopes: dict.new()` to the `minimal_input()` helper's `SbomInput(...)` literal and any other full `SbomInput(...)` literal (sites at lines ~197 and ~221; the `..minimal_input()` spread at ~182 inherits it). `gleam/dict` is already imported.

Then append a test asserting the property renders. Find a test that builds a hex component (e.g. `render_emits_hex_component_with_hash_and_license_test`) and add a sibling:

```gleam
pub fn render_emits_scope_property_test() {
  let input =
    sbom.SbomInput(
      ..minimal_input(),
      scopes: dict.from_list([#("birch", manifest.Dev)]),
    )
  let output = sbom.render(input)

  assert string.contains(output, "licence_audit:scope")
  assert string.contains(output, "\"value\":\"dev\"")
}
```

(`minimal_input()`'s SBOM entry is named `"birch"`, so the dict is keyed on `"birch"`.)

- [ ] **Step 5: Wire `run_sbom_options`**

In `src/licence_audit.gleam`, in `run_sbom_options`, compute scopes from the SBOM manifest and add them to `SbomInput`. After `let root = read_root_component(project_root)`:

```gleam
      let scopes =
        manifest.sbom_scopes(
          sbom_manifest,
          resolve_prod_seed(project_root, sbom_manifest.root_requirements),
        )
      let input =
        sbom.SbomInput(
          manifest: sbom_manifest,
          root: root,
          tool_version: tool_version(),
          serial_number: sbom_uuid.serial_number(),
          timestamp: sbom_uuid.timestamp_now(),
          license_metadata: license_metadata,
          scopes: scopes,
        )
```

- [ ] **Step 6: Test, lint, commit**

Run: `gleam test && gleam format && gleam check`
Expected: PASS, clean.

```bash
git add src/licence_audit/sbom.gleam src/licence_audit.gleam test/licence_audit/sbom_test.gleam
git commit -m "feat: tag SBOM components with licence_audit:scope property"
```

---

## Task 4: Label scope in the `vulns` report

**Files:**
- Modify: `src/licence_audit.gleam`
- Test: `test/licence_audit/integration_test.gleam`

- [ ] **Step 1: Write a failing integration test**

Append to `test/licence_audit/integration_test.gleam`. This drives the `vulns` command with fake OSV clients; `gleam_stdlib` is a prod dep in the repo's `gleam.toml`, so it is labelled `[prod]`.

```gleam
fn one_vuln_batch(
  purls: List(String),
) -> Result(List(osv.BatchEntry), osv.Error) {
  Ok(
    list.map(purls, fn(purl) {
      osv.BatchEntry(purl: purl, vuln_ids: ["CVE-2024-0001"])
    }),
  )
}

fn one_vuln_detail(_id: String) -> Result(osv.Vulnerability, osv.Error) {
  Ok(osv.Vulnerability(
    id: "CVE-2024-0001",
    summary: "example",
    severity: osv.High,
  ))
}

pub fn vulns_report_labels_scope_test() {
  let licence_audit.RunResult(exit_code, output) =
    licence_audit.run_with_clients(
      ["vulns", "--manifest=test/fixtures/manifest.toml"],
      fake_fetcher,
      one_vuln_batch,
      one_vuln_detail,
    )

  should.equal(exit_code, 0)
  assert string.contains(output, "gleam_stdlib")
  assert string.contains(output, "[prod]")
}
```

Constructors (verified): `osv.BatchEntry(purl: String, vuln_ids: List(String))` and `osv.Vulnerability(id: String, summary: String, severity: osv.Severity)`. `merge_entries_with_packages` reads only `vuln_ids`, but `purl` is required by the constructor. `import licence_audit/osv` is already present in the test file.

- [ ] **Step 2: Run to verify it fails**

Run: `gleam test`
Expected: FAIL — output contains no `[prod]` label yet.

- [ ] **Step 3: Compute scopes in `run_vulns_options` and thread them through**

In `run_vulns_options`, after `Ok(sbom_manifest) -> {`, compute scopes (project_root is already in scope):

```gleam
      let scopes =
        manifest.sbom_scopes(
          sbom_manifest,
          resolve_prod_seed(project_root, sbom_manifest.root_requirements),
        )
```

Pass `scopes` to the empty-purls `format_vulns_output` call and to `query_and_report_vulns`:

```gleam
        [] -> {
          let output = format_vulns_output([], purl_errors, scopes, palette)
          #(RunResult(0, output), reporter)
        }
        _ ->
          query_and_report_vulns(
            purls,
            purl_pairs,
            purl_errors,
            scopes,
            batch_fetcher,
            detail_fetcher,
            reporter,
            palette,
          )
```

- [ ] **Step 4: Thread `scopes` through `query_and_report_vulns` and `format_vulns_output`**

Add a `scopes` parameter to `query_and_report_vulns` (after `purl_errors`) and pass it to its `format_vulns_output` call:

```gleam
fn query_and_report_vulns(
  purls: List(String),
  purl_pairs: List(PurlPair),
  purl_errors: List(String),
  scopes: dict.Dict(String, manifest.Scope),
  batch_fetcher: fn(List(String)) -> Result(List(osv.BatchEntry), osv.Error),
  detail_fetcher: fn(String) -> Result(osv.Vulnerability, osv.Error),
  reporter: progress.Reporter,
  palette: color.Palette,
) -> #(RunResult, progress.Reporter) {
```

```gleam
      let output = format_vulns_output(rows, purl_errors, scopes, palette)
```

Add `scopes` to `format_vulns_output` (after `unsupported_packages`) and pass it into the per-row map:

```gleam
fn format_vulns_output(
  rows: List(VulnRow),
  unsupported_packages: List(String),
  scopes: dict.Dict(String, manifest.Scope),
  palette: color.Palette,
) -> String {
```

```gleam
      let body_doc =
        list.map(affected, fn(row) { format_vuln_row(row, scopes, palette) })
        |> doc.join(with: doc.line)
```

- [ ] **Step 5: Add the scope label in `format_vuln_row`**

```gleam
fn format_vuln_row(
  row: VulnRow,
  scopes: dict.Dict(String, manifest.Scope),
  palette: color.Palette,
) -> Document {
  let scope = case dict.get(scopes, row.package.name) {
    Ok(scope) -> scope
    Error(_) -> manifest.Prod
  }
  let pkg_line =
    doc.from_string(
      "● "
      <> row.package.name
      <> " "
      <> row.package.version
      <> "  ["
      <> manifest.scope_label(scope)
      <> "]",
    )
```

(The remainder of `format_vuln_row` — `vuln_lines` and the final `doc.concat` — is unchanged.)

- [ ] **Step 6: Test, lint, commit**

Run: `gleam test && gleam format && gleam check`
Expected: PASS, clean.

```bash
git add src/licence_audit.gleam test/licence_audit/integration_test.gleam
git commit -m "feat: label prod/dev scope in vulns report"
```

---

## Task 5: `--prod-only` flag for `check`

**Files:**
- Modify: `src/licence_audit/cli.gleam`
- Modify: `src/licence_audit.gleam` (`audit_locked` filtering)
- Create: `test/fixtures/prod_dev_manifest.toml`
- Test: `test/licence_audit/integration_test.gleam`

- [ ] **Step 1: Add `prod_only` to `cli.Options`**

In `src/licence_audit/cli.gleam`, add the field to `Options` (after `vuln_severity`):

```gleam
pub type Options {
  Options(
    manifest_path: Option(String),
    project_root: Option(String),
    config_path: Option(String),
    allow_licences: List(String),
    deny_licences: List(String),
    ignore_config: Bool,
    check: Bool,
    verbosity: progress.Verbosity,
    color: color.Mode,
    no_cache: Bool,
    cache_path: Option(String),
    check_vulns: Bool,
    vuln_severity: Option(String),
    prod_only: Bool,
  )
}
```

- [ ] **Step 2: Add the flag definition**

Add near the other flag builders in `cli.gleam`:

```gleam
fn prod_only_flag() -> glint.Flag(Bool) {
  glint.bool_flag("prod-only")
  |> glint.flag_default(False)
  |> glint.flag_help(
    "Only audit production dependencies; ignore dev-dependency violations",
  )
}
```

- [ ] **Step 3: Register + set the flag in both commands**

In `audit_command`, add `use prod_only <- glint.flag(prod_only_flag())` with the other `use ... <- glint.flag(...)` lines, add `let assert Ok(prod_only_value) = prod_only(flags)` with the other asserts, and add `prod_only: prod_only_value,` to its `Options(...)`.

In `check_command`, do the same three additions, with `prod_only: prod_only_value,` in its `Options(...)`.

- [ ] **Step 4: Apply filtering in `audit_locked`**

In `src/licence_audit.gleam`, in `audit_locked`, just before the `fetch_packages` call, derive the active package/skipped sets:

```gleam
  let #(active_packages, active_skipped) = case options.prod_only {
    False -> #(locked.packages, locked.skipped_packages)
    True -> #(
      list.filter(locked.packages, fn(p) {
        scope_for(scopes, p.name) == manifest.Prod
      }),
      list.filter(locked.skipped_packages, fn(p) {
        scope_for(scopes, p.name) == manifest.Prod
      }),
    )
  }
```

Change the `fetch_packages` first argument from `locked.packages` to `active_packages`, and `build_skipped_rows`'s first argument from `locked.skipped_packages` to `active_skipped`. Because dropped dev packages are never fetched, their policy status never contributes to `result.policy_failed`, so the exit code reflects prod-only — matching the spec.

- [ ] **Step 5: Create the fixture**

Create `test/fixtures/prod_dev_manifest.toml`:

```toml
packages = [
  { name = "gleam_stdlib", version = "1.0.0", build_tools = ["gleam"], requirements = [], otp_app = "gleam_stdlib", source = "hex", outer_checksum = "AAAA" },
  { name = "gleeunit", version = "1.0.0", build_tools = ["gleam"], requirements = [], otp_app = "gleeunit", source = "hex", outer_checksum = "BBBB" },
]

[requirements]
gleam_stdlib = { version = ">= 1.0.0 and < 2.0.0" }
gleeunit = { version = ">= 1.0.0 and < 2.0.0" }
```

With `project_root="."`, `gleam_stdlib ∈ [dependencies]` (prod) and `gleeunit ∉ [dependencies]` (dev) per the repo's own `gleam.toml`, so `gleeunit` classifies as `Dev`.

- [ ] **Step 6: Write the integration test**

Append to `test/licence_audit/integration_test.gleam`:

```gleam
fn prod_dev_fetcher(name: String) -> Result(hex.PackageMetadata, hex.Error) {
  case name {
    "gleam_stdlib" -> Ok(hex.PackageMetadata(licences: ["MIT"]))
    // A denied licence on the dev dependency.
    "gleeunit" -> Ok(hex.PackageMetadata(licences: ["AGPL-3.0"]))
    _ -> Error(hex.NotFound)
  }
}

pub fn check_fails_on_dev_dependency_violation_by_default_test() {
  let licence_audit.RunResult(exit_code, _output) =
    licence_audit.run_with(
      [
        "--manifest=test/fixtures/prod_dev_manifest.toml",
        "--ignore-config",
        "check",
        "--allow=MIT",
        "--deny=AGPL-3.0",
      ],
      prod_dev_fetcher,
    )

  should.equal(exit_code, 1)
}

pub fn check_prod_only_ignores_dev_dependency_violation_test() {
  let licence_audit.RunResult(exit_code, output) =
    licence_audit.run_with(
      [
        "--manifest=test/fixtures/prod_dev_manifest.toml",
        "--ignore-config",
        "check",
        "--allow=MIT",
        "--deny=AGPL-3.0",
        "--prod-only",
      ],
      prod_dev_fetcher,
    )

  should.equal(exit_code, 0)
  assert string.contains(output, "gleam_stdlib")
  // gleeunit (dev) is dropped under --prod-only.
  assert !string.contains(output, "gleeunit")
}
```

- [ ] **Step 7: Run the tests**

Run: `gleam test`
Expected: PASS. The default check exits 1 (dev violation counts); `--prod-only` exits 0 (dev dropped) and omits `gleeunit`.

- [ ] **Step 8: Lint and commit**

```bash
gleam format && gleam check
git add src/licence_audit/cli.gleam src/licence_audit.gleam test/fixtures/prod_dev_manifest.toml test/licence_audit/integration_test.gleam
git commit -m "feat: add --prod-only flag to skip dev-dependency violations"
```

---

## Self-Review Notes (plan vs spec)

- **Spec coverage:** Scope type + prod-wins reachability + `[dependencies]` seed + fallback (Task 1) ✓; report prod/dev sections (Task 2) ✓; SBOM `licence_audit:scope` property, property-only (Task 3) ✓; `vulns` scope labels (Task 4) ✓; `check --prod-only`, default unchanged (Task 5) ✓.
- **Type consistency:** `manifest.Scope{Prod,Dev}`, `manifest.dep_scopes`, `manifest.sbom_scopes`, `manifest.prod_direct_names`, `manifest.scope_label`, `report.Row.scope`, `sbom.SbomInput.scopes`, and the `scope_for`/`resolve_prod_seed`/`compute_scopes` helpers are referenced identically across tasks.
- **Behavior preservation:** default report still column-aligned (widths over all rows) and integration tests use `string.contains`; SBOM/vulns default to `prod` via the fallback; `check` default behavior unchanged (filter only under `--prod-only`).
- **No `[dev-dependencies]` parsing:** intentional — dev is the reachability complement of prod, robust to the repo's `[dev_dependencies]` spelling.
- **Deviation flagged:** the `--prod-only` test relies on the repo's real `gleam.toml` (`gleam_stdlib` prod, `gleeunit` dev) because there is no `--project-root` flag. If you'd prefer hermetic fixtures, a small follow-up adding `--project-root` would let the test point at a self-contained project dir; out of scope here.
