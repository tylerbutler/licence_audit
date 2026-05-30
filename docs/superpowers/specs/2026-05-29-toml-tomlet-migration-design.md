# Project A: Migrate all TOML parsing `tom` → `tomlet`

**Date:** 2026-05-29
**Status:** Approved, ready for implementation plan
**Relationship:** Foundation for [Project B: prod vs dev dependency breakdown](./2026-05-29-prod-dev-dependency-breakdown-design.md). Do A first.

## Goal

Consolidate the codebase onto a single TOML library (`tomlet`) and drop the
`tom` dependency. This is a **behavior-preserving refactor**: all existing
error variants, parse results, and command outputs stay identical, and the
existing test suite stays green without modification.

There is no user-visible change. The value is a single TOML access path
(parsing + comment-preserving edits both go through `tomlet`), removing the
two-library split that currently exists between `tom` (reads) and `tomlet`
(edits).

## Background: current state

The repo currently uses **two** TOML libraries:

- `tom` (v2.1.0) — read/parse. Used in `manifest.gleam` (lockfile + SBOM
  manifest parsing) and `config.gleam` (policy parsing from `gleam.toml`).
- `tomlet` (v1.0.0) — comment-preserving edits. Wrapped by `toml_port.gleam`,
  used only by `update.gleam` to write policy back to `gleam.toml`.

`tom` usage to migrate (three consumers):

- **`manifest.gleam`**: `tom.parse`, `tom.get_array(doc, ["packages"])`,
  `tom.NotFound`, `tom.as_table`, `tom.as_string`, `tom.as_array`,
  `type Toml`, and `decode_direct_names` (reads `[requirements]` table keys).
- **`config.gleam`**: `tom.parse`, `tom.get_table(doc, candidate)`,
  `tom.NotFound`, `tom.as_string`, `tom.as_array`, `type Toml`.
- **`licence_audit.gleam`**: `read_root_component` and `tool_version` use
  `tom.parse` + `tom.get_string(doc, ["name"])` / `["version"]` to read the
  project's own `gleam.toml` name/version.

## The crux: read-model difference

`tom` exposes `get_array` / `as_table` / `as_string` over a `Dict(String, Toml)`.

`tomlet`'s read API is `tomlet.get(doc, key) -> Result(Value, GetError)`, where
table-shaped values are **ordered association lists**:

```gleam
StandardTableValue(List(#(List(String), Value)))
ArrayOfTablesValue(List(List(#(List(String), Value))))
ArrayValue(List(Value))
StringValue(String)
```

The lockfile expresses packages as an **array of inline tables**
(`packages = [ { name = ..., ... }, ... ]`), not `[[packages]]` array-of-tables.
So `tomlet.get(doc, ["packages"])` returns `ArrayValue([InlineTableValue(...), ...])`,
and each package is an inline-table entry assoc list (`List(#(List(String), Value))`)
that we walk directly — `tomlet.get` operates on the `Document`, not on a
sub-table `Value`. This is the main shape the migration has to bridge.

## Components

### 1. Rename `toml_port.gleam` → `licence_audit/toml.gleam`

`toml_port` is poorly named ("port" implies an FFI/Erlang port; it is just a
`tomlet` wrapper). Rename it to `licence_audit/toml` and grow it into the
shared TOML facade for the whole project. Update the import in `update.gleam`
(currently the only consumer).

New read accessors (added alongside the existing `set_string_array` edit helper).
These deliberately mirror the old `tom` primitives so the three consumers swap
`tom.*` → `toml.*` with minimal change. `Entry = List(#(List(String), Value))`.

- `parse(input: String) -> Result(Document, Nil)`
- `get_string(doc, path) -> Result(String, Nil)` — top-level scalar (for
  `licence_audit.gleam` name/version).
- `get_array(doc, path) -> Result(List(Value), ArrayError)` where
  `ArrayError = ArrayMissing | ArrayNotArray` — for `packages = [...]`.
- `get_table(doc, path) -> Result(Entry, TableLookupError)` where
  `TableLookupError = TableLookupMissing | TableLookupNotTable` — for
  `[tools.licence_audit]`.
- `table_keys(doc, path) -> Result(List(String), Nil)` — top-level keys of a
  table, for `[requirements]` and (Project B) `[dependencies]`.
- value/entry accessors mirroring `tom`: `as_string(value)`, `as_array(value)`,
  `as_table(value)`, and `field(entry, name)` (single-segment lookup).

The facade owns the assoc-list walking so the consumers stay declarative. Each
caller maps facade errors to its own existing `Error` variants (below). The
assoc-list-walking accessors are the workaround for tomlet#22/#23; the source
carries comments linking those issues.

### 2. `manifest.gleam`

Replace all `tom.*` calls with the new `toml` facade accessors:

- `parse` / `sbom_entries`: `toml.parse`, then `toml.get_array(doc, ["packages"])`.
- `decode_package` / `decode_sbom_entry`: each package item becomes an `Entry`
  via `toml.as_table`; fields read via `toml.field` + `toml.as_string` /
  `toml.as_array`. `required_string` / `optional_string_list` are reimplemented
  over `Entry` instead of `Dict(String, Toml)`, preserving decode order.
- `decode_direct_names`: `toml.table_keys(doc, ["requirements"])`, then keep
  the existing `list.sort(by: string.compare)`.

**Error mapping (variants unchanged):**

- tomlet parse failure → `InvalidToml("Invalid TOML")`
- `["packages"]` absent → `MissingPackages`
- `["packages"]` present but not an array-of-tables → `InvalidPackageField("<manifest>", "packages", "Array")`
- field missing / wrong type → `InvalidPackageField(package, field, expected)`

### 3. `config.gleam`

Move `[tools.licence_audit]` policy parsing to the `toml` facade. `find_section`
becomes a `get` on the candidate path returning a `StandardTableValue`; the
`allow`/`deny` arrays and `vuln_severity` string read through facade helpers.
`Error` variants (`InvalidToml`, `MissingPolicy`, `InvalidField`,
`InvalidLicenceIdentifier`, `FileReadError`) are **unchanged**.

### 4. `licence_audit.gleam`

`read_root_component` and `tool_version` swap `tom.parse` → `toml.parse` and
`tom.get_string(doc, [..])` → `toml.get_string(doc, [..])`. Both already fall
back to defaults on any error, so behavior is unchanged.

### 5. `gleam.toml`

Remove `tom = ">= 2.1.0 and < 3.0.0"`. Keep `tomlet`.

## Testing (parity-first)

- The existing `manifest_test`, `config_test`, and `sbom_test` are the parity
  harness. They assert exact `Error(...)` values and parsed structures and must
  pass **unchanged**. Run them as a baseline before the migration and again
  after — green-to-green is the proof of parity.
- Add focused unit tests for the new `toml` facade accessors:
  - `array_of_tables` walks a `[[packages]]` document into per-package entries.
  - `get_table_keys` returns `[requirements]` keys.
  - missing path vs wrong-type produce the distinct facade errors that callers
    map to `MissingPackages` vs `InvalidPackageField`.
- No behavior change ⇒ no new golden/report outputs.

## Risks & mitigations

- **Error-variant drift** — tomlet may distinguish "not found" vs "wrong type"
  differently than `tom`. Mitigated by the existing tests asserting exact
  `Error(...)` values; the facade error mapping is written to satisfy them.
- **Ordering** — tomlet preserves source order; `tom` table iteration order was
  already normalized by an explicit `list.sort` in `decode_direct_names`. Keep
  that sort.
- **Inline-table dependency values** (Project B relevance, but valid here too) —
  `name = { version = "..." }` still yields a top-level entry key of `name`, so
  `get_table_keys` is correct regardless of the value shape.

## Out of scope

- Any prod/dev classification or new commands/flags — that is Project B.
- Changing the comment-preserving write path beyond the module rename.
