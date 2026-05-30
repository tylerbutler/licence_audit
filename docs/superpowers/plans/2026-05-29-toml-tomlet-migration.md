# tom → tomlet Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the `tom` TOML library with `tomlet` everywhere, behind a single `licence_audit/toml` facade, and drop the `tom` dependency — with zero behavior change.

**Architecture:** Rename the existing `toml_port.gleam` (a thin `tomlet` edit wrapper) to `licence_audit/toml.gleam` and grow it into the project's one TOML access layer. Add read accessors that mirror the old `tom` primitives (`as_string`/`as_array`/`as_table`/`field`/`get_array`/`get_table`/`get_string`/`table_keys`) implemented over tomlet's `Value` assoc lists. Then migrate the three consumers (`manifest.gleam`, `config.gleam`, `licence_audit.gleam`) and remove `tom` from `gleam.toml`. The existing test suite is the parity harness.

**Tech Stack:** Gleam, `tomlet` (v1.0.0), `gleeunit`, `simplifile`.

**Spec:** `docs/superpowers/specs/2026-05-29-toml-tomlet-migration-design.md`

**Reference — tomlet read API used here:**
- `tomlet.parse(String) -> Result(Document, ParseError)`
- `tomlet.get(doc, key: List(String)) -> Result(Value, GetError)` — for a top-level array of inline tables returns `ArrayValue([InlineTableValue(...), ...])`; for a header table returns `StandardTableValue(entries)`.
- `tomlet.get_string(doc, key) -> Result(String, GetError)`
- `Value` table variants carry `List(#(List(String), Value))` (entry key is a dotted path; simple keys are single-element lists).
- `GetError = KeyNotFound(key) | WrongType(key, expected)`.

**Workaround note:** the assoc-list-walking accessors exist only because tomlet lacks value-level accessors (tylerbutler/tomlet#22) and table-key enumeration (tylerbutler/tomlet#23). The facade source must carry comments linking those issues.

---

## File Structure

- `src/licence_audit/toml.gleam` — **renamed** from `toml_port.gleam`; the single TOML facade (edits + new read accessors).
- `test/licence_audit/toml_test.gleam` — **renamed** from `toml_port_test.gleam`; gains tests for the new read accessors.
- `src/licence_audit/manifest.gleam` — **modified**; lockfile + SBOM-manifest parsing moved off `tom`.
- `src/licence_audit/config.gleam` — **modified**; policy parsing moved off `tom`.
- `src/licence_audit.gleam` — **modified**; `read_root_component` / `tool_version` moved off `tom`.
- `src/licence_audit/update.gleam` — **modified**; import path of the renamed module only.
- `gleam.toml` — **modified**; drop the `tom` dependency.

---

## Task 1: Rename `toml_port` → `toml` (pure rename, no behavior change)

**Files:**
- Rename: `src/licence_audit/toml_port.gleam` → `src/licence_audit/toml.gleam`
- Rename: `test/licence_audit/toml_port_test.gleam` → `test/licence_audit/toml_test.gleam`
- Modify: `src/licence_audit/update.gleam` (import + references)

- [ ] **Step 1: Capture the green baseline**

Run: `gleam test`
Expected: PASS (all existing tests). Record this as the parity baseline.

- [ ] **Step 2: Move the source and test files with git**

```bash
git mv src/licence_audit/toml_port.gleam src/licence_audit/toml.gleam
git mv test/licence_audit/toml_port_test.gleam test/licence_audit/toml_test.gleam
```

- [ ] **Step 3: Update the module doc comment**

In `src/licence_audit/toml.gleam`, replace the first line:

```gleam
//// Shared TOML access layer for licence_audit, built on the `tomlet`
//// dependency: comment-preserving edits (`set_string_array`) plus the read
//// accessors used by manifest/config parsing.
////
//// The read accessors below walk tomlet's raw `Value` assoc lists by hand
//// because tomlet has no value-level accessors and no table-key enumeration.
//// Tracked upstream — if these land, the helpers become thin pass-throughs:
////   - value-level accessors: https://github.com/tylerbutler/tomlet/issues/22
////   - table key enumeration:  https://github.com/tylerbutler/tomlet/issues/23
```

- [ ] **Step 4: Update references in `update.gleam`**

Replace every `toml_port` with `toml`. There are four occurrences (one import, `toml_port.Error`, `toml_port.error_message`, two `toml_port.set_string_array`):

Run: `sd 'toml_port' 'toml' src/licence_audit/update.gleam`

- [ ] **Step 5: Update references in the renamed test file**

Run: `sd 'toml_port' 'toml' test/licence_audit/toml_test.gleam`

- [ ] **Step 6: Verify no `toml_port` references remain**

Run: `rg -n 'toml_port' src/ test/`
Expected: no matches.

- [ ] **Step 7: Run tests**

Run: `gleam test`
Expected: PASS (unchanged from baseline).

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "refactor: rename toml_port module to toml

'port' implied an FFI/Erlang port; it is just the tomlet wrapper. The module
is becoming the project's single TOML access layer."
```

---

## Task 2: Add read accessors to the `toml` facade (TDD)

**Files:**
- Modify: `src/licence_audit/toml.gleam`
- Test: `test/licence_audit/toml_test.gleam`

- [ ] **Step 1: Write failing tests for the read accessors**

Append to `test/licence_audit/toml_test.gleam`. (Keep the file's existing imports; add `import licence_audit/toml` and `import tomlet` if not already present.)

```gleam
const packages_doc = "packages = [
  { name = \"app_a\", version = \"1.0.0\", source = \"hex\", requirements = [\"lib_b\"] },
  { name = \"lib_b\", version = \"2.0.0\", source = \"hex\", requirements = [] },
]

[requirements]
app_a = { version = \">= 1.0.0\" }
gleam_stdlib = { version = \">= 1.0.0\" }
"

pub fn parse_ok_test() {
  let assert Ok(_) = toml.parse(packages_doc)
}

pub fn parse_error_on_malformed_test() {
  let assert Error(Nil) = toml.parse("packages = [")
}

pub fn get_array_returns_items_test() {
  let assert Ok(doc) = toml.parse(packages_doc)
  let assert Ok(items) = toml.get_array(doc, ["packages"])
  should.equal(list.length(items), 2)
}

pub fn get_array_missing_test() {
  let assert Ok(doc) = toml.parse("[requirements]\n")
  should.equal(toml.get_array(doc, ["packages"]), Error(toml.ArrayMissing))
}

pub fn get_array_not_array_test() {
  let assert Ok(doc) = toml.parse("packages = 42\n")
  should.equal(toml.get_array(doc, ["packages"]), Error(toml.ArrayNotArray))
}

pub fn as_table_and_field_string_test() {
  let assert Ok(doc) = toml.parse(packages_doc)
  let assert Ok([first, ..]) = toml.get_array(doc, ["packages"])
  let assert Ok(entry) = toml.as_table(first)
  let assert Ok(value) = toml.field(entry, "name")
  should.equal(toml.as_string(value), Ok("app_a"))
}

pub fn field_missing_test() {
  let assert Ok(doc) = toml.parse(packages_doc)
  let assert Ok([first, ..]) = toml.get_array(doc, ["packages"])
  let assert Ok(entry) = toml.as_table(first)
  should.equal(toml.field(entry, "nope"), Error(Nil))
}

pub fn as_array_of_requirements_test() {
  let assert Ok(doc) = toml.parse(packages_doc)
  let assert Ok([first, ..]) = toml.get_array(doc, ["packages"])
  let assert Ok(entry) = toml.as_table(first)
  let assert Ok(value) = toml.field(entry, "requirements")
  let assert Ok(items) = toml.as_array(value)
  should.equal(list.length(items), 1)
}

pub fn table_keys_returns_keys_test() {
  let assert Ok(doc) = toml.parse(packages_doc)
  let assert Ok(keys) = toml.table_keys(doc, ["requirements"])
  should.equal(list.sort(keys, string.compare), ["app_a", "gleam_stdlib"])
}

pub fn table_keys_missing_test() {
  let assert Ok(doc) = toml.parse("packages = []\n")
  should.equal(toml.table_keys(doc, ["requirements"]), Error(Nil))
}

pub fn get_table_returns_entries_test() {
  let assert Ok(doc) = toml.parse("[tools.licence_audit]\nallow = [\"MIT\"]\n")
  let assert Ok(entry) = toml.get_table(doc, ["tools", "licence_audit"])
  let assert Ok(value) = toml.field(entry, "allow")
  let assert Ok(items) = toml.as_array(value)
  should.equal(list.length(items), 1)
}

pub fn get_table_missing_test() {
  let assert Ok(doc) = toml.parse("name = \"x\"\n")
  should.equal(
    toml.get_table(doc, ["tools", "licence_audit"]),
    Error(toml.TableLookupMissing),
  )
}

pub fn get_table_not_table_test() {
  let assert Ok(doc) = toml.parse("tools = 7\n")
  should.equal(
    toml.get_table(doc, ["tools"]),
    Error(toml.TableLookupNotTable),
  )
}

pub fn get_string_test() {
  let assert Ok(doc) = toml.parse("name = \"hello\"\nversion = \"1.2.3\"\n")
  should.equal(toml.get_string(doc, ["name"]), Ok("hello"))
  should.equal(toml.get_string(doc, ["missing"]), Error(Nil))
}
```

Ensure the test file imports `gleam/list` and `gleam/string` and `gleeunit/should`.

- [ ] **Step 2: Run the new tests to verify they fail**

Run: `gleam test`
Expected: FAIL — compile errors (`toml.get_array`, `toml.ArrayMissing`, etc. unknown).

- [ ] **Step 3: Implement the read accessors**

In `src/licence_audit/toml.gleam`, change the import line and add the accessors. The existing imports are `gleam/int`, `gleam/list`, `gleam/string`, `tomlet`. Update the tomlet import to also bring in the types, and add the new code below the existing `pub type Error`:

```gleam
import tomlet.{type Document, type Value}
```

```gleam
/// A table's entries as tomlet exposes them: an ordered assoc list of
/// `#(dotted_key_path, value)`. See tylerbutler/tomlet#22.
pub type Entry =
  List(#(List(String), Value))

pub type ArrayError {
  ArrayMissing
  ArrayNotArray
}

pub type TableLookupError {
  TableLookupMissing
  TableLookupNotTable
}

/// Parse TOML source, collapsing tomlet's rich parse error to `Error(Nil)`.
pub fn parse(input: String) -> Result(Document, Nil) {
  case tomlet.parse(input) {
    Ok(doc) -> Ok(doc)
    Error(_) -> Error(Nil)
  }
}

/// Read a top-level (or path-addressed) string scalar.
pub fn get_string(doc: Document, path: List(String)) -> Result(String, Nil) {
  case tomlet.get_string(doc, path) {
    Ok(value) -> Ok(value)
    Error(_) -> Error(Nil)
  }
}

/// Read the array at `path` as its item values.
/// Workaround for tylerbutler/tomlet#22 (no value-level array accessor).
pub fn get_array(
  doc: Document,
  path: List(String),
) -> Result(List(Value), ArrayError) {
  case tomlet.get(doc, path) {
    Error(_) -> Error(ArrayMissing)
    Ok(tomlet.ArrayValue(items)) -> Ok(items)
    Ok(_) -> Error(ArrayNotArray)
  }
}

/// Read the table at `path` as its entry assoc list.
pub fn get_table(
  doc: Document,
  path: List(String),
) -> Result(Entry, TableLookupError) {
  case tomlet.get(doc, path) {
    Error(_) -> Error(TableLookupMissing)
    Ok(value) ->
      case as_table(value) {
        Ok(entries) -> Ok(entries)
        Error(_) -> Error(TableLookupNotTable)
      }
  }
}

/// Top-level keys of the table at `path`, in source order. `Error(Nil)` when
/// the path is absent or is not a table.
/// Workaround for tylerbutler/tomlet#23 (no table-key enumeration).
pub fn table_keys(doc: Document, path: List(String)) -> Result(List(String), Nil) {
  case tomlet.get(doc, path) {
    Ok(value) ->
      case as_table(value) {
        Ok(entries) -> Ok(entry_keys(entries))
        Error(_) -> Error(Nil)
      }
    Error(_) -> Error(Nil)
  }
}

/// Look up a simple (single-segment) field within a table's entries.
/// Workaround for tylerbutler/tomlet#22.
pub fn field(entry: Entry, name: String) -> Result(Value, Nil) {
  case list.find(entry, fn(pair) { pair.0 == [name] }) {
    Ok(pair) -> Ok(pair.1)
    Error(_) -> Error(Nil)
  }
}

/// Value -> String.
pub fn as_string(value: Value) -> Result(String, Nil) {
  case value {
    tomlet.StringValue(s) -> Ok(s)
    _ -> Error(Nil)
  }
}

/// Value -> array item list.
pub fn as_array(value: Value) -> Result(List(Value), Nil) {
  case value {
    tomlet.ArrayValue(items) -> Ok(items)
    _ -> Error(Nil)
  }
}

/// Value -> table entries (standard or inline table).
pub fn as_table(value: Value) -> Result(Entry, Nil) {
  case value {
    tomlet.StandardTableValue(entries) -> Ok(entries)
    tomlet.InlineTableValue(entries) -> Ok(entries)
    _ -> Error(Nil)
  }
}

fn entry_keys(entries: Entry) -> List(String) {
  list.filter_map(entries, fn(pair) {
    case pair.0 {
      [name, ..] -> Ok(name)
      [] -> Error(Nil)
    }
  })
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `gleam test`
Expected: PASS (existing + new accessor tests).

- [ ] **Step 5: Lint**

Run: `gleam format && gleam check`
Expected: clean (no glinter/compile warnings).

- [ ] **Step 6: Commit**

```bash
git add src/licence_audit/toml.gleam test/licence_audit/toml_test.gleam
git commit -m "feat: add tomlet-backed read accessors to toml facade

Mirrors the tom primitives (as_string/as_array/as_table/field/get_array/
get_table/get_string/table_keys) over tomlet Value assoc lists. Hand-walking
is a workaround for tomlet#22 and tomlet#23."
```

---

## Task 3: Migrate `manifest.gleam` off `tom`

**Files:**
- Modify: `src/licence_audit/manifest.gleam`
- Test (parity): `test/licence_audit/manifest_test.gleam`, `test/licence_audit/sbom_test.gleam`

These tests already assert exact `Error(...)` values and parsed structures.
They are the parity harness and must pass **unchanged**.

- [ ] **Step 1: Run the parity tests first (baseline)**

Run: `gleam test`
Expected: PASS.

- [ ] **Step 2: Swap imports**

In `src/licence_audit/manifest.gleam`, replace:

```gleam
import tom.{type Toml}
```

with:

```gleam
import licence_audit/toml
import tomlet.{type Document, type Value}
```

(Keep `gleam/dict`, `gleam/list`, `gleam/result`, `gleam/string`, `simplifile`.)

- [ ] **Step 3: Rewrite `sbom_entries` and `sbom_entries_from_document`**

```gleam
pub fn sbom_entries(input: String) -> Result(SbomManifest, Error) {
  case toml.parse(input) {
    Error(_) -> Error(InvalidToml("Invalid TOML"))
    Ok(document) -> sbom_entries_from_document(document)
  }
}

fn sbom_entries_from_document(
  document: Document,
) -> Result(SbomManifest, Error) {
  case toml.get_array(document, ["packages"]) {
    Error(toml.ArrayMissing) -> Error(MissingPackages)
    Error(toml.ArrayNotArray) ->
      Error(InvalidPackageField("<manifest>", "packages", "Array"))
    Ok(packages) -> {
      let direct_names = decode_direct_names(document)
      use entries <- result.try(
        list.try_map(packages, fn(package) {
          decode_sbom_entry(package, direct_names)
        }),
      )
      Ok(SbomManifest(entries: entries, root_requirements: direct_names))
    }
  }
}
```

- [ ] **Step 4: Rewrite `decode_sbom_entry` and `decode_provenance` to take a package `Value` / `Entry`**

```gleam
fn decode_sbom_entry(
  package: Value,
  direct_names: List(String),
) -> Result(SbomEntry, Error) {
  case toml.as_table(package) {
    Error(_) ->
      Error(InvalidPackageField(
        package: "<unknown>",
        field: "package",
        expected: "Table",
      ))
    Ok(table) -> {
      use source <- result.try(required_string(table, "source", "<unknown>"))
      use name <- result.try(required_string(table, "name", "<unknown>"))
      use version <- result.try(required_string(table, "version", name))
      use requirements <- result.try(optional_string_list(
        table,
        "requirements",
        name,
      ))
      use provenance <- result.try(decode_provenance(source, table, name))
      let kind = case list.contains(direct_names, name) {
        True -> Direct
        False -> Transitive
      }
      Ok(SbomEntry(
        name: name,
        version: version,
        kind: kind,
        requirements: requirements,
        provenance: provenance,
      ))
    }
  }
}

fn decode_provenance(
  source: String,
  table: toml.Entry,
  package_name: String,
) -> Result(Provenance, Error) {
  case source {
    "hex" -> {
      use checksum <- result.try(required_string(
        table,
        "outer_checksum",
        package_name,
      ))
      Ok(HexProvenance(outer_checksum: checksum))
    }
    "git" -> {
      use repo <- result.try(required_string(table, "repo", package_name))
      use commit <- result.try(required_string(table, "commit", package_name))
      Ok(GitProvenance(repo: repo, commit: commit))
    }
    "path" -> {
      use path <- result.try(required_string(table, "path", package_name))
      Ok(PathProvenance(path: path))
    }
    other -> Ok(UnknownProvenance(source: other))
  }
}
```

- [ ] **Step 5: Rewrite `parse` and `decode_package`**

```gleam
pub fn parse(input: String) -> Result(LockedPackages, Error) {
  case toml.parse(input) {
    Error(_) -> Error(InvalidToml("Invalid TOML"))
    Ok(document) ->
      case toml.get_array(document, ["packages"]) {
        Error(toml.ArrayMissing) -> Error(MissingPackages)
        Error(toml.ArrayNotArray) ->
          Error(InvalidPackageField("<manifest>", "packages", "Array"))
        Ok(packages) -> {
          use raw_packages <- result.try(list.try_map(packages, decode_package))
          let direct_names = decode_direct_names(document)
          Ok(build_locked(raw_packages, direct_names))
        }
      }
  }
}

fn decode_package(package: Value) -> Result(RawPackage, Error) {
  case toml.as_table(package) {
    Error(_) ->
      Error(InvalidPackageField(
        package: "<unknown>",
        field: "package",
        expected: "Table",
      ))
    Ok(table) -> {
      use source <- result.try(required_string(table, "source", "<unknown>"))
      use name <- result.try(required_string(table, "name", "<unknown>"))
      use version <- result.try(required_string(table, "version", name))
      use requirements <- result.try(optional_string_list(
        table,
        "requirements",
        name,
      ))
      let source_kind = case source {
        "hex" -> HexSource
        _ -> NonHexSource
      }
      Ok(RawPackage(
        name: name,
        version: version,
        source: source,
        source_kind: source_kind,
        requirements: requirements,
      ))
    }
  }
}
```

- [ ] **Step 6: Rewrite `decode_direct_names`**

```gleam
fn decode_direct_names(document: Document) -> List(String) {
  case toml.table_keys(document, ["requirements"]) {
    Ok(keys) -> list.sort(keys, by: string.compare)
    Error(_) -> []
  }
}
```

- [ ] **Step 7: Rewrite the field helpers over `Entry`**

Replace `required_string`, `optional_string_list`, and `decode_string_list`:

```gleam
fn optional_string_list(
  table: toml.Entry,
  field: String,
  package_name: String,
) -> Result(List(String), Error) {
  case toml.field(table, field) {
    Error(_) -> Ok([])
    Ok(value) ->
      case toml.as_array(value) {
        Error(_) ->
          Error(InvalidPackageField(
            package: package_name,
            field: field,
            expected: "Array",
          ))
        Ok(items) -> decode_string_list(items, package_name, field, [])
      }
  }
}

fn decode_string_list(
  items: List(Value),
  package_name: String,
  field: String,
  acc: List(String),
) -> Result(List(String), Error) {
  case items {
    [] -> Ok(list.reverse(acc))
    [item, ..rest] ->
      case toml.as_string(item) {
        Error(_) ->
          Error(InvalidPackageField(
            package: package_name,
            field: field,
            expected: "String",
          ))
        Ok(value) ->
          decode_string_list(rest, package_name, field, [value, ..acc])
      }
  }
}

fn required_string(
  table: toml.Entry,
  field: String,
  package_name: String,
) -> Result(String, Error) {
  case toml.field(table, field) {
    Error(_) ->
      Error(InvalidPackageField(
        package: package_name,
        field: field,
        expected: "String",
      ))
    Ok(value) ->
      case toml.as_string(value) {
        Ok(value) -> Ok(value)
        Error(_) ->
          Error(InvalidPackageField(
            package: package_name,
            field: field,
            expected: "String",
          ))
      }
  }
}
```

- [ ] **Step 8: Confirm no `tom.` / `Toml` references remain in the file**

Run: `rg -n '\btom\.|type Toml|: Toml' src/licence_audit/manifest.gleam`
Expected: no matches.

- [ ] **Step 9: Run the parity tests**

Run: `gleam test`
Expected: PASS — `manifest_test` and `sbom_test` green, unchanged. In particular:
- `parse_errors_when_packages_is_missing_test` → `MissingPackages`
- `parse_errors_on_malformed_toml_test` → `InvalidToml(_)`
- `parse_errors_when_package_field_has_wrong_type_test` → `InvalidPackageField("<unknown>", "name", "String")`
- `parse_returns_only_hex_packages_and_skipped_count_test` and `dep_paths_*` unchanged.

- [ ] **Step 10: Lint and commit**

```bash
gleam format && gleam check
git add src/licence_audit/manifest.gleam
git commit -m "refactor: parse manifest.toml via toml facade instead of tom"
```

---

## Task 4: Migrate `config.gleam` off `tom`

**Files:**
- Modify: `src/licence_audit/config.gleam`
- Test (parity): `test/licence_audit/config_test.gleam`

- [ ] **Step 1: Baseline**

Run: `gleam test`
Expected: PASS.

- [ ] **Step 2: Swap imports**

Replace `import tom.{type Toml}` with `import licence_audit/toml`. Remove
`import gleam/dict` (it becomes unused — confirmed in Step 6). Keep `gleam/bool`,
`gleam/list`, `gleam/option`, `gleam/result`, `gleam/string`, `simplifile`.

- [ ] **Step 3: Rewrite `parse` to look up the policy section directly**

Replace `parse` and delete the now-unused `parse_document`, `find_section`, and
`key_name` helpers:

```gleam
pub fn parse(input: String) -> Result(Policy, Error) {
  case toml.parse(input) {
    Error(_) -> Error(InvalidToml("Invalid TOML"))
    Ok(document) ->
      case toml.get_table(document, ["tools", "licence_audit"]) {
        Error(toml.TableLookupMissing) -> Error(MissingPolicy)
        Error(toml.TableLookupNotTable) ->
          Error(InvalidField(field: "tools.licence_audit", expected: "Table"))
        Ok(section) -> parse_policy_section(section)
      }
  }
}
```

- [ ] **Step 4: Rewrite `parse_policy_section` and the field readers over `Entry`**

```gleam
fn parse_policy_section(section: toml.Entry) -> Result(Policy, Error) {
  use allow <- result.try(optional_string_list(section, "allow"))
  use deny <- result.try(optional_string_list(section, "deny"))
  use severity <- result.try(optional_string(section, "vuln_severity"))
  validate(Policy(allow: allow, deny: deny, vuln_severity: severity))
}

fn optional_string(
  section: toml.Entry,
  field: String,
) -> Result(Option(String), Error) {
  case toml.field(section, field) {
    Error(_) -> Ok(None)
    Ok(value) ->
      case toml.as_string(value) {
        Error(_) -> Error(InvalidField(field: field, expected: "String"))
        Ok(s) -> Ok(Some(s))
      }
  }
}

fn optional_string_list(
  section: toml.Entry,
  field: String,
) -> Result(List(String), Error) {
  case toml.field(section, field) {
    Error(_) -> Ok([])
    Ok(value) ->
      case toml.as_array(value) {
        Error(_) -> Error(InvalidField(field: field, expected: "List(String)"))
        Ok(values) -> strings_from_toml(values, field, [])
      }
  }
}

fn strings_from_toml(
  values: List(toml.Value),
  field: String,
  decoded: List(String),
) -> Result(List(String), Error) {
  case values {
    [] -> Ok(list.reverse(decoded))
    [value, ..rest] ->
      case toml.as_string(value) {
        Ok(value) -> strings_from_toml(rest, field, [value, ..decoded])
        Error(_) -> Error(InvalidField(field: field, expected: "List(String)"))
      }
  }
}
```

Note: `strings_from_toml` takes `List(toml.Value)`. Add `import tomlet.{type Value}` if you prefer `List(Value)`; using the re-exported `toml.Value` alias avoids a second import — but `toml` does not re-export the `Value` type. Therefore add `import tomlet.{type Value}` and write `List(Value)`.

- [ ] **Step 5: Adjust the `Value` type reference**

Add to the imports: `import tomlet.{type Value}` and change `strings_from_toml`'s
parameter type from `List(toml.Value)` to `List(Value)`.

- [ ] **Step 6: Confirm `gleam/dict` and `tom` are fully gone**

Run: `rg -n '\btom\.|type Toml|gleam/dict|dict\.' src/licence_audit/config.gleam`
Expected: no matches. (If `dict.` still appears, do not remove the `gleam/dict`
import; otherwise the removal in Step 2 is correct.)

- [ ] **Step 7: Run the parity tests**

Run: `gleam test`
Expected: PASS. In particular:
- `parse_errors_on_invalid_field_type_test` → `InvalidField("allow", "List(String)")`
- `parse_errors_on_invalid_vuln_severity_test` → `InvalidField("vuln_severity", "low|medium|high|critical")`
- `parse_rejects_bare_licence_audit_section_test` and `parse_rejects_legacy_licences_section_test` unchanged.

- [ ] **Step 8: Lint and commit**

```bash
gleam format && gleam check
git add src/licence_audit/config.gleam
git commit -m "refactor: parse policy from gleam.toml via toml facade instead of tom"
```

---

## Task 5: Migrate `licence_audit.gleam` off `tom`

**Files:**
- Modify: `src/licence_audit.gleam` (`read_root_component`, `tool_version`)

- [ ] **Step 1: Baseline**

Run: `gleam test`
Expected: PASS.

- [ ] **Step 2: Swap the import**

In `src/licence_audit.gleam`, replace `import tom` with `import licence_audit/toml`.
(Place it in alphabetical order among the `licence_audit/*` imports.)

- [ ] **Step 3: Rewrite `read_root_component`**

```gleam
fn read_root_component(project_root: String) -> sbom.RootComponent {
  let path = project_root <> "/gleam.toml"
  case simplifile.read(from: path) {
    Error(_) -> sbom.RootComponent(name: "project", version: "0.0.0")
    Ok(contents) ->
      case toml.parse(contents) {
        Error(_) -> sbom.RootComponent(name: "project", version: "0.0.0")
        Ok(doc) -> {
          let name = case toml.get_string(doc, ["name"]) {
            Ok(v) -> v
            Error(_) -> "project"
          }
          let version = case toml.get_string(doc, ["version"]) {
            Ok(v) -> v
            Error(_) -> "0.0.0"
          }
          sbom.RootComponent(name: name, version: version)
        }
      }
  }
}
```

- [ ] **Step 4: Rewrite `tool_version`**

```gleam
fn tool_version() -> String {
  case simplifile.read(from: "gleam.toml") {
    Error(_) -> "unknown"
    Ok(contents) ->
      case toml.parse(contents) {
        Error(_) -> "unknown"
        Ok(doc) ->
          case toml.get_string(doc, ["version"]) {
            Ok(v) -> v
            Error(_) -> "unknown"
          }
      }
  }
}
```

- [ ] **Step 5: Confirm no `tom.` references remain in the file**

Run: `rg -n '\btom\.' src/licence_audit.gleam`
Expected: no matches.

- [ ] **Step 6: Run tests + lint, commit**

```bash
gleam test && gleam format && gleam check
git add src/licence_audit.gleam
git commit -m "refactor: read root gleam.toml via toml facade instead of tom"
```

---

## Task 6: Drop the `tom` dependency

**Files:**
- Modify: `gleam.toml`

- [ ] **Step 1: Verify `tom` is unused across the source tree**

Run: `rg -n 'import tom\b|\btom\.' src/ test/`
Expected: no matches (only `tomlet` should appear, which `\btom\.` does not match).

- [ ] **Step 2: Remove the dependency line**

In `gleam.toml`, delete the line:

```toml
tom = ">= 2.1.0 and < 3.0.0"
```

- [ ] **Step 3: Refresh the lockfile and rebuild**

Run: `gleam deps download && gleam build`
Expected: builds cleanly; `manifest.toml` no longer lists `tom`.

- [ ] **Step 4: Confirm `tom` is gone from the project manifest**

Run: `rg -n '^tom ' gleam.toml; rg -n 'name = "tom"' manifest.toml`
Expected: no matches.

- [ ] **Step 5: Full suite + lint**

Run: `gleam test && gleam format --check && gleam check`
Expected: PASS, formatting clean, no warnings.

- [ ] **Step 6: Commit**

```bash
git add gleam.toml manifest.toml
git commit -m "build: drop tom dependency in favor of tomlet"
```

---

## Self-Review Notes (verification of this plan against the spec)

- **Spec coverage:** Rename (Task 1) ✓; facade read accessors incl. tomlet#22/#23 comments (Task 2) ✓; `manifest.gleam` migration + error-variant parity (Task 3) ✓; `config.gleam` migration + variant parity (Task 4) ✓; third consumer `licence_audit.gleam` (Task 5) ✓; drop `tom` (Task 6) ✓.
- **Parity harness:** every migration task runs the existing tests and names the exact error-asserting cases that lock behavior.
- **Type consistency:** facade names (`get_array`/`get_table`/`get_string`/`table_keys`/`field`/`as_string`/`as_array`/`as_table`, `Entry`, `ArrayError{ArrayMissing,ArrayNotArray}`, `TableLookupError{TableLookupMissing,TableLookupNotTable}`) are used identically across Tasks 2–5.
- **Behavior preserved:** decode order in `decode_package`/`decode_sbom_entry` is unchanged; `decode_direct_names` keeps the explicit sort; `read_root_component`/`tool_version` keep their default fallbacks.
