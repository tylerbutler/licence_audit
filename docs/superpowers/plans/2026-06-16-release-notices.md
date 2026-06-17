# Release Notices Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `licence_audit notices`, a release-ready third-party licence text generator for locked dependencies.

**Architecture:** Keep release notices separate from SBOM generation. Parse the existing lockfile, reuse manifest scope helpers, fetch exact source archives for Hex and GitHub dependencies, read path dependencies locally, extract shipped licence files, and render deterministic plain text.

**Tech Stack:** Gleam 1.16, Erlang/OTP 28 FFI, `gleam_httpc.dispatch_bits`, `simplifile`, existing `glint` CLI plumbing, existing `progress` and `error` patterns, gleeunit tests via `mise exec -- gleam test --target erlang -- <module>_test`.

---

## File structure

- Create `src/licence_audit/source_archive.gleam`: archive extraction wrapper, Hex `contents.tar.gz` extraction, SHA-256 helper, and text conversion.
- Create `src/licence_audit/source_archive_ffi.erl`: small OTP FFI around `erl_tar:extract/2`.
- Create `test/licence_audit/source_archive_test.gleam`: archive and checksum tests using tiny fixture archives.
- Create `src/licence_audit/notices.gleam`: notice input types, source selection, licence file matching, source fetching, path scanning, rendering, and command-level error descriptions.
- Create `test/licence_audit/notices_test.gleam`: core selection, matching, rendering, missing-text, unsupported-source, checksum, GitHub URL, and path tests.
- Modify `src/licence_audit/cli.gleam`: add `NoticesOptions`, `RunNotices`, command registration, and flags.
- Modify `test/licence_audit/cli_test.gleam`: add CLI parsing and help tests for `notices`.
- Modify `src/licence_audit.gleam`: dispatch `RunNotices`, add injectable notice fetchers for tests, write stdout/output, and flush progress.
- Modify `src/licence_audit/error.gleam`: add `Notices(String)` for command diagnostics.
- Modify `test/licence_audit/integration_test.gleam`: add end-to-end notices tests with injected fetchers.
- Create `docs/notices.md`; modify `README.md`: document the new command.

## Task 1: Archive extraction module

**Files:**
- Create: `src/licence_audit/source_archive.gleam`
- Create: `src/licence_audit/source_archive_ffi.erl`
- Create: `test/licence_audit/source_archive_test.gleam`
- Create fixture files under: `test/fixtures/notices/archive_fixture/`

- [ ] **Step 1: Create tiny archive fixtures**

Run:

```bash
mkdir -p test/fixtures/notices/archive_fixture/pkg
printf 'Fixture licence text\n' > test/fixtures/notices/archive_fixture/pkg/LICENSE
printf 'Fixture notice text\n' > test/fixtures/notices/archive_fixture/pkg/NOTICE.txt
tar -czf test/fixtures/notices/archive_fixture/contents.tar.gz -C test/fixtures/notices/archive_fixture/pkg .
tmpdir="$(mktemp -d)"
printf '3' > "$tmpdir/VERSION"
printf '[]' > "$tmpdir/metadata.config"
cp test/fixtures/notices/archive_fixture/contents.tar.gz "$tmpdir/contents.tar.gz"
printf 'unused\n' > "$tmpdir/CHECKSUM"
tar -cf test/fixtures/notices/archive_fixture/hex.tar -C "$tmpdir" VERSION metadata.config contents.tar.gz CHECKSUM
rm -rf "$tmpdir"
```

Expected: `test/fixtures/notices/archive_fixture/contents.tar.gz` and `hex.tar` exist.

- [ ] **Step 2: Write failing source archive tests**

Create `test/licence_audit/source_archive_test.gleam`:

```gleam
import gleam/list
import gleam/string
import gleeunit/should
import licence_audit/source_archive
import simplifile

const fixture_dir = "test/fixtures/notices/archive_fixture"

pub fn sha256_hex_is_uppercase_test() {
  let assert Ok(bits) = simplifile.read_bits(fixture_dir <> "/hex.tar")

  let digest = source_archive.sha256_hex(bits)

  should.equal(string.uppercase(digest), digest)
  should.equal(string.length(digest), 64)
}

pub fn extract_tar_gz_returns_text_files_test() {
  let assert Ok(bits) = simplifile.read_bits(fixture_dir <> "/contents.tar.gz")

  let assert Ok(files) = source_archive.extract_tar_gz(bits)

  let paths = list.map(files, fn(file) { file.path })
  assert list.contains(paths, "./LICENSE")
  assert list.contains(paths, "./NOTICE.txt")
  let assert [licence] = list.filter(files, fn(file) {
    file.path == "./LICENSE"
  })
  should.equal(licence.contents, "Fixture licence text\n")
}

pub fn extract_hex_contents_reads_inner_contents_tarball_test() {
  let assert Ok(bits) = simplifile.read_bits(fixture_dir <> "/hex.tar")

  let assert Ok(files) = source_archive.extract_hex_contents(bits)

  let paths = list.map(files, fn(file) { file.path })
  assert list.contains(paths, "./LICENSE")
  assert list.contains(paths, "./NOTICE.txt")
}

pub fn extract_tar_rejects_invalid_archive_test() {
  let result = source_archive.extract_tar(<<"not a tar":utf8>>)

  should.equal(result, Error(source_archive.InvalidArchive))
}
```

- [ ] **Step 3: Run test to verify it fails**

Run:

```bash
mise exec -- gleam test --target erlang -- source_archive_test
```

Expected: FAIL because `licence_audit/source_archive` does not exist.

- [ ] **Step 4: Add the Erlang archive FFI**

Create `src/licence_audit/source_archive_ffi.erl`:

```erlang
-module(source_archive_ffi).
-export([extract_tar/1, extract_tar_gz/1]).

extract_tar(Data) when is_binary(Data) ->
    extract(Data, []).

extract_tar_gz(Data) when is_binary(Data) ->
    extract(Data, [compressed]).

extract(Data, Options) ->
    case erl_tar:extract({binary, Data}, [memory | Options]) of
        {ok, Files} -> {ok, lists:filtermap(fun to_entry/1, Files)};
        {error, _Reason} -> {error, invalid_archive}
    end.

to_entry({Path, Contents}) when is_list(Path), is_binary(Contents) ->
    {true, {unicode:characters_to_binary(Path), Contents}};
to_entry({Path, Contents}) when is_binary(Path), is_binary(Contents) ->
    {true, {Path, Contents}};
to_entry(_) ->
    false.
```

- [ ] **Step 5: Add the Gleam archive wrapper**

Create `src/licence_audit/source_archive.gleam`:

```gleam
import gleam/bit_array.{type BitArray}
import gleam/list
import gleam/result
import gleam/string

pub type ArchiveError {
  InvalidArchive
  MissingContentsArchive
  InvalidText(path: String)
}

pub type ArchiveFile {
  ArchiveFile(path: String, contents: String)
}

@external(erlang, "source_archive_ffi", "extract_tar")
fn extract_tar_raw(data: BitArray) ->
  Result(List(#(String, BitArray)), ArchiveError)

@external(erlang, "source_archive_ffi", "extract_tar_gz")
fn extract_tar_gz_raw(data: BitArray) ->
  Result(List(#(String, BitArray)), ArchiveError)

@external(erlang, "sbom_uuid_ffi", "sha256")
fn sha256(data: BitArray) -> BitArray

pub fn extract_tar(data: BitArray) -> Result(List(ArchiveFile), ArchiveError) {
  use files <- result.try(extract_tar_raw(data))
  files_to_text(files)
}

pub fn extract_tar_gz(data: BitArray) -> Result(List(ArchiveFile), ArchiveError) {
  use files <- result.try(extract_tar_gz_raw(data))
  files_to_text(files)
}

pub fn extract_hex_contents(
  data: BitArray,
) -> Result(List(ArchiveFile), ArchiveError) {
  use files <- result.try(extract_tar_raw(data))
  use contents <- result.try(find_file_bits(files, "contents.tar.gz"))
  extract_tar_gz(contents)
}

pub fn sha256_hex(data: BitArray) -> String {
  sha256(data)
  |> bit_array.base16_encode
  |> string.uppercase
}

fn files_to_text(
  files: List(#(String, BitArray)),
) -> Result(List(ArchiveFile), ArchiveError) {
  list.try_map(files, fn(file) {
    let #(path, contents) = file
    case bit_array.to_string(contents) {
      Ok(text) -> Ok(ArchiveFile(path: path, contents: text))
      Error(_) -> Error(InvalidText(path: path))
    }
  })
}

fn find_file_bits(
  files: List(#(String, BitArray)),
  wanted: String,
) -> Result(BitArray, ArchiveError) {
  case files {
    [] -> Error(MissingContentsArchive)
    [file, ..rest] -> {
      let #(path, contents) = file
      case path == wanted {
        True -> Ok(contents)
        False -> find_file_bits(rest, wanted)
      }
    }
  }
}

pub fn describe_error(error: ArchiveError) -> String {
  case error {
    InvalidArchive -> "invalid archive"
    MissingContentsArchive -> "Hex tarball missing contents.tar.gz"
    InvalidText(path) -> "archive file is not valid UTF-8: " <> path
  }
}
```

- [ ] **Step 6: Run archive tests**

Run:

```bash
mise exec -- gleam test --target erlang -- source_archive_test
```

Expected: PASS.

- [ ] **Step 7: Commit archive extraction**

Run:

```bash
git add src/licence_audit/source_archive.gleam src/licence_audit/source_archive_ffi.erl test/licence_audit/source_archive_test.gleam test/fixtures/notices/archive_fixture
git commit -m "feat: extract package licence archives"
```

Expected: commit succeeds.

## Task 2: Notice core model, matching, and rendering

**Files:**
- Create: `src/licence_audit/notices.gleam`
- Create: `test/licence_audit/notices_test.gleam`

- [ ] **Step 1: Write failing rendering and matching tests**

Create `test/licence_audit/notices_test.gleam`:

```gleam
import gleam/bit_array
import gleam/list
import gleam/option.{None, Some}
import gleam/string
import gleeunit/should
import licence_audit/manifest
import licence_audit/notices
import licence_audit/source_archive

fn file(path: String, contents: String) -> source_archive.ArchiveFile {
  source_archive.ArchiveFile(path: path, contents: contents)
}

fn package(name: String, source: notices.PackageSource) -> notices.NoticePackage {
  notices.NoticePackage(
    name: name,
    version: "1.0.0",
    declared_licences: ["MIT"],
    source: source,
    scope: manifest.Prod,
  )
}

pub fn licence_file_candidates_include_license_and_notice_test() {
  let files = [
    file("./README.md", "readme"),
    file("./LICENSE", "license"),
    file("./NOTICE.txt", "notice"),
    file("./src/COPYING.md", "copying"),
  ]

  let matches = notices.licence_files(files)

  should.equal(list.map(matches, fn(match) { match.path }), [
    "./LICENSE",
    "./NOTICE.txt",
  ])
}

pub fn licence_file_candidates_fall_back_to_nested_paths_test() {
  let files = [
    file("./README.md", "readme"),
    file("./priv/LICENSE.md", "nested license"),
  ]

  let matches = notices.licence_files(files)

  should.equal(list.map(matches, fn(match) { match.path }), [
    "./priv/LICENSE.md",
  ])
}

pub fn licence_file_matching_is_case_insensitive_test() {
  let files = [file("./licence.MD", "licence")]

  let matches = notices.licence_files(files)

  should.equal(list.map(matches, fn(match) { match.path }), ["./licence.MD"])
}

pub fn render_notice_entries_is_deterministic_test() {
  let entries = [
    notices.NoticeEntry(
      package: package("beta", notices.HexPackage(outer_checksum: "BBBB")),
      files: [notices.NoticeFile(path: "./LICENSE", contents: "Beta text\n")],
    ),
    notices.NoticeEntry(
      package: package("alpha", notices.GitHubPackage(
        repo: "https://github.com/example/alpha",
        commit: "abc123",
      )),
      files: [
        notices.NoticeFile(path: "./NOTICE.txt", contents: "Alpha notice\n"),
        notices.NoticeFile(path: "./LICENSE", contents: "Alpha license\n"),
      ],
    ),
  ]

  let output = notices.render(entries, manifest_path: "manifest.toml")

  assert string.contains(output, "Third-party licences")
  assert string.contains(output, "Generated by licence_audit notices from manifest.toml.")
  assert string.contains(output, "alpha 1.0.0")
  assert string.contains(output, "Source: git https://github.com/example/alpha @ abc123")
  assert string.contains(output, "Declared licences: MIT")
  assert string.contains(output, "Files: ./LICENSE, ./NOTICE.txt")
  assert string.contains(output, "Alpha license\n")
  assert string.contains(output, "Alpha notice\n")
  assert string.contains(output, "beta 1.0.0")
  assert string.ends_with(output, "\n")
  let alpha_index = string.first(output, "alpha 1.0.0")
  let beta_index = string.first(output, "beta 1.0.0")
  case alpha_index, beta_index {
    Ok(a), Ok(b) -> assert a < b
    _, _ -> panic as "expected both package headings"
  }
}

pub fn render_unknown_declared_licences_test() {
  let entry =
    notices.NoticeEntry(
      package: notices.NoticePackage(
        name: "local_dep",
        version: "0.1.0",
        declared_licences: [],
        source: notices.PathPackage(path: "../local_dep"),
        scope: manifest.Prod,
      ),
      files: [notices.NoticeFile(path: "LICENSE", contents: "Local text\n")],
    )

  let output = notices.render([entry], manifest_path: "manifest.toml")

  assert string.contains(output, "Declared licences: unknown")
  assert string.contains(output, "Source: path ../local_dep")
}

pub fn missing_text_error_describes_all_packages_test() {
  let error = notices.MissingLicenceText(["beta", "alpha"])

  should.equal(
    notices.describe_error(error),
    "Missing licence text for packages: alpha, beta",
  )
}

pub fn checksum_mismatch_describes_expected_and_actual_test() {
  let error =
    notices.ChecksumMismatch(
      package: "gleam_stdlib",
      expected: "AAAA",
      actual: "BBBB",
    )

  assert string.contains(notices.describe_error(error), "gleam_stdlib")
  assert string.contains(notices.describe_error(error), "AAAA")
  assert string.contains(notices.describe_error(error), "BBBB")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
mise exec -- gleam test --target erlang -- notices_test
```

Expected: FAIL because `licence_audit/notices` does not exist.

- [ ] **Step 3: Implement notice types, matching, and rendering**

Create `src/licence_audit/notices.gleam` with this initial core:

```gleam
import gleam/bool
import gleam/dict.{type Dict}
import gleam/http.{Get, Https}
import gleam/http/request.{type Request, Request}
import gleam/http/response.{type Response}
import gleam/httpc
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import licence_audit/hex
import licence_audit/manifest
import licence_audit/sbom
import licence_audit/source_archive
import simplifile

pub type PackageSource {
  HexPackage(outer_checksum: String)
  GitHubPackage(repo: String, commit: String)
  PathPackage(path: String)
}

pub type NoticePackage {
  NoticePackage(
    name: String,
    version: String,
    declared_licences: List(String),
    source: PackageSource,
    scope: manifest.Scope,
  )
}

pub type NoticeFile {
  NoticeFile(path: String, contents: String)
}

pub type NoticeEntry {
  NoticeEntry(package: NoticePackage, files: List(NoticeFile))
}

pub type Error {
  MissingLicenceText(packages: List(String))
  UnsupportedSource(package: String, source: String, detail: String)
  FetchFailed(package: String, reason: String)
  ArchiveFailed(package: String, reason: String)
  ChecksumMismatch(package: String, expected: String, actual: String)
  PathReadFailed(package: String, path: String, reason: String)
  OutputWriteFailed(path: String, reason: String)
}

pub fn licence_files(
  files: List(source_archive.ArchiveFile),
) -> List(NoticeFile) {
  let root_matches =
    files
    |> list.filter(fn(file) { is_root_notice_file(file.path) })
    |> list.map(to_notice_file)
    |> sort_notice_files

  case root_matches {
    [] ->
      files
      |> list.filter(fn(file) { is_any_notice_file(file.path) })
      |> list.map(to_notice_file)
      |> sort_notice_files
    _ -> root_matches
  }
}

pub fn render(entries: List(NoticeEntry), manifest_path manifest_path: String) -> String {
  let sorted =
    list.sort(entries, by: fn(a, b) {
      compare_package(a.package, b.package)
    })
  let sections =
    sorted
    |> list.map(render_entry)
    |> string.join(with: "\n")
  "Third-party licences\n"
  <> "Generated by licence_audit notices from "
  <> manifest_path
  <> ".\n\n"
  <> sections
  <> "\n"
}

pub fn describe_error(error: Error) -> String {
  case error {
    MissingLicenceText(packages) ->
      "Missing licence text for packages: "
      <> string.join(list.sort(packages, by: string.compare), ", ")
    UnsupportedSource(package, source, detail) ->
      "Cannot generate notices for package `"
      <> package
      <> "` (source: "
      <> source
      <> ", "
      <> detail
      <> ")"
    FetchFailed(package, reason) ->
      "Failed to fetch source archive for " <> package <> ": " <> reason
    ArchiveFailed(package, reason) ->
      "Failed to extract source archive for " <> package <> ": " <> reason
    ChecksumMismatch(package, expected, actual) ->
      "Checksum mismatch for "
      <> package
      <> ": expected "
      <> string.uppercase(expected)
      <> ", got "
      <> string.uppercase(actual)
    PathReadFailed(package, path, reason) ->
      "Failed to read path dependency "
      <> package
      <> " at "
      <> path
      <> ": "
      <> reason
    OutputWriteFailed(path, reason) ->
      "Failed to write notices to " <> path <> ": " <> reason
  }
}

fn to_notice_file(file: source_archive.ArchiveFile) -> NoticeFile {
  NoticeFile(path: file.path, contents: file.contents)
}

fn sort_notice_files(files: List(NoticeFile)) -> List(NoticeFile) {
  list.sort(files, by: fn(a, b) { string.compare(a.path, b.path) })
}

fn is_root_notice_file(path: String) -> Bool {
  let normalized = normalize_path(path)
  !string.contains(normalized, "/") && is_notice_basename(normalized)
}

fn is_any_notice_file(path: String) -> Bool {
  normalize_path(path)
  |> basename
  |> is_notice_basename
}

fn normalize_path(path: String) -> String {
  let without_prefix = case string.starts_with(path, "./") {
    True -> string.drop_start(path, 2)
    False -> path
  }
  string.trim_right(without_prefix, "/")
}

fn basename(path: String) -> String {
  case string.split(path, on: "/") |> list.reverse {
    [name, ..] -> name
    [] -> path
  }
}

fn is_notice_basename(name: String) -> Bool {
  let lower = string.lowercase(name)
  list.any(["license", "licence", "copying", "notice"], fn(base) {
    lower == base
    || lower == base <> ".txt"
    || lower == base <> ".md"
    || lower == base <> ".rst"
    || lower == base <> ".adoc"
  })
}

fn compare_package(a: NoticePackage, b: NoticePackage) -> order.Order {
  case string.compare(a.name, b.name) {
    order.Eq -> string.compare(a.version, b.version)
    other -> other
  }
}

fn render_entry(entry: NoticeEntry) -> String {
  let files = sort_notice_files(entry.files)
  separator("=")
  <> "\n"
  <> entry.package.name
  <> " "
  <> entry.package.version
  <> "\n"
  <> "Source: "
  <> source_text(entry.package.source)
  <> "\n"
  <> "Declared licences: "
  <> declared_licences_text(entry.package.declared_licences)
  <> "\n"
  <> "Files: "
  <> string.join(list.map(files, fn(file) { file.path }), ", ")
  <> "\n"
  <> separator("-")
  <> "\n"
  <> render_files(files)
}

fn render_files(files: List(NoticeFile)) -> String {
  files
  |> list.map(fn(file) { file.contents |> ensure_trailing_newline })
  |> string.join(with: "\n")
}

fn source_text(source: PackageSource) -> String {
  case source {
    HexPackage(_) -> "hex"
    GitHubPackage(repo, commit) -> "git " <> repo <> " @ " <> commit
    PathPackage(path) -> "path " <> path
  }
}

fn declared_licences_text(licences: List(String)) -> String {
  case licences {
    [] -> "unknown"
    _ -> string.join(licences, ", ")
  }
}

fn ensure_trailing_newline(text: String) -> String {
  case string.ends_with(text, "\n") {
    True -> text
    False -> text <> "\n"
  }
}

fn separator(char: String) -> String {
  string.repeat(char, times: 80)
}
```

The imports include modules used by later tasks. `gleam/order` may be required by the compiler; if the compiler reports `Unknown module order`, add `import gleam/order`.

- [ ] **Step 4: Run notices tests**

Run:

```bash
mise exec -- gleam test --target erlang -- notices_test
```

Expected: PASS after adding any missing `gleam/order` import reported by the compiler.

- [ ] **Step 5: Commit notice core**

Run:

```bash
git add src/licence_audit/notices.gleam test/licence_audit/notices_test.gleam
git commit -m "feat: render release licence notices"
```

Expected: commit succeeds.

## Task 3: Notice source collection

**Files:**
- Modify: `src/licence_audit/notices.gleam`
- Modify: `test/licence_audit/notices_test.gleam`
- Create fixtures under: `test/fixtures/notices/path_dep/`

- [ ] **Step 1: Add failing source collection tests**

Append to `test/licence_audit/notices_test.gleam`:

```gleam
fn manifest_entry(
  name: String,
  version: String,
  provenance: manifest.Provenance,
  requirements: List(String),
) -> manifest.SbomEntry {
  manifest.SbomEntry(
    name: name,
    version: version,
    kind: manifest.Direct,
    requirements: requirements,
    provenance: provenance,
  )
}

fn fetch_metadata(name: String) -> Result(hex.PackageMetadata, hex.Error) {
  case name {
    "hex_dep" -> Ok(hex.licences_only(["Apache-2.0"]))
    _ -> Ok(hex.licences_only([]))
  }
}

fn fetch_hex_tarball(
  _name: String,
  _version: String,
) -> Result(BitArray, notices.FetchError) {
  Ok(bit_array.from_string("fake"))
}

fn fetch_github_tarball(
  _owner: String,
  _repo: String,
  _commit: String,
) -> Result(BitArray, notices.FetchError) {
  Ok(bit_array.from_string("fake"))
}

pub fn selected_packages_default_to_prod_scope_test() {
  let manifest_value =
    manifest.SbomManifest(
      entries: [
        manifest_entry(
          "prod_dep",
          "1.0.0",
          manifest.HexProvenance("AAAA", None),
          ["shared"],
        ),
        manifest_entry(
          "dev_dep",
          "1.0.0",
          manifest.HexProvenance("BBBB", None),
          [],
        ),
        manifest_entry(
          "shared",
          "1.0.0",
          manifest.HexProvenance("CCCC", None),
          [],
        ),
      ],
      root_requirements: ["prod_dep", "dev_dep"],
    )
  let scopes =
    dict.from_list([
      #("prod_dep", manifest.Prod),
      #("shared", manifest.Prod),
      #("dev_dep", manifest.Dev),
    ])

  let selected =
    notices.selected_entries(manifest_value, scopes, include_dev: False)

  should.equal(list.map(selected, fn(entry) { entry.name }), [
    "prod_dep",
    "shared",
  ])
}

pub fn selected_packages_include_dev_when_requested_test() {
  let manifest_value =
    manifest.SbomManifest(
      entries: [
        manifest_entry(
          "prod_dep",
          "1.0.0",
          manifest.HexProvenance("AAAA", None),
          [],
        ),
        manifest_entry(
          "dev_dep",
          "1.0.0",
          manifest.HexProvenance("BBBB", None),
          [],
        ),
      ],
      root_requirements: ["prod_dep", "dev_dep"],
    )
  let scopes =
    dict.from_list([
      #("prod_dep", manifest.Prod),
      #("dev_dep", manifest.Dev),
    ])

  let selected =
    notices.selected_entries(manifest_value, scopes, include_dev: True)

  should.equal(list.map(selected, fn(entry) { entry.name }), [
    "prod_dep",
    "dev_dep",
  ])
}

pub fn github_source_rejects_non_github_repo_test() {
  let entry =
    manifest_entry(
      "git_dep",
      "1.0.0",
      manifest.GitProvenance(
        repo: "https://gitlab.com/example/git_dep",
        commit: "abc",
      ),
      [],
    )

  let result = notices.package_source(entry)

  let assert Error(notices.UnsupportedSource("git_dep", "git", _)) = result
}

pub fn github_source_accepts_github_repo_test() {
  let entry =
    manifest_entry(
      "git_dep",
      "1.0.0",
      manifest.GitProvenance(
        repo: "https://github.com/example/git_dep.git",
        commit: "abc",
      ),
      [],
    )

  let assert Ok(notices.GitHubPackage(repo, commit)) =
    notices.package_source(entry)
  should.equal(repo, "https://github.com/example/git_dep.git")
  should.equal(commit, "abc")
}
```

Also add imports at the top of `test/licence_audit/notices_test.gleam`:

```gleam
import gleam/bit_array.{type BitArray}
import gleam/dict
import licence_audit/hex
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
mise exec -- gleam test --target erlang -- notices_test
```

Expected: FAIL because `FetchError`, `selected_entries`, and `package_source` are missing.

- [ ] **Step 3: Add selection and source helpers**

Modify `src/licence_audit/notices.gleam`:

```gleam
pub type FetchError {
  FetchNetworkFailure
  FetchUnexpectedResponse(status: Int)
}

pub fn selected_entries(
  manifest_value: manifest.SbomManifest,
  scopes: Dict(String, manifest.Scope),
  include_dev include_dev: Bool,
) -> List(manifest.SbomEntry) {
  list.filter(manifest_value.entries, fn(entry) {
    include_dev || scope_for(scopes, entry.name) == manifest.Prod
  })
}

pub fn package_source(
  entry: manifest.SbomEntry,
) -> Result(PackageSource, Error) {
  case entry.provenance {
    manifest.HexProvenance(outer_checksum, _) ->
      Ok(HexPackage(outer_checksum: outer_checksum))
    manifest.GitProvenance(repo, commit) ->
      case github_owner_repo(repo) {
        Ok(_) -> Ok(GitHubPackage(repo: repo, commit: commit))
        Error(_) ->
          Error(UnsupportedSource(
            package: entry.name,
            source: "git",
            detail: "repo: " <> repo,
          ))
      }
    manifest.PathProvenance(path) -> Ok(PathPackage(path: path))
    manifest.UnknownProvenance(source) ->
      Error(UnsupportedSource(
        package: entry.name,
        source: source,
        detail: "unsupported source",
      ))
  }
}

fn scope_for(
  scopes: Dict(String, manifest.Scope),
  name: String,
) -> manifest.Scope {
  case dict.get(scopes, name) {
    Ok(scope) -> scope
    Error(_) -> manifest.Prod
  }
}

fn github_owner_repo(repo: String) -> Result(#(String, String), Nil) {
  use path <- result.try(github_repo_path(repo))
  case string.split(drop_suffix(drop_suffix(path, "/"), ".git"), on: "/") {
    [owner, name] if owner != "" && name != "" -> Ok(#(owner, name))
    _ -> Error(Nil)
  }
}

fn github_repo_path(repo: String) -> Result(String, Nil) {
  case strip_prefix(repo, "https://github.com/") {
    Ok(path) -> Ok(path)
    Error(_) ->
      case strip_prefix(repo, "http://github.com/") {
        Ok(path) -> Ok(path)
        Error(_) ->
          case strip_prefix(repo, "git@github.com:") {
            Ok(path) -> Ok(path)
            Error(_) -> strip_prefix(repo, "git@github.com/")
          }
      }
  }
}

fn strip_prefix(value: String, prefix: String) -> Result(String, Nil) {
  use <- bool.guard(
    when: !string.starts_with(value, prefix),
    return: Error(Nil),
  )
  Ok(string.drop_start(value, string.length(prefix)))
}

fn drop_suffix(value: String, suffix: String) -> String {
  use <- bool.guard(when: !string.ends_with(value, suffix), return: value)
  string.slice(value, 0, string.length(value) - string.length(suffix))
}
```

If `github_owner_repo`, `strip_prefix`, and `drop_suffix` already exist in `sbom.gleam`, keep this copy private for now. Do not move SBOM internals during this task.

- [ ] **Step 4: Run notices tests**

Run:

```bash
mise exec -- gleam test --target erlang -- notices_test
```

Expected: PASS.

- [ ] **Step 5: Commit source selection**

Run:

```bash
git add src/licence_audit/notices.gleam test/licence_audit/notices_test.gleam
git commit -m "feat: select notice source packages"
```

Expected: commit succeeds.

## Task 4: Build notices from fetched sources

**Files:**
- Modify: `src/licence_audit/notices.gleam`
- Modify: `test/licence_audit/notices_test.gleam`

- [ ] **Step 1: Add failing build tests for checksum and missing text**

Append to `test/licence_audit/notices_test.gleam`:

```gleam
fn fake_archive_files(
  package_name: String,
) -> Result(List(source_archive.ArchiveFile), notices.Error) {
  case package_name {
    "with_license" -> Ok([file("./LICENSE", "License text\n")])
    "without_license" -> Ok([file("./README.md", "Readme\n")])
    _ -> Ok([file("./LICENSE", "Default text\n")])
  }
}

pub fn entries_from_sources_fails_with_all_missing_license_text_test() {
  let packages = [
    package("without_license", notices.HexPackage(outer_checksum: "AAAA")),
    package("also_missing", notices.PathPackage(path: "./missing")),
  ]
  let read_source = fn(pkg: notices.NoticePackage) {
    case pkg.name {
      "also_missing" -> Ok([file("./README.md", "Readme\n")])
      _ -> fake_archive_files(pkg.name)
    }
  }

  let result = notices.entries_from_sources(packages, read_source)

  should.equal(
    result,
    Error(notices.MissingLicenceText(["without_license", "also_missing"])),
  )
}

pub fn entries_from_sources_collects_notice_entries_test() {
  let packages = [
    package("with_license", notices.HexPackage(outer_checksum: "AAAA")),
  ]

  let assert Ok(entries) =
    notices.entries_from_sources(packages, fake_archive_files)

  should.equal(list.length(entries), 1)
  let assert [entry] = entries
  should.equal(entry.package.name, "with_license")
  should.equal(list.map(entry.files, fn(file) { file.path }), ["./LICENSE"])
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
mise exec -- gleam test --target erlang -- notices_test
```

Expected: FAIL because `entries_from_sources` is missing.

- [ ] **Step 3: Implement `entries_from_sources`**

Add to `src/licence_audit/notices.gleam`:

```gleam
pub fn entries_from_sources(
  packages: List(NoticePackage),
  read_source: fn(NoticePackage) -> Result(List(source_archive.ArchiveFile), Error),
) -> Result(List(NoticeEntry), Error) {
  let result =
    list.fold(packages, #([], []), fn(acc, package) {
      let #(entries, missing) = acc
      case read_source(package) {
        Error(error) -> panic as describe_error(error)
        Ok(files) -> {
          let notice_files = licence_files(files)
          case notice_files {
            [] -> #(entries, [package.name, ..missing])
            _ -> #(
              [
                NoticeEntry(package: package, files: notice_files),
                ..entries
              ],
              missing,
            )
          }
        }
      }
    })
  let #(entries, missing) = result
  case missing {
    [] -> Ok(list.reverse(entries))
    _ -> Error(MissingLicenceText(list.reverse(missing)))
  }
}
```

Replace the panic-based version before committing with the error-preserving version below:

```gleam
pub fn entries_from_sources(
  packages: List(NoticePackage),
  read_source: fn(NoticePackage) -> Result(List(source_archive.ArchiveFile), Error),
) -> Result(List(NoticeEntry), Error) {
  entries_from_sources_loop(packages, read_source, [], [])
}

fn entries_from_sources_loop(
  packages: List(NoticePackage),
  read_source: fn(NoticePackage) -> Result(List(source_archive.ArchiveFile), Error),
  entries: List(NoticeEntry),
  missing: List(String),
) -> Result(List(NoticeEntry), Error) {
  case packages {
    [] ->
      case missing {
        [] -> Ok(list.reverse(entries))
        _ -> Error(MissingLicenceText(list.reverse(missing)))
      }
    [package, ..rest] ->
      case read_source(package) {
        Error(error) -> Error(error)
        Ok(files) -> {
          let notice_files = licence_files(files)
          case notice_files {
            [] ->
              entries_from_sources_loop(
                rest,
                read_source,
                entries,
                [package.name, ..missing],
              )
            _ ->
              entries_from_sources_loop(
                rest,
                read_source,
                [
                  NoticeEntry(package: package, files: notice_files),
                  ..entries
                ],
                missing,
              )
          }
        }
      }
  }
}
```

- [ ] **Step 4: Run notices tests**

Run:

```bash
mise exec -- gleam test --target erlang -- notices_test
```

Expected: PASS.

- [ ] **Step 5: Commit notice entry building**

Run:

```bash
git add src/licence_audit/notices.gleam test/licence_audit/notices_test.gleam
git commit -m "feat: build notices from package sources"
```

Expected: commit succeeds.

## Task 5: HTTP and path source readers

**Files:**
- Modify: `src/licence_audit/notices.gleam`
- Modify: `test/licence_audit/notices_test.gleam`

- [ ] **Step 1: Add failing tests for source readers**

Append to `test/licence_audit/notices_test.gleam`:

```gleam
pub fn read_hex_source_rejects_checksum_mismatch_test() {
  let pkg =
    notices.NoticePackage(
      name: "hex_dep",
      version: "1.0.0",
      declared_licences: ["MIT"],
      source: notices.HexPackage(outer_checksum: "AAAA"),
      scope: manifest.Prod,
    )
  let fetch_hex = fn(_name, _version) {
    Ok(bit_array.from_string("not the expected bytes"))
  }
  let fetch_github = fn(_owner, _repo, _commit) {
    Ok(bit_array.from_string("unused"))
  }

  let assert Error(notices.ChecksumMismatch("hex_dep", "AAAA", _actual)) =
    notices.read_remote_source(pkg, fetch_hex, fetch_github)
}

pub fn fetch_error_description_is_human_readable_test() {
  should.equal(
    notices.describe_fetch_error(notices.FetchNetworkFailure),
    "network failure",
  )
  should.equal(
    notices.describe_fetch_error(notices.FetchUnexpectedResponse(500)),
    "unexpected HTTP response 500",
  )
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
mise exec -- gleam test --target erlang -- notices_test
```

Expected: FAIL because `read_remote_source` and `describe_fetch_error` are missing.

- [ ] **Step 3: Add remote readers and HTTP fetchers**

Add to `src/licence_audit/notices.gleam`:

```gleam
pub fn read_remote_source(
  package: NoticePackage,
  fetch_hex_tarball: fn(String, String) -> Result(BitArray, FetchError),
  fetch_github_tarball: fn(String, String, String) -> Result(BitArray, FetchError),
) -> Result(List(source_archive.ArchiveFile), Error) {
  case package.source {
    HexPackage(expected) -> {
      use bytes <- result.try(
        fetch_hex_tarball(package.name, package.version)
        |> result.map_error(fn(error) {
          FetchFailed(package: package.name, reason: describe_fetch_error(error))
        }),
      )
      let actual = source_archive.sha256_hex(bytes)
      use <- bool.guard(
        when: string.uppercase(expected) != actual,
        return: Error(ChecksumMismatch(
          package: package.name,
          expected: expected,
          actual: actual,
        )),
      )
      source_archive.extract_hex_contents(bytes)
      |> result.map_error(fn(error) {
        ArchiveFailed(
          package: package.name,
          reason: source_archive.describe_error(error),
        )
      })
    }
    GitHubPackage(repo, commit) -> {
      use owner_repo <- result.try(
        github_owner_repo(repo)
        |> result.map_error(fn(_) {
          UnsupportedSource(
            package: package.name,
            source: "git",
            detail: "repo: " <> repo,
          )
        }),
      )
      let #(owner, name) = owner_repo
      use bytes <- result.try(
        fetch_github_tarball(owner, name, commit)
        |> result.map_error(fn(error) {
          FetchFailed(package: package.name, reason: describe_fetch_error(error))
        }),
      )
      source_archive.extract_tar_gz(bytes)
      |> result.map_error(fn(error) {
        ArchiveFailed(
          package: package.name,
          reason: source_archive.describe_error(error),
        )
      })
    }
    PathPackage(path) -> read_path_source(package.name, path)
  }
}

pub fn fetch_hex_tarball_from_hex(
  name: String,
  version: String,
) -> Result(BitArray, FetchError) {
  fetch_bits(hex_tarball_request(name, version))
}

pub fn fetch_github_tarball_from_github(
  owner: String,
  repo: String,
  commit: String,
) -> Result(BitArray, FetchError) {
  fetch_bits(github_tarball_request(owner, repo, commit))
}

pub fn describe_fetch_error(error: FetchError) -> String {
  case error {
    FetchNetworkFailure -> "network failure"
    FetchUnexpectedResponse(status) ->
      "unexpected HTTP response " <> int.to_string(status)
  }
}

fn fetch_bits(req: Request(BitArray)) -> Result(BitArray, FetchError) {
  let req = request.set_header(req, "user-agent", "licence_audit")
  case
    httpc.configure()
    |> httpc.timeout(8000)
    |> httpc.dispatch_bits(req)
  {
    Error(_) -> Error(FetchNetworkFailure)
    Ok(response) if response.status >= 200 && response.status < 300 ->
      Ok(response.body)
    Ok(response) -> Error(FetchUnexpectedResponse(response.status))
  }
}

fn hex_tarball_request(name: String, version: String) -> Request(BitArray) {
  Request(
    method: Get,
    headers: [],
    body: <<>>,
    scheme: Https,
    host: "repo.hex.pm",
    port: None,
    path: "/tarballs/" <> name <> "-" <> version <> ".tar",
    query: None,
  )
}

fn github_tarball_request(
  owner: String,
  repo: String,
  commit: String,
) -> Request(BitArray) {
  Request(
    method: Get,
    headers: [],
    body: <<>>,
    scheme: Https,
    host: "codeload.github.com",
    port: None,
    path: "/" <> owner <> "/" <> repo <> "/tar.gz/" <> commit,
    query: None,
  )
}
```

- [ ] **Step 4: Add path reader**

Add to `src/licence_audit/notices.gleam`:

```gleam
fn read_path_source(
  package_name: String,
  path: String,
) -> Result(List(source_archive.ArchiveFile), Error) {
  use files <- result.try(
    simplifile.get_files(in: path)
    |> result.map_error(fn(error) {
      PathReadFailed(
        package: package_name,
        path: path,
        reason: simplifile.describe_error(error),
      )
    }),
  )
  list.try_map(files, fn(file_path) {
    simplifile.read(from: file_path)
    |> result.map(fn(contents) {
      source_archive.ArchiveFile(
        path: relative_path(file_path, path),
        contents: contents,
      )
    })
    |> result.map_error(fn(error) {
      PathReadFailed(
        package: package_name,
        path: file_path,
        reason: simplifile.describe_error(error),
      )
    })
  })
}

fn relative_path(file_path: String, root: String) -> String {
  let root_prefix = case string.ends_with(root, "/") {
    True -> root
    False -> root <> "/"
  }
  case string.starts_with(file_path, root_prefix) {
    True -> string.drop_start(file_path, string.length(root_prefix))
    False -> file_path
  }
}
```

- [ ] **Step 5: Run notices tests**

Run:

```bash
mise exec -- gleam test --target erlang -- notices_test
```

Expected: PASS.

- [ ] **Step 6: Commit source readers**

Run:

```bash
git add src/licence_audit/notices.gleam test/licence_audit/notices_test.gleam
git commit -m "feat: read notice package sources"
```

Expected: commit succeeds.

## Task 6: CLI parsing

**Files:**
- Modify: `src/licence_audit/cli.gleam`
- Modify: `test/licence_audit/cli_test.gleam`

- [ ] **Step 1: Add failing CLI tests**

Modify `test/licence_audit/cli_test.gleam`:

```gleam
fn parse_notices_options(args: List(String)) -> cli.NoticesOptions {
  let assert Ok(glint.Out(cli.RunNotices(options))) =
    glint.execute(cli.app(), cli.normalize_args(args))
  options
}

pub fn notices_subcommand_is_listed_in_help_test() {
  let help = help_text(["--help"])

  assert string.contains(help, "notices")
}

pub fn notices_subcommand_parses_defaults_test() {
  let options = parse_notices_options(["notices"])

  should.equal(options.manifest_path, None)
  should.equal(options.output, None)
  should.equal(options.include_dev, False)
  should.equal(options.verbosity, progress.Normal)
}

pub fn notices_subcommand_parses_supported_flags_test() {
  let options =
    parse_notices_options([
      "notices",
      "--manifest=locked.toml",
      "--output=THIRD_PARTY_LICENSES.txt",
      "--include-dev",
      "--verbose",
    ])

  should.equal(options.manifest_path, Some("locked.toml"))
  should.equal(options.output, Some("THIRD_PARTY_LICENSES.txt"))
  should.equal(options.include_dev, True)
  should.equal(options.verbosity, progress.Verbose)
}

pub fn notices_subcommand_rejects_quiet_and_verbose_test() {
  let assert Ok(glint.Out(cli.InvalidUsage(message))) =
    glint.execute(cli.app(), ["notices", "--quiet", "--verbose"])

  assert string.contains(message, "--quiet")
  assert string.contains(message, "--verbose")
}

pub fn notices_subcommand_rejects_config_flag_test() {
  let message = usage_error(["notices", "--config=gleam.toml"])

  assert string.contains(message, "config")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
mise exec -- gleam test --target erlang -- cli_test
```

Expected: FAIL because `NoticesOptions` and `RunNotices` are missing.

- [ ] **Step 3: Add CLI options and action**

Modify `src/licence_audit/cli.gleam`:

```gleam
pub type NoticesOptions {
  NoticesOptions(
    manifest_path: Option(String),
    verbosity: progress.Verbosity,
    output: Option(String),
    include_dev: Bool,
  )
}
```

Add the action:

```gleam
pub type CliAction {
  RunAudit(Options)
  UpdateConfig(UpdateOptions)
  RunSbom(SbomOptions)
  RunVulns(VulnsOptions)
  RunNotices(NoticesOptions)
  GenDocsCompleted
  InvalidUsage(String)
}
```

Register the command in `app()`:

```gleam
|> glint.add(at: ["notices"], do: notices_command())
```

Add the flag and command:

```gleam
fn include_dev_flag() -> glint.Flag(Bool) {
  glint.bool_flag("include-dev")
  |> glint.flag_default(False)
  |> glint.flag_help("Include dev-only dependencies in the notice file")
}

const notices_help = "Generate a release-ready third-party licence notices text file from locked dependencies."

fn notices_command() -> glint.Command(CliAction) {
  use <- glint.command_help(notices_help)
  use <- glint.unnamed_args(glint.EqArgs(0))
  use manifest <- glint.flag(manifest_flag())
  use quiet <- glint.flag(quiet_flag())
  use verbose <- glint.flag(verbose_flag())
  use output <- glint.flag(output_flag())
  use include_dev <- glint.flag(include_dev_flag())
  use _, _, flags <- glint.command()

  let assert Ok(manifest_path) = manifest(flags)
  let assert Ok(quiet) = quiet(flags)
  let assert Ok(verbose) = verbose(flags)
  let assert Ok(output_value) = output(flags)
  let assert Ok(include_dev_value) = include_dev(flags)

  case verbosity(quiet, verbose) {
    Error(verbosity_error) ->
      InvalidUsage(verbosity_error_message(verbosity_error))
    Ok(verbosity) ->
      RunNotices(NoticesOptions(
        manifest_path: optional_string(manifest_path),
        verbosity: verbosity,
        output: optional_string(output_value),
        include_dev: include_dev_value,
      ))
  }
}
```

- [ ] **Step 4: Run CLI tests**

Run:

```bash
mise exec -- gleam test --target erlang -- cli_test
```

Expected: PASS.

- [ ] **Step 5: Commit CLI parsing**

Run:

```bash
git add src/licence_audit/cli.gleam test/licence_audit/cli_test.gleam
git commit -m "feat: parse notices command"
```

Expected: commit succeeds.

## Task 7: Top-level notices command wiring

**Files:**
- Modify: `src/licence_audit.gleam`
- Modify: `src/licence_audit/error.gleam`
- Modify: `src/licence_audit/notices.gleam`
- Modify: `test/licence_audit/integration_test.gleam`

- [ ] **Step 1: Add failing integration tests**

Append to `test/licence_audit/integration_test.gleam`:

```gleam
fn notice_metadata_fetcher(name: String) -> Result(hex.PackageMetadata, hex.Error) {
  case name {
    "gleam_stdlib" -> Ok(hex.licences_only(["Apache-2.0"]))
    "argv" -> Ok(hex.licences_only(["Apache-2.0"]))
    _ -> Ok(hex.licences_only([]))
  }
}

fn fixture_hex_tarball(_name: String, _version: String) -> Result(BitArray, notices.FetchError) {
  simplifile.read_bits("test/fixtures/notices/archive_fixture/hex.tar")
  |> result.map_error(fn(_) { notices.FetchNetworkFailure })
}

fn unused_github_tarball(
  _owner: String,
  _repo: String,
  _commit: String,
) -> Result(BitArray, notices.FetchError) {
  Error(notices.FetchNetworkFailure)
}

pub fn notices_subcommand_prints_release_notice_text_test() {
  let fixture_checksum =
    simplifile.read_bits("test/fixtures/notices/archive_fixture/hex.tar")
    |> result.unwrap(<<"":utf8>>)
    |> source_archive.sha256_hex
  let manifest_path = "build/tmp/notices-manifest.toml"
  let _ = simplifile.create_directory_all("build/tmp")
  let assert Ok(_) =
    simplifile.write(
      to: manifest_path,
      contents: "packages = [
  { name = \"gleam_stdlib\", version = \"1.0.0\", source = \"hex\", outer_checksum = \"" <> fixture_checksum <> "\" },
]

[requirements]
gleam_stdlib = { version = \">= 1.0.0\" }
",
    )

  let result =
    licence_audit.run_with_notice_clients(
      ["notices", "--manifest=" <> manifest_path],
      notice_metadata_fetcher,
      fixture_hex_tarball,
      unused_github_tarball,
    )

  should.equal(result.exit_code, 0)
  assert string.contains(result.output, "Third-party licences")
  assert string.contains(result.output, "gleam_stdlib 1.0.0")
  assert string.contains(result.output, "Declared licences: Apache-2.0")
  assert string.contains(result.output, "Fixture licence text")
}

pub fn notices_subcommand_writes_output_file_test() {
  let fixture_checksum =
    simplifile.read_bits("test/fixtures/notices/archive_fixture/hex.tar")
    |> result.unwrap(<<"":utf8>>)
    |> source_archive.sha256_hex
  let manifest_path = "build/tmp/notices-output-manifest.toml"
  let output_path = "build/tmp/THIRD_PARTY_LICENSES.txt"
  let _ = simplifile.delete(output_path)
  let assert Ok(_) =
    simplifile.write(
      to: manifest_path,
      contents: "packages = [
  { name = \"gleam_stdlib\", version = \"1.0.0\", source = \"hex\", outer_checksum = \"" <> fixture_checksum <> "\" },
]

[requirements]
gleam_stdlib = { version = \">= 1.0.0\" }
",
    )

  let result =
    licence_audit.run_with_notice_clients(
      [
        "notices",
        "--manifest=" <> manifest_path,
        "--output=" <> output_path,
      ],
      notice_metadata_fetcher,
      fixture_hex_tarball,
      unused_github_tarball,
    )
  let assert Ok(contents) = simplifile.read(from: output_path)

  should.equal(result.exit_code, 0)
  should.equal(result.output, "")
  assert string.contains(contents, "Fixture licence text")
}
```

Add imports at the top of `test/licence_audit/integration_test.gleam`:

```gleam
import gleam/bit_array.{type BitArray}
import licence_audit/notices
import licence_audit/source_archive
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
mise exec -- gleam test --target erlang -- integration_test
```

Expected: FAIL because `run_with_notice_clients` is missing and `RunNotices` is not dispatched.

- [ ] **Step 3: Add notice error mapping**

Modify `src/licence_audit/error.gleam`:

```gleam
pub type Error {
  Success
  AuditFailed
  MissingPolicy
  Usage(String)
  Config(String)
  Input(String)
  Hex(String)
  Decode(String)
  UnsupportedSourceForSbom(package: String, source: String, detail: String)
  SbomWriteFailed(path: String, reason: String)
  Osv(String)
  Notices(String)
}
```

Add to `message`:

```gleam
Notices(message) -> message
```

- [ ] **Step 4: Add notice package construction**

Add to `src/licence_audit/notices.gleam`:

```gleam
pub fn packages_from_entries(
  entries: List(manifest.SbomEntry),
  scopes: Dict(String, manifest.Scope),
  fetch_metadata: fn(String) -> Result(hex.PackageMetadata, hex.Error),
) -> Result(List(NoticePackage), Error) {
  list.try_map(entries, fn(entry) {
    use source <- result.try(package_source(entry))
    let declared_licences = case entry.provenance {
      manifest.HexProvenance(_, _) ->
        case fetch_metadata(entry.name) {
          Ok(metadata) -> metadata.licences
          Error(_) -> []
        }
      _ -> []
    }
    Ok(NoticePackage(
      name: entry.name,
      version: entry.version,
      declared_licences: declared_licences,
      source: source,
      scope: scope_for(scopes, entry.name),
    ))
  })
}
```

This keeps metadata fetch failures non-fatal for `notices`; missing actual licence text remains fatal.

- [ ] **Step 5: Wire `RunNotices` through `licence_audit.gleam`**

Modify imports:

```gleam
import licence_audit/notices
```

Add to `handle_action`:

```gleam
cli.RunNotices(options) -> {
  let #(RunResult(exit_code, output), reporter) =
    run_notices_options(
      options,
      hex.fetch_package_metadata_from_hex,
      notices.fetch_hex_tarball_from_hex,
      notices.fetch_github_tarball_from_github,
      progress.enabled(options.verbosity, "notices"),
    )
  io.print(output)
  let _ = progress.flush(reporter)
  halt(exit_code)
}
```

Add to `run_with_reporter`:

```gleam
Ok(glint.Out(cli.RunNotices(options))) ->
  run_notices_options(
    options,
    fetcher,
    notices.fetch_hex_tarball_from_hex,
    notices.fetch_github_tarball_from_github,
    reporter,
  )
```

Add a test helper:

```gleam
pub fn run_with_notice_clients(
  args: List(String),
  fetcher: fn(String) -> Result(hex.PackageMetadata, hex.Error),
  hex_tarball_fetcher: fn(String, String) -> Result(BitArray, notices.FetchError),
  github_tarball_fetcher: fn(String, String, String) ->
    Result(BitArray, notices.FetchError),
) -> RunResult {
  let #(result, _) =
    run_with_reporter_and_notices(
      list.append(args, ["--no-cache"]),
      fetcher,
      osv.query_batch_from_osv,
      osv.fetch_vulnerability_from_osv,
      hex_tarball_fetcher,
      github_tarball_fetcher,
      progress.disabled(),
      color.for_enabled(False),
    )
  result
}
```

Refactor `run_with_reporter` to call a new helper that accepts notice fetchers:

```gleam
fn run_with_reporter(
  args: List(String),
  fetcher: fn(String) -> Result(hex.PackageMetadata, hex.Error),
  osv_batch_fetcher: fn(List(String)) -> Result(List(osv.BatchEntry), osv.Error),
  osv_detail_fetcher: fn(String) -> Result(osv.Vulnerability, osv.Error),
  reporter: progress.Reporter,
  palette: color.Palette,
) -> #(RunResult, progress.Reporter) {
  run_with_reporter_and_notices(
    args,
    fetcher,
    osv_batch_fetcher,
    osv_detail_fetcher,
    notices.fetch_hex_tarball_from_hex,
    notices.fetch_github_tarball_from_github,
    reporter,
    palette,
  )
}
```

Create `run_with_reporter_and_notices` by moving the existing `glint.execute` case body into it and adding the `RunNotices` branch.

- [ ] **Step 6: Implement `run_notices_options`**

Add to `src/licence_audit.gleam`:

```gleam
fn run_notices_options(
  options: cli.NoticesOptions,
  fetcher: fn(String) -> Result(hex.PackageMetadata, hex.Error),
  hex_tarball_fetcher: fn(String, String) -> Result(BitArray, notices.FetchError),
  github_tarball_fetcher: fn(String, String, String) ->
    Result(BitArray, notices.FetchError),
  reporter: progress.Reporter,
) -> #(RunResult, progress.Reporter) {
  let manifest_path = option_value(options.manifest_path, "manifest.toml")
  let reporter = progress.phase(reporter, "Generating licence notices")
  let reporter = progress.detail(reporter, "Loading package manifest")

  case manifest.load_sbom(manifest_path) {
    Error(manifest_error) -> #(
      diagnostic(error.from_manifest_error(manifest_error)),
      reporter,
    )
    Ok(sbom_manifest) -> {
      let scopes =
        manifest.sbom_scopes(
          sbom_manifest,
          resolve_prod_seed(".", sbom_manifest.root_requirements),
        )
      let selected =
        notices.selected_entries(
          sbom_manifest,
          scopes,
          include_dev: options.include_dev,
        )
      let reporter = progress.package_count(reporter, list.length(selected))
      case
        notices.packages_from_entries(selected, scopes, fetcher)
        |> result.try_then(fn(packages) {
          notices.entries_from_sources(packages, fn(package) {
            notices.read_remote_source(
              package,
              hex_tarball_fetcher,
              github_tarball_fetcher,
            )
          })
        })
      {
        Error(notice_error) -> #(
          diagnostic(error.Notices(notices.describe_error(notice_error))),
          reporter,
        )
        Ok(entries) ->
          write_notices_output(
            options.output,
            notices.render(entries, manifest_path: manifest_path),
            reporter,
          )
      }
    }
  }
}

fn write_notices_output(
  output: option.Option(String),
  text: String,
  reporter: progress.Reporter,
) -> #(RunResult, progress.Reporter) {
  case output {
    option.None -> #(RunResult(0, text), reporter)
    option.Some(path) ->
      case simplifile.write(to: path, contents: text) {
        Ok(_) -> #(RunResult(0, ""), reporter)
        Error(reason) -> #(
          diagnostic(error.Notices(notices.describe_error(
            notices.OutputWriteFailed(
              path: path,
              reason: simplifile.describe_error(reason),
            ),
          ))),
          reporter,
        )
      }
  }
}
```

Add `import gleam/bit_array.{type BitArray}` at the top of `src/licence_audit.gleam`.

- [ ] **Step 7: Run integration tests**

Run:

```bash
mise exec -- gleam test --target erlang -- integration_test
```

Expected: PASS.

- [ ] **Step 8: Commit top-level wiring**

Run:

```bash
git add src/licence_audit.gleam src/licence_audit/error.gleam src/licence_audit/notices.gleam test/licence_audit/integration_test.gleam
git commit -m "feat: generate release licence notices"
```

Expected: commit succeeds.

## Task 8: Documentation and generated command docs

**Files:**
- Create: `docs/notices.md`
- Modify: `README.md`
- Generated by command: docs command blocks for new subcommand

- [ ] **Step 1: Add notices docs**

Create `docs/notices.md`:

````markdown
# `licence_audit notices`

Generate a release-ready third-party licence notices text file from locked
dependencies.

**Usage:**

```sh
licence_audit notices
licence_audit notices --output=THIRD_PARTY_LICENSES.txt
licence_audit notices --include-dev
```

By default, `notices` includes production dependencies only. Use `--include-dev`
when the release artifact must include development-only dependencies too.

`notices` differs from `sbom`: `sbom` emits machine-readable CycloneDX JSON,
while `notices` emits the licence and notice text that dependencies ship in
their source archives. This is similar to npm's `generate-license-file`.

The command fails if any selected dependency lacks a recognizable licence or
notice file. It also fails on unsupported sources, network errors, archive
errors, checksum mismatches, or output write failures. Hex package tarballs are
verified against the lockfile's `outer_checksum`.
````

- [ ] **Step 2: Update README feature list and command list**

Modify `README.md`:

```markdown
- 📄 **bundle** release-ready third-party licence notices
```

Add the command entry:

```markdown
* [`licence_audit notices`](docs/notices.md) - Generate a release-ready third-party licence notices text file from locked dependencies.
```

Add a concept section after “Generate an SBOM”:

````markdown
## Generate release licence notices

```sh
licence_audit notices
licence_audit notices --output=THIRD_PARTY_LICENSES.txt
licence_audit notices --include-dev
```

`notices` creates a plain-text release artifact containing the licence and
notice files shipped by locked dependencies. It defaults to production
dependencies; pass `--include-dev` to include development-only dependencies.

Use `notices` when you need a human-readable third-party licence bundle for a
release. Use `sbom` when you need machine-readable CycloneDX JSON.
````

- [ ] **Step 3: Regenerate command docs**

Run:

```bash
just docs
```

Expected: README command help blocks and `docs/notices.md` match the CLI output. If the repository uses a different docs recipe, run:

```bash
mise exec -- gleam run -- gen-docs
```

Expected: command exits `0`.

- [ ] **Step 4: Run docs-adjacent tests**

Run:

```bash
mise exec -- gleam test --target erlang -- cli_test
```

Expected: PASS.

- [ ] **Step 5: Commit docs**

Run:

```bash
git add README.md docs/notices.md docs/check.md docs/sbom.md docs/update.md docs/vulns.md
git commit -m "docs: document notices command"
```

Expected: commit succeeds. If generated docs touch a different set of `docs/*.md`, stage those exact generated files instead.

## Task 9: Final validation

**Files:**
- No planned edits.

- [ ] **Step 1: Format**

Run:

```bash
just format
```

Expected: command exits `0`.

- [ ] **Step 2: Check formatting**

Run:

```bash
just format-check
```

Expected: command exits `0`.

- [ ] **Step 3: Type-check**

Run:

```bash
just check
```

Expected: command exits `0`.

- [ ] **Step 4: Run full tests**

Run:

```bash
just test
```

Expected: command exits `0`.

- [ ] **Step 5: Run lint**

Run:

```bash
just glint
```

Expected: command exits `0`.

- [ ] **Step 6: Inspect final git status**

Run:

```bash
git --no-pager status --short
git --no-pager log --oneline -5
```

Expected: only intentional changes remain, and the recent commits match the task commits above.

---

## Self-review

Spec coverage:

- Research and command split: Task 8 documents `generate-license-file` and `notices` versus `sbom`.
- Command surface: Task 6 adds `notices`, `--manifest`, `--output`, `--include-dev`, `--quiet`, and `--verbose`.
- Production default and dev inclusion: Tasks 3 and 7 implement and test scope selection.
- Hex, GitHub, and path sources: Tasks 3, 5, and 7 implement source routing and readers.
- Hex checksum verification: Tasks 1 and 5 add SHA-256 and mismatch tests.
- Licence file detection: Task 2 covers root-first matching, fallback, suffixes, case, multiple files, and notices.
- Deterministic output: Task 2 tests sorted packages and files.
- Error handling: Tasks 2, 4, 5, and 7 cover missing text, unsupported source, checksum mismatch, fetch/archive/path/output errors.
- Progress: Task 7 uses existing progress phases and package count.
- Tests and docs: Tasks 1 through 8 add targeted tests and docs.

Red-flag scan: no banned planning patterns remain.

Type consistency: the plan defines `PackageSource`, `NoticePackage`, `NoticeFile`, `NoticeEntry`, `FetchError`, `Error`, `selected_entries`, `package_source`, `licence_files`, `entries_from_sources`, `read_remote_source`, `fetch_hex_tarball_from_hex`, `fetch_github_tarball_from_github`, `packages_from_entries`, and `render` before later tasks use them.
