import gleam/bit_array
import gleam/dict
import gleam/list
import gleam/option.{None}
import gleam/string
import gleeunit/should
import licence_audit/manifest
import licence_audit/notices
import licence_audit/source_archive

fn file(path: String, contents: String) -> source_archive.ArchiveFile {
  source_archive.ArchiveFile(
    path: path,
    contents: bit_array.from_string(contents),
  )
}

fn binary_file(path: String, contents: BitArray) -> source_archive.ArchiveFile {
  source_archive.ArchiveFile(path: path, contents: contents)
}

fn package(
  name: String,
  source: notices.PackageSource,
) -> notices.NoticePackage {
  notices.NoticePackage(
    name: name,
    version: "1.0.0",
    declared_licences: ["MIT"],
    source: source,
    scope: manifest.Prod,
  )
}

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

fn transitive_manifest_entry(
  name: String,
  version: String,
  provenance: manifest.Provenance,
  requirements: List(String),
) -> manifest.SbomEntry {
  manifest.SbomEntry(
    name: name,
    version: version,
    kind: manifest.Transitive,
    requirements: requirements,
    provenance: provenance,
  )
}

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
    notices.entries_from_sources(packages, fn(pkg) {
      fake_archive_files(pkg.name)
    })

  should.equal(list.length(entries), 1)
  let assert [entry] = entries
  should.equal(entry.package.name, "with_license")
  should.equal(list.map(entry.files, fn(file) { file.path }), ["./LICENSE"])
}

pub fn entries_from_sources_propagates_read_source_error_test() {
  let packages = [
    package("checksum_mismatch", notices.HexPackage(outer_checksum: "AAAA")),
  ]
  let error =
    notices.ChecksumMismatch(
      package: "checksum_mismatch",
      expected: "AAAA",
      actual: "BBBB",
    )
  let read_source = fn(_pkg: notices.NoticePackage) { Error(error) }

  should.equal(
    notices.entries_from_sources(packages, read_source),
    Error(error),
  )
}

pub fn licence_file_candidates_include_all_root_matches_test() {
  let files = [
    file("./README.md", "readme"),
    file("./LICENSE", "license"),
    file("./NOTICE.txt", "notice"),
    file("./src/COPYING.md", "copying"),
  ]

  let assert Ok(matches) = notices.licence_files(files)

  should.equal(list.map(matches, fn(match) { match.path }), [
    "./LICENSE",
    "./NOTICE.txt",
  ])
}

pub fn licence_file_candidates_strip_common_archive_root_test() {
  let files = [
    file("repo-sha/README.md", "readme"),
    file("repo-sha/vendor/LICENSE", "nested"),
    file("repo-sha/LICENSE", "root"),
  ]

  let assert Ok(matches) = notices.licence_files(files)

  should.equal(matches, [
    notices.NoticeFile(path: "LICENSE", contents: "root"),
  ])
}

pub fn nested_fallback_strips_common_archive_root_test() {
  let files = [
    file("repo-sha/README.md", "readme"),
    file("repo-sha/vendor/LICENSE", "nested"),
  ]

  let assert Ok(matches) = notices.licence_files(files)

  should.equal(matches, [
    notices.NoticeFile(path: "vendor/LICENSE", contents: "nested"),
  ])
}

pub fn licence_file_candidates_fall_back_to_nested_paths_test() {
  let files = [
    file("./README.md", "readme"),
    file("./src/NOTICE", "nested notice"),
    file("./priv/LICENSE.md", "nested license"),
    file("./docs/copying.adoc", "nested copying"),
  ]

  let assert Ok(matches) = notices.licence_files(files)

  should.equal(list.map(matches, fn(match) { match.path }), [
    "./docs/copying.adoc",
    "./priv/LICENSE.md",
    "./src/NOTICE",
  ])
}

pub fn licence_file_matching_is_case_insensitive_test() {
  let files = [file("./licence.MD", "licence")]

  let assert Ok(matches) = notices.licence_files(files)

  should.equal(list.map(matches, fn(match) { match.path }), ["./licence.MD"])
}

pub fn licence_file_matching_decodes_only_matched_files_test() {
  let files = [
    binary_file("./image.bin", <<255>>),
    file("./LICENSE", "license"),
  ]

  let assert Ok(matches) = notices.licence_files(files)

  should.equal(matches, [
    notices.NoticeFile(path: "./LICENSE", contents: "license"),
  ])
}

pub fn licence_file_matching_returns_matched_decode_errors_test() {
  let files = [
    binary_file("./LICENSE", <<255>>),
    file("./NOTICE", "notice"),
  ]

  should.equal(
    notices.licence_files(files),
    Error(source_archive.InvalidText("./LICENSE")),
  )
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
        transitive_manifest_entry(
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

pub fn selected_packages_treat_missing_scope_as_prod_test() {
  let manifest_value =
    manifest.SbomManifest(
      entries: [
        manifest_entry(
          "missing_scope",
          "1.0.0",
          manifest.HexProvenance("AAAA", None),
          [],
        ),
      ],
      root_requirements: ["missing_scope"],
    )

  let selected =
    notices.selected_entries(manifest_value, dict.new(), include_dev: False)

  should.equal(list.map(selected, fn(entry) { entry.name }), ["missing_scope"])
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

pub fn path_source_returns_path_package_test() {
  let entry =
    manifest_entry(
      "local_dep",
      "1.0.0",
      manifest.PathProvenance(path: "../local_dep"),
      [],
    )

  should.equal(
    notices.package_source(entry),
    Ok(notices.PathPackage(path: "../local_dep")),
  )
}

pub fn unknown_source_returns_unsupported_source_test() {
  let entry =
    manifest_entry(
      "weird",
      "1.0.0",
      manifest.UnknownProvenance(source: "rebar3"),
      [],
    )

  should.equal(
    notices.package_source(entry),
    Error(notices.UnsupportedSource(
      package: "weird",
      source: "rebar3",
      detail: "unsupported source",
    )),
  )
}

pub fn render_notice_entries_is_deterministic_test() {
  let entries = [
    notices.NoticeEntry(
      package: package("beta", notices.HexPackage(outer_checksum: "BBBB")),
      files: [notices.NoticeFile(path: "./LICENSE", contents: "Beta text\n")],
    ),
    notices.NoticeEntry(
      package: package(
        "alpha",
        notices.GitHubPackage(
          repo: "https://github.com/example/alpha",
          commit: "abc123",
        ),
      ),
      files: [
        notices.NoticeFile(path: "./NOTICE.txt", contents: "Alpha notice\n"),
        notices.NoticeFile(path: "./LICENSE", contents: "Alpha license\n"),
      ],
    ),
  ]
  let equals = string.repeat("=", times: 80)
  let dashes = string.repeat("-", times: 80)
  let expected =
    "Third-party licences\n"
    <> "Generated by licence_audit notices from manifest.toml.\n\n"
    <> equals
    <> "\n"
    <> "alpha 1.0.0\n"
    <> "Source: git https://github.com/example/alpha @ abc123\n"
    <> "Declared licences: MIT\n"
    <> "Files: ./LICENSE, ./NOTICE.txt\n"
    <> dashes
    <> "\n"
    <> "Alpha license\n"
    <> "\n"
    <> "Alpha notice\n"
    <> "\n"
    <> equals
    <> "\n"
    <> "beta 1.0.0\n"
    <> "Source: hex\n"
    <> "Declared licences: MIT\n"
    <> "Files: ./LICENSE\n"
    <> dashes
    <> "\n"
    <> "Beta text\n"

  should.equal(
    notices.render(entries, manifest_path: "manifest.toml"),
    expected,
  )
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
      files: [notices.NoticeFile(path: "LICENSE", contents: "Local text")],
    )

  let output = notices.render([entry], manifest_path: "manifest.toml")

  assert string.contains(output, "Declared licences: unknown")
  assert string.contains(output, "Source: path ../local_dep")
  assert string.ends_with(output, "\n")
}

pub fn describe_error_formats_all_variants_test() {
  should.equal(
    notices.describe_error(notices.MissingLicenceText(["beta", "alpha"])),
    "Missing licence text for packages: alpha, beta",
  )
  should.equal(
    notices.describe_error(notices.UnsupportedSource(
      package: "git_dep",
      source: "git",
      detail: "not a github.com repository",
    )),
    "Cannot generate notices for package `git_dep` (source: git, not a github.com repository)",
  )
  should.equal(
    notices.describe_error(notices.FetchFailed(
      package: "gleam_stdlib",
      reason: "network failure",
    )),
    "Failed to fetch source archive for gleam_stdlib: network failure",
  )
  should.equal(
    notices.describe_error(notices.ArchiveFailed(
      package: "gleam_stdlib",
      reason: "invalid archive",
    )),
    "Failed to extract source archive for gleam_stdlib: invalid archive",
  )
  should.equal(
    notices.describe_error(notices.ChecksumMismatch(
      package: "gleam_stdlib",
      expected: "aaaa",
      actual: "bbbb",
    )),
    "Checksum mismatch for gleam_stdlib: expected AAAA, got BBBB",
  )
  should.equal(
    notices.describe_error(notices.PathReadFailed(
      package: "local_dep",
      path: "../local_dep",
      reason: "enoent",
    )),
    "Failed to read path dependency local_dep at ../local_dep: enoent",
  )
  should.equal(
    notices.describe_error(notices.OutputWriteFailed(
      path: "THIRD_PARTY_LICENSES.txt",
      reason: "eperm",
    )),
    "Failed to write notices to THIRD_PARTY_LICENSES.txt: eperm",
  )
}
