import gleam/bit_array
import gleam/dict
import gleam/list
import gleam/option.{None}
import gleam/string
import gleeunit/should
import licence_audit/hex
import licence_audit/manifest
import licence_audit/notices
import licence_audit/repository
import licence_audit/source_archive
import licence_audit/spdx
import simplifile

const archive_fixture_dir = "test/fixtures/notices/archive_fixture"

const tmp_dir = "build/tmp/notices_test"

fn file(path: String, contents: String) -> source_archive.ArchiveFile {
  source_archive.ArchiveFile(
    path: path,
    contents: bit_array.from_string(contents),
  )
}

fn binary_file(path: String, contents: BitArray) -> source_archive.ArchiveFile {
  source_archive.ArchiveFile(path: path, contents: contents)
}

fn fresh_dir(name: String) -> String {
  let _ = simplifile.create_directory_all(tmp_dir)
  let path = tmp_dir <> "/" <> name
  let _ = simplifile.delete(path)
  let assert Ok(Nil) = simplifile.create_directory_all(path)
  path
}

fn package(
  name: String,
  source: notices.PackageSource,
) -> notices.NoticePackage {
  notices.NoticePackage(
    name: name,
    version: "1.0.0",
    declared_licences: ["MIT"],
    repo_links: [],
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

pub fn package_metadata_uses_only_repository_links_test() {
  let entry =
    manifest_entry("dep", "1.0.0", manifest.HexProvenance("AAAA", None), [])
  let metadata =
    hex.PackageMetadata(
      licences: ["MIT"],
      description: None,
      links: [
        #("Sponsor", "https://github.com/sponsors/example"),
        #("Repository", "https://github.com/example/dep"),
      ],
      publisher: None,
    )

  let assert Ok([package]) =
    notices.packages_from_entries([entry], dict.new(), fn(_entry) {
      Ok(metadata)
    })
  should.equal(package.repo_links, ["https://github.com/example/dep"])
}

pub fn read_hex_source_rejects_checksum_mismatch_test() {
  let pkg = package("hex_dep", notices.HexPackage(outer_checksum: "AAAA"))
  let fetch_hex = fn(_name, _version) {
    Ok(bit_array.from_string("not the expected bytes"))
  }
  let fetch_git = fn(_repo, _commit) { Ok(bit_array.from_string("unused")) }

  let assert Error(notices.ChecksumMismatch("hex_dep", "AAAA", _actual)) =
    notices.read_remote_source(pkg, fetch_hex, fetch_git)
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
  should.equal(
    notices.describe_fetch_error(notices.FetchTimeout),
    "timed out after 30s",
  )
  should.equal(
    notices.describe_fetch_error(notices.FetchTimeoutAfter(10)),
    "timed out after 10s",
  )
}

pub fn read_path_source_returns_relative_binary_archive_files_test() {
  let root = fresh_dir("path_source")
  let assert Ok(Nil) = simplifile.create_directory_all(root <> "/src")
  let assert Ok(Nil) =
    simplifile.write(to: root <> "/LICENSE", contents: "Local licence\n")
  let assert Ok(Nil) =
    simplifile.write_bits(to: root <> "/src/image.bin", bits: <<0, 255>>)
  let pkg = package("local_dep", notices.PathPackage(path: root))

  let assert Ok(files) =
    notices.read_remote_source(
      pkg,
      fn(_name, _version) { Error(notices.FetchNetworkFailure) },
      fn(_repo, _commit) { Error(notices.FetchNetworkFailure) },
    )

  should.equal(
    list.map(files, fn(file) { file.path }) |> list.sort(string.compare),
    ["LICENSE", "src/image.bin"],
  )
  let assert [binary] =
    list.filter(files, fn(file) { file.path == "src/image.bin" })
  should.equal(binary.contents, <<0, 255>>)
}

pub fn read_path_source_skips_symlink_targets_outside_root_test() {
  let root = fresh_dir("path_source_symlink_root")
  let outside_dir = fresh_dir("path_source_symlink_outside")
  let outside_contents = "Outside secret/license text\n"
  let assert Ok(Nil) =
    simplifile.write(to: root <> "/LICENSE", contents: "Local licence\n")
  let assert Ok(Nil) =
    simplifile.write(
      to: outside_dir <> "/outside.txt",
      contents: outside_contents,
    )
  let assert Ok(cwd) = simplifile.current_directory()
  let assert Ok(Nil) =
    simplifile.create_symlink(
      to: cwd <> "/" <> outside_dir <> "/outside.txt",
      from: root <> "/LINKED_LICENSE",
    )
  let pkg = package("local_dep", notices.PathPackage(path: root))

  let assert Ok(files) =
    notices.read_remote_source(
      pkg,
      fn(_name, _version) { Error(notices.FetchNetworkFailure) },
      fn(_repo, _commit) { Error(notices.FetchNetworkFailure) },
    )

  let paths = list.map(files, fn(file) { file.path })
  assert list.contains(paths, "LICENSE")
  assert !list.contains(paths, "LINKED_LICENSE")
  assert !list.any(files, fn(file) {
    case bit_array.to_string(file.contents) {
      Ok(contents) -> string.contains(contents, outside_contents)
      Error(_) -> False
    }
  })
}

pub fn read_git_source_uses_fetcher_and_extracts_archive_test() {
  let assert Ok(bits) =
    simplifile.read_bits(archive_fixture_dir <> "/contents.tar.gz")
  let repo = repository.Repository(repository.GitHub, "example", "git_dep")
  let pkg =
    package(
      "git_dep",
      notices.GitPackage(
        repository: repo,
        url: "https://github.com/example/git_dep.git",
        commit: "abc123",
      ),
    )
  let fetch_git = fn(fetched_repo, commit) {
    should.equal(fetched_repo, repo)
    should.equal(commit, "abc123")
    Ok(bits)
  }

  let assert Ok(files) =
    notices.read_remote_source(
      pkg,
      fn(_name, _version) { Error(notices.FetchNetworkFailure) },
      fetch_git,
    )

  let paths = list.map(files, fn(file) { file.path })
  assert list.contains(paths, "./LICENSE")
  assert list.contains(paths, "./NOTICE.txt")
}

pub fn read_hex_source_verifies_checksum_and_extracts_contents_test() {
  let assert Ok(bits) = simplifile.read_bits(archive_fixture_dir <> "/hex.tar")
  let assert Ok(checksum) = source_archive.sha256_hex(bits)
  let pkg = package("hex_dep", notices.HexPackage(outer_checksum: checksum))
  let fetch_hex = fn(name, version) {
    should.equal(name, "hex_dep")
    should.equal(version, "1.0.0")
    Ok(bits)
  }

  let assert Ok(files) =
    notices.read_remote_source(pkg, fetch_hex, fn(_repo, _commit) {
      Error(notices.FetchNetworkFailure)
    })

  let paths = list.map(files, fn(file) { file.path })
  assert list.contains(paths, "./LICENSE")
  assert list.contains(paths, "./NOTICE.txt")
}

pub fn entries_from_sources_fails_with_all_missing_license_text_test() {
  let packages = [
    package("without_license", notices.HexPackage(outer_checksum: "AAAA")),
    package("also_missing", notices.PathPackage(path: "./missing")),
  ]
  let read_source = fn(pkg: notices.NoticePackage) {
    case pkg.name {
      "also_missing" ->
        notices.notice_files_of(pkg.name, [file("./README.md", "Readme\n")])
      _ ->
        case fake_archive_files(pkg.name) {
          Ok(files) -> notices.notice_files_of(pkg.name, files)
          Error(error) -> Error(error)
        }
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
      case fake_archive_files(pkg.name) {
        Ok(files) -> notices.notice_files_of(pkg.name, files)
        Error(error) -> Error(error)
      }
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

pub fn git_source_rejects_unsupported_repo_test() {
  // An arbitrary host is not one of the supported git providers.
  let unsupported =
    manifest_entry(
      "git_dep",
      "1.0.0",
      manifest.GitProvenance(
        repo: "https://example.com/example/git_dep",
        commit: "abc",
      ),
      [],
    )
  let assert Error(notices.UnsupportedSource("git_dep", "git", _)) =
    notices.package_source(unsupported)

  // A non-HTTPS / SCP-style git URL is rejected outright.
  let scp =
    manifest_entry(
      "git_dep",
      "1.0.0",
      manifest.GitProvenance(
        repo: "git@github.com:example/git_dep.git",
        commit: "abc",
      ),
      [],
    )
  let assert Error(notices.UnsupportedSource("git_dep", "git", _)) =
    notices.package_source(scp)
}

pub fn git_source_accepts_github_repo_test() {
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

  let assert Ok(notices.GitPackage(repo, url, commit)) =
    notices.package_source(entry)
  should.equal(
    repo,
    repository.Repository(repository.GitHub, "example", "git_dep"),
  )
  should.equal(url, "https://github.com/example/git_dep.git")
  should.equal(commit, "abc")
}

pub fn git_source_accepts_gitlab_repo_test() {
  let entry =
    manifest_entry(
      "git_dep",
      "1.0.0",
      manifest.GitProvenance(
        repo: "https://gitlab.com/example/git_dep",
        commit: "def",
      ),
      [],
    )

  let assert Ok(notices.GitPackage(repo, url, commit)) =
    notices.package_source(entry)
  should.equal(
    repo,
    repository.Repository(repository.GitLab, "example", "git_dep"),
  )
  should.equal(url, "https://gitlab.com/example/git_dep")
  should.equal(commit, "def")
}

pub fn git_source_accepts_codeberg_repo_test() {
  let entry =
    manifest_entry(
      "git_dep",
      "1.0.0",
      manifest.GitProvenance(
        repo: "https://codeberg.org/example/git_dep.git",
        commit: "ghi",
      ),
      [],
    )

  let assert Ok(notices.GitPackage(repo, url, commit)) =
    notices.package_source(entry)
  should.equal(
    repo,
    repository.Repository(repository.Codeberg, "example", "git_dep"),
  )
  should.equal(url, "https://codeberg.org/example/git_dep.git")
  should.equal(commit, "ghi")
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
        notices.GitPackage(
          repository: repository.Repository(
            repository.GitHub,
            "example",
            "alpha",
          ),
          url: "https://github.com/example/alpha",
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
    <> "Products using this licence:\n"
    <> "  alpha 1.0.0\n"
    <> "    Source: git https://github.com/example/alpha @ abc123\n"
    <> "    Declared licences: MIT\n"
    <> "    Licence files: ./LICENSE\n"
    <> dashes
    <> "\n"
    <> "Alpha license\n"
    <> "\n"
    <> equals
    <> "\n"
    <> "Products using this licence:\n"
    <> "  beta 1.0.0\n"
    <> "    Source: hex\n"
    <> "    Declared licences: MIT\n"
    <> "    Licence files: ./LICENSE\n"
    <> dashes
    <> "\n"
    <> "Beta text\n"
    <> "\n"
    <> equals
    <> "\n"
    <> "Additional notices for alpha 1.0.0\n"
    <> "Source: git https://github.com/example/alpha @ abc123\n"
    <> "Declared licences: MIT\n"
    <> "Notice files: ./NOTICE.txt\n"
    <> dashes
    <> "\n"
    <> "Alpha notice\n"

  should.equal(
    notices.render(entries, manifest_path: "manifest.toml"),
    expected,
  )
}

pub fn render_groups_products_with_identical_licence_text_test() {
  let entries = [
    notices.NoticeEntry(
      package: package("beta", notices.HexPackage(outer_checksum: "BBBB")),
      files: [
        notices.NoticeFile(path: "./LICENSE", contents: "Shared text\r\n"),
        notices.NoticeFile(path: "./NOTICE", contents: "Beta notice\n"),
      ],
    ),
    notices.NoticeEntry(
      package: package("alpha", notices.HexPackage(outer_checksum: "AAAA")),
      files: [
        notices.NoticeFile(path: "./COPYING", contents: "Shared text\n"),
        notices.NoticeFile(path: "./LICENSE", contents: "Shared text"),
      ],
    ),
  ]

  let output = notices.render(entries, manifest_path: "manifest.toml")

  should.equal(list.length(string.split(output, on: "Shared text\n")), 2)
  should.equal(
    list.length(string.split(output, on: "Products using this licence:\n")),
    2,
  )
  assert string.contains(output, "  alpha 1.0.0\n")
  assert string.contains(output, "    Licence files: ./COPYING, ./LICENSE\n")
  assert string.contains(output, "  beta 1.0.0\n")
  assert string.contains(output, "Additional notices for beta 1.0.0\n")
  assert string.contains(output, "Beta notice\n")
}

pub fn render_unknown_declared_licences_test() {
  let entry =
    notices.NoticeEntry(
      package: notices.NoticePackage(
        name: "local_dep",
        version: "0.1.0",
        declared_licences: [],
        repo_links: [],
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

pub fn has_licence_file_detects_licence_type_files_test() {
  assert notices.has_licence_file([notices.NoticeFile("./LICENSE", "x")])
  assert notices.has_licence_file([notices.NoticeFile("COPYING", "x")])
  assert notices.has_licence_file([notices.NoticeFile("licence.md", "x")])
  // A NOTICE-only set does not count as having a licence.
  assert !notices.has_licence_file([notices.NoticeFile("./NOTICE.txt", "x")])
  assert !notices.has_licence_file([notices.NoticeFile("README.md", "x")])
}

pub fn licence_files_only_drops_ancillary_notice_test() {
  let files = [
    notices.NoticeFile("LICENSE", "lic"),
    notices.NoticeFile("NOTICE.txt", "notice"),
    notices.NoticeFile("COPYING", "copying"),
  ]
  should.equal(notices.licence_files_only(files), [
    notices.NoticeFile("LICENSE", "lic"),
    notices.NoticeFile("COPYING", "copying"),
  ])
}

pub fn spdx_file_labels_synthetic_origin_test() {
  should.equal(
    notices.spdx_file(spdx.LicenseRequirement("Apache-2.0"), "text"),
    notices.NoticeFile("SPDX-License-List/Apache-2.0.txt", "text"),
  )
}

pub fn describe_error_formats_all_variants_test() {
  should.equal(
    notices.describe_error(notices.MissingLicenceText(["beta", "alpha"])),
    "Missing licence text for packages: alpha, beta",
  )
  should.equal(
    notices.describe_error(notices.MetadataFailed(
      package: "gleam_stdlib",
      reason: "package not found on Hex",
    )),
    "Failed to resolve licence metadata for gleam_stdlib: package not found on Hex",
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
    notices.describe_error(notices.SpdxFetchFailed(
      package: "gleam_stdlib",
      id: "Apache-2.0",
      reason: "network failure",
    )),
    "Failed to fetch canonical SPDX text for gleam_stdlib (Apache-2.0): network failure",
  )
  should.equal(
    notices.describe_error(notices.OutputWriteFailed(
      path: "THIRD_PARTY_LICENSES.txt",
      reason: "eperm",
    )),
    "Failed to write notices to THIRD_PARTY_LICENSES.txt: eperm",
  )
}

// --- Pure HTTP status → outcome mapping (network-free) -----------------------

pub fn commit_response_maps_404_to_not_found_test() {
  let repo = repository.Repository(repository.GitHub, "o", "r")
  should.equal(notices.commit_response(repo, 404, ""), Ok(None))
}

pub fn commit_response_maps_github_422_to_not_found_test() {
  let repo = repository.Repository(repository.GitHub, "o", "r")
  should.equal(notices.commit_response(repo, 422, ""), Ok(None))
}

pub fn commit_response_decodes_sha_on_2xx_test() {
  let repo = repository.Repository(repository.GitHub, "o", "r")
  should.equal(
    notices.commit_response(repo, 200, "{\"sha\":\"abc123\"}"),
    Ok(option.Some("abc123")),
  )
  // A 2xx body missing the provider's SHA field is treated as "not found".
  should.equal(notices.commit_response(repo, 200, "{}"), Ok(None))
}

pub fn commit_response_maps_other_status_to_transient_test() {
  let repo = repository.Repository(repository.GitLab, "o", "r")
  should.equal(
    notices.commit_response(repo, 500, ""),
    Error(notices.FetchUnexpectedResponse(500)),
  )
}

pub fn spdx_response_maps_404_to_unknown_test() {
  let requirement = spdx.LicenseRequirement("MIT")
  should.equal(notices.spdx_response(requirement, 404, ""), Ok(None))
}

pub fn spdx_response_decodes_text_on_2xx_test() {
  let requirement = spdx.LicenseRequirement("MIT")
  should.equal(
    notices.spdx_response(requirement, 200, "{\"licenseText\":\"MIT text\"}"),
    Ok(option.Some("MIT text")),
  )
  should.equal(notices.spdx_response(requirement, 200, "{}"), Ok(None))
}

pub fn spdx_response_maps_other_status_to_transient_test() {
  let requirement = spdx.ExceptionRequirement("LLVM-exception")
  should.equal(
    notices.spdx_response(requirement, 503, ""),
    Error(notices.FetchUnexpectedResponse(503)),
  )
}
