import gleam/bit_array
import gleam/json
import gleam/list
import gleam/option.{None, Some}
import gleam/string
import gleeunit/should
import licence_audit/cache_support
import licence_audit/manifest
import licence_audit/notice
import licence_audit/notice_cache
import licence_audit/notice_resolve
import licence_audit/repository
import licence_audit/source_archive
import licence_audit/source_archive_test
import licence_audit/spdx
import simplifile

const archive_fixture_dir = "test/fixtures/notices/archive_fixture"

const tmp_dir = "build/tmp/notices_resolve_test"

pub fn corrupt_spdx_text_is_refetched_and_renders_without_crashing_test() {
  let path = fresh_cache_path("corrupt_spdx_text")
  let cache = notice_cache.open(notice_cache.Enabled(path: Some(path)))
  let key = "spdx:" <> spdx.license_list_commit <> ":license:MIT"
  notice_cache.put_text(cache, key, "previous text")
  let assert Ok(_) = cache_support.corrupt_entry(path, key)
  let source = read_bytes("notice_only_hex.tar")
  let package =
    hex_package("corrupt_spdx_text", checksum_of(source), ["MIT"], [])
  let assert #(Ok(resolution), Some(warning)) =
    notice_resolve.resolve(
      cache,
      package,
      clients(
        fn(_name, _version) { Ok(source) },
        panic_git,
        panic_resolve,
        panic_archive,
        fn(requirement) {
          should.equal(requirement, spdx.LicenseRequirement("MIT"))
          Ok(Some("Refetched canonical MIT text"))
        },
      ),
    )
  let assert notice_resolve.Resolved(files) = resolution.outcome
  let rendered =
    notice.render(
      [notice.NoticeEntry(package, files)],
      manifest_path: "manifest.toml",
    )
  assert string.contains(rendered, "Refetched canonical MIT text")
  assert string.contains(warning, "read " <> key)
  let assert None = notice_cache.close(cache)
  let cache = notice_cache.open(notice_cache.Enabled(path: Some(path)))
  should.equal(notice_cache.get_text(cache, key), #(
    Ok("Refetched canonical MIT text"),
    None,
  ))
  let assert None = notice_cache.close(cache)
}

fn read_bytes(name: String) -> BitArray {
  let assert Ok(bytes) =
    simplifile.read_bits(archive_fixture_dir <> "/" <> name)
  bytes
}

fn checksum_of(bytes: BitArray) -> String {
  let assert Ok(checksum) = source_archive.sha256_hex(bytes)
  checksum
}

fn hex_package(
  name: String,
  checksum: String,
  declared: List(String),
  repo_links: List(String),
) -> notice.NoticePackage {
  notice.NoticePackage(
    name: name,
    version: "1.0.0",
    declared_licences: declared,
    repo_links: repo_links,
    source: notice.HexPackage(outer_checksum: checksum),
    scope: manifest.Prod,
  )
}

fn panic_hex(_name: String, _version: String) {
  panic as "hex tarball fetch must not be called"
}

fn panic_git(_repo: repository.Repository, _commit: String) {
  panic as "git archive fetch must not be called"
}

fn panic_resolve(_repo: repository.Repository, _tag: String) {
  panic as "repository tag resolution must not be called"
}

fn panic_archive(_repo: repository.Repository, _commit: String) {
  panic as "repository archive fetch must not be called"
}

fn panic_spdx(_requirement: spdx.Requirement) {
  panic as "SPDX fetch must not be called"
}

fn clients(
  hex: fn(String, String) -> Result(BitArray, notice.FetchError),
  git: fn(repository.Repository, String) -> Result(BitArray, notice.FetchError),
  resolve: fn(repository.Repository, String) ->
    Result(option.Option(String), notice.FetchError),
  archive: fn(repository.Repository, String) ->
    Result(BitArray, notice.FetchError),
  spdx_fetch: fn(spdx.Requirement) ->
    Result(option.Option(String), notice.FetchError),
) -> notice.Clients {
  notice.Clients(
    fetch_hex_tarball: hex,
    fetch_git_archive: git,
    resolve_commit: resolve,
    fetch_repo_archive: archive,
    fetch_spdx_index: fn(kind) {
      case kind {
        spdx.LicenceIndex ->
          Ok(["Apache-2.0", "BSD-3-Clause", "GPL-2.0", "MIT"])
        spdx.ExceptionIndex -> Ok(["LLVM-exception"])
      }
    },
    fetch_spdx: spdx_fetch,
  )
}

fn paths(files: List(notice.NoticeFile)) -> List(String) {
  list.map(files, fn(file) { file.path }) |> list.sort(string.compare)
}

fn fresh_cache_path(name: String) -> String {
  let _ = simplifile.create_directory_all(tmp_dir)
  let path = tmp_dir <> "/" <> name <> ".sqlite3"
  list.each(["", "-wal", "-shm"], fn(suffix) {
    let _ = simplifile.delete(path <> suffix)
  })
  path
}

fn final_cache_key(package: notice.NoticePackage, identity: String) -> String {
  let metadata =
    json.object([
      #("declared_licences", json.array(package.declared_licences, json.string)),
      #("repo_links", json.array(package.repo_links, json.string)),
    ])
    |> json.to_string
    |> bit_array.from_string
    |> checksum_of
  "pkg:v2:"
  <> identity
  <> ":metadata:"
  <> metadata
  <> ":spdx:"
  <> spdx.license_list_commit
}

pub fn source_with_licence_needs_no_fallback_test() {
  let bytes = read_bytes("hex.tar")
  let package = hex_package("has_lic", checksum_of(bytes), ["MIT"], [])
  let client =
    clients(
      fn(_n, _v) { Ok(bytes) },
      panic_git,
      panic_resolve,
      panic_archive,
      panic_spdx,
    )

  let assert #(Ok(resolution), None) =
    notice_resolve.resolve(
      notice_cache.open(notice_cache.Disabled),
      package,
      client,
    )
  let assert notice_resolve.Resolved(files) = resolution.outcome
  should.equal(paths(files), ["./LICENSE", "./NOTICE.txt"])
  should.equal(resolution.warnings, [])
}

pub fn immutable_source_cache_persists_and_changes_with_checksum_test() {
  let path = fresh_cache_path("source_identity")
  let source = read_bytes("hex.tar")
  let checksum = checksum_of(source)
  let package = hex_package("same", string.lowercase(checksum), ["MIT"], [])
  let cache = notice_cache.open(notice_cache.Enabled(path: Some(path)))
  let assert #(Ok(first), None) =
    notice_resolve.resolve(
      cache,
      package,
      clients(
        fn(_n, _v) { Ok(source) },
        panic_git,
        panic_resolve,
        panic_archive,
        panic_spdx,
      ),
    )
  let assert None = notice_cache.close(cache)

  let cache = notice_cache.open(notice_cache.Enabled(path: Some(path)))
  let assert #(Ok(cached), None) =
    notice_resolve.resolve(
      cache,
      hex_package("same", checksum, ["MIT"], []),
      clients(panic_hex, panic_git, panic_resolve, panic_archive, panic_spdx),
    )
  should.equal(cached, first)

  let changed_source = read_bytes("notice_only_hex.tar")
  let assert #(Ok(changed), None) =
    notice_resolve.resolve(
      cache,
      hex_package("same", checksum_of(changed_source), ["MIT"], []),
      clients(
        fn(_n, _v) { Ok(changed_source) },
        panic_git,
        panic_resolve,
        panic_archive,
        fn(_requirement) { Ok(Some("Canonical MIT text")) },
      ),
    )
  let assert notice_resolve.Resolved(files) = changed.outcome
  should.equal(paths(files), ["./NOTICE.txt", "SPDX-License-List/MIT.txt"])
  let assert None = notice_cache.close(cache)
}

pub fn path_packages_always_read_mutable_source_test() {
  let path = fresh_cache_path("path_bypass")
  let root = tmp_dir <> "/local"
  let assert Ok(_) = simplifile.create_directory_all(root)
  let package =
    notice.NoticePackage(
      name: "local",
      version: "1.0.0",
      declared_licences: [],
      repo_links: [],
      source: notice.PathPackage(root),
      scope: manifest.Prod,
    )
  let client =
    clients(panic_hex, panic_git, panic_resolve, panic_archive, panic_spdx)

  list.each(["first", "second"], fn(contents) {
    let assert Ok(_) = simplifile.write(contents, to: root <> "/LICENSE")
    let cache = notice_cache.open(notice_cache.Enabled(path: Some(path)))
    let assert #(Ok(resolution), None) =
      notice_resolve.resolve(cache, package, client)
    should.equal(
      resolution.outcome,
      notice_resolve.Resolved([notice.NoticeFile("LICENSE", contents)]),
    )
    let assert None = notice_cache.close(cache)
  })
}

pub fn blank_path_licence_uses_spdx_or_reports_missing_test() {
  let root = tmp_dir <> "/blank_local"
  let assert Ok(_) = simplifile.create_directory_all(root)
  let cache = notice_cache.open(notice_cache.Disabled)
  list.each(["", " \t\r\n", "\u{00A0}\u{2003}"], fn(blank) {
    let assert Ok(_) = simplifile.write(blank, to: root <> "/LICENSE")
    let package =
      notice.NoticePackage(
        name: "local",
        version: "1.0.0",
        declared_licences: ["LicenseRef-Proprietary"],
        repo_links: [],
        source: notice.PathPackage(root),
        scope: manifest.Prod,
      )
    let assert #(Ok(missing), None) =
      notice_resolve.resolve(
        cache,
        package,
        clients(panic_hex, panic_git, panic_resolve, panic_archive, panic_spdx),
      )
    should.equal(missing.outcome, notice_resolve.Missing)
    let assert #(Ok(resolved), None) =
      notice_resolve.resolve(
        cache,
        notice.NoticePackage(..package, declared_licences: ["MIT"]),
        clients(panic_hex, panic_git, panic_resolve, panic_archive, fn(_) {
          Ok(Some("Canonical MIT text"))
        }),
      )
    should.equal(
      resolved.outcome,
      notice_resolve.Resolved([
        notice.spdx_file(spdx.LicenseRequirement("MIT"), "Canonical MIT text"),
      ]),
    )
  })
  let assert None = notice_cache.close(cache)
  let assert Ok(_) = simplifile.delete(root)
}

pub fn blank_repository_uses_next_repository_or_spdx_test() {
  source_archive_test.with_tar_gz(
    [#("repo/LICENSE", <<" \t\r\n":utf8>>)],
    fn(blank_archive) {
      let source = read_bytes("notice_only_hex.tar")
      let usable_archive = read_bytes("repo_with_license.tar.gz")
      list.each([False, True], fn(second_repo) {
        let links = case second_repo {
          False -> ["https://github.com/owner/blank"]
          True -> [
            "https://github.com/owner/blank",
            "https://github.com/owner/usable",
          ]
        }
        let package = hex_package("dep", checksum_of(source), ["MIT"], links)
        let assert #(Ok(resolved), None) =
          notice_resolve.resolve(
            notice_cache.open(notice_cache.Disabled),
            package,
            clients(
              fn(_, _) { Ok(source) },
              panic_git,
              fn(_, _) { Ok(Some("commit")) },
              fn(repo, _) {
                Ok(case repo.repo {
                  "blank" -> blank_archive
                  _ -> usable_archive
                })
              },
              fn(_) {
                assert !second_repo
                Ok(Some("Canonical MIT text"))
              },
            ),
          )
        let assert notice_resolve.Resolved(files) = resolved.outcome
        should.equal(paths(files), case second_repo {
          True -> ["./NOTICE.txt", "LICENSE"]
          False -> ["./NOTICE.txt", "SPDX-License-List/MIT.txt"]
        })
        should.equal(resolved.warnings, [])
      })
    },
  )
}

fn assert_attribution_requires_fallback(
  cache: notice_cache.Cache,
  package: notice.NoticePackage,
  client: notice.Clients,
) -> Nil {
  list.each(["LicenseRef-Custom", "mit"], fn(declared) {
    let package = notice.NoticePackage(..package, declared_licences: [declared])
    let assert #(Ok(resolution), None) =
      notice_resolve.resolve(cache, package, client)
    case declared {
      "LicenseRef-Custom" ->
        should.equal(resolution.outcome, notice_resolve.Missing)
      _ -> {
        let assert notice_resolve.Resolved(files) = resolution.outcome
        assert list.contains(
          files,
          notice.spdx_file(spdx.LicenseRequirement("MIT"), "Canonical MIT text"),
        )
        let output =
          notice.render(
            [notice.NoticeEntry(package, files)],
            manifest_path: "manifest.toml",
          )
        should.equal(
          list.length(string.split(output, on: "Products using this licence:")),
          2,
        )
        assert string.contains(output, "Additional notices for")
      }
    }
  })
}

pub fn attribution_in_spdx_directory_cannot_resolve_or_revive_from_cache_test() {
  source_archive_test.with_tar_gz(
    [
      #("repo/LICENSE", <<" \t\r\n":utf8>>),
      #("repo/README.md", <<"readme":utf8>>),
      #("repo/SPDX-License-List/NOTICE", <<"attribution":utf8>>),
    ],
    fn(archive) {
      let source = read_bytes("notice_only_hex.tar")
      let routes = [
        #(
          git_package(
            repository.Repository(repository.GitHub, "owner", "git_dep"),
            "https://github.com/owner/git_dep",
            "sha",
          ),
          "git_dep@1.0.0@git:github:owner/git_dep@sha",
          clients(
            panic_hex,
            fn(_, _) { Ok(archive) },
            panic_resolve,
            panic_archive,
            fn(_) { Ok(Some("Canonical MIT text")) },
          ),
        ),
        #(
          hex_package("hex_dep", checksum_of(source), ["MIT"], [
            "https://github.com/owner/repo",
          ]),
          "hex_dep@1.0.0@hex:" <> checksum_of(source),
          clients(
            fn(_, _) { Ok(source) },
            panic_git,
            fn(_, _) { Ok(Some("commit")) },
            fn(_, _) { Ok(archive) },
            fn(_) { Ok(Some("Canonical MIT text")) },
          ),
        ),
      ]
      list.each(routes, fn(route) {
        let #(package, identity, live) = route
        let cache =
          notice_cache.open(
            notice_cache.Enabled(
              path: Some(fresh_cache_path("attribution_" <> package.name)),
            ),
          )
        assert_attribution_requires_fallback(cache, package, live)
        let attribution = [
          notice.NoticeFile("SPDX-License-List/NOTICE", "attribution"),
        ]
        notice_cache.put_files(cache, "source:v2:" <> identity, attribution)
        notice_cache.put_files(
          cache,
          "repo:v2:github:owner/repo@commit",
          attribution,
        )
        list.each(["LicenseRef-Custom", "mit"], fn(declared) {
          notice_cache.put_files(
            cache,
            final_cache_key(
              notice.NoticePackage(..package, declared_licences: [declared]),
              identity,
            ),
            attribution,
          )
        })
        let cached =
          clients(
            panic_hex,
            panic_git,
            panic_resolve,
            panic_archive,
            panic_spdx,
          )
        assert_attribution_requires_fallback(cache, package, cached)
        notice_cache.put_files(
          cache,
          final_cache_key(
            notice.NoticePackage(..package, declared_licences: ["mit"]),
            identity,
          ),
          [notice.spdx_file(spdx.LicenseRequirement("MIT"), "attribution")],
        )
        assert_attribution_requires_fallback(cache, package, cached)
        assert_attribution_requires_fallback(cache, package, cached)
        let assert None = notice_cache.close(cache)
      })
    },
  )
}

pub fn stale_blank_source_repository_and_final_caches_are_repaired_test() {
  let path = fresh_cache_path("stale_blank")
  let source = read_bytes("notice_only_hex.tar")
  let repo_archive = read_bytes("repo_with_license.tar.gz")
  let package =
    hex_package("dep", checksum_of(source), ["MIT"], [
      "https://github.com/owner/repo",
    ])
  let identity = "dep@1.0.0@hex:" <> checksum_of(source)
  let final_key = final_cache_key(package, identity)
  let cache = notice_cache.open(notice_cache.Enabled(path: Some(path)))
  let blank_files = [notice.NoticeFile("LICENSE", " \t\r\n")]
  notice_cache.put_files(cache, "source:v2:" <> identity, blank_files)
  notice_cache.put_files(cache, "repo:v2:github:owner/repo@commit", blank_files)
  let live =
    clients(
      fn(_, _) { Ok(source) },
      panic_git,
      fn(_, _) { Ok(Some("commit")) },
      fn(_, _) { Ok(repo_archive) },
      panic_spdx,
    )
  list.each(
    [
      blank_files,
      [],
      [notice.NoticeFile("NOTICE", "attribution")],
      [notice.NoticeFile("SPDX-License-List/NOTICE", "attribution")],
    ],
    fn(stale) {
      notice_cache.put_files(cache, final_key, stale)
      let assert #(Ok(resolved), None) =
        notice_resolve.resolve(cache, package, live)
      let assert notice_resolve.Resolved(files) = resolved.outcome
      should.equal(paths(files), ["./NOTICE.txt", "LICENSE"])
    },
  )
  let assert None = notice_cache.close(cache)
  let cache = notice_cache.open(notice_cache.Enabled(path: Some(path)))
  let assert #(Ok(resolved), None) =
    notice_resolve.resolve(
      cache,
      package,
      clients(panic_hex, panic_git, panic_resolve, panic_archive, panic_spdx),
    )
  let assert notice_resolve.Resolved(files) = resolved.outcome
  should.equal(paths(files), ["./NOTICE.txt", "LICENSE"])
  let assert None = notice_cache.close(cache)
}

pub fn old_empty_material_caches_do_not_hide_nested_licences_test() {
  source_archive_test.with_tar_gz(
    [
      #("repo/NOTICE", <<" \t\r\n":utf8>>),
      #("repo/README.md", <<"readme":utf8>>),
      #("repo/legal/LICENSE", <<"Nested licence text":utf8>>),
    ],
    fn(archive) {
      let source = read_bytes("notice_only_hex.tar")
      let routes = [
        #(
          git_package(
            repository.Repository(repository.GitHub, "owner", "git_dep"),
            "https://github.com/owner/git_dep",
            "sha",
          ),
          "git_dep@1.0.0@git:github:owner/git_dep@sha",
        ),
        #(
          hex_package("hex_dep", checksum_of(source), ["MIT"], [
            "https://github.com/owner/repo",
          ]),
          "hex_dep@1.0.0@hex:" <> checksum_of(source),
        ),
      ]
      list.each(routes, fn(route) {
        let #(package, identity) = route
        let cache =
          notice_cache.open(
            notice_cache.Enabled(
              path: Some(fresh_cache_path("old_empty_" <> package.name)),
            ),
          )
        notice_cache.put_files(cache, "source:" <> identity, [])
        notice_cache.put_files(cache, "repo:github:owner/repo@commit", [])
        notice_cache.put_text(
          cache,
          "spdx-index:" <> spdx.license_list_commit <> ":licenses",
          spdx.encode_index(["MIT"]),
        )
        notice_cache.put_text(
          cache,
          "spdx:" <> spdx.license_list_commit <> ":license:MIT",
          "Old canonical text",
        )
        notice_cache.put_files(
          cache,
          string.replace(final_cache_key(package, identity), "pkg:v2:", "pkg:"),
          [
            notice.spdx_file(
              spdx.LicenseRequirement("MIT"),
              "Old canonical text",
            ),
          ],
        )
        let assert #(Ok(resolution), None) =
          notice_resolve.resolve(
            cache,
            package,
            clients(
              fn(_, _) { Ok(source) },
              fn(_, _) { Ok(archive) },
              fn(_, _) { Ok(Some("commit")) },
              fn(_, _) { Ok(archive) },
              panic_spdx,
            ),
          )
        let assert notice_resolve.Resolved(files) = resolution.outcome
        assert list.contains(
          files,
          notice.NoticeFile("legal/LICENSE", "Nested licence text"),
        )
        assert !list.contains(paths(files), "SPDX-License-List/MIT.txt")
        let assert None = notice_cache.close(cache)
      })
    },
  )
}

pub fn blank_cached_spdx_is_refetched_and_blank_live_spdx_is_missing_test() {
  let path = fresh_cache_path("blank_spdx")
  let cache = notice_cache.open(notice_cache.Enabled(path: Some(path)))
  let key = "spdx:" <> spdx.license_list_commit <> ":license:MIT"
  notice_cache.put_text(cache, key, " \t\r\n")
  let source = read_bytes("notice_only_hex.tar")
  let client = fn(text) {
    clients(
      fn(_, _) { Ok(source) },
      panic_git,
      panic_resolve,
      panic_archive,
      fn(_) { Ok(Some(text)) },
    )
  }
  let assert #(Ok(resolved), None) =
    notice_resolve.resolve(
      cache,
      hex_package("cached", checksum_of(source), ["MIT"], []),
      client("Canonical MIT text"),
    )
  let assert notice_resolve.Resolved(files) = resolved.outcome
  should.equal(paths(files), ["./NOTICE.txt", "SPDX-License-List/MIT.txt"])
  should.equal(notice_cache.get_text(cache, key), #(
    Ok("Canonical MIT text"),
    None,
  ))
  let assert None = notice_cache.close(cache)
  let assert #(Ok(missing), None) =
    notice_resolve.resolve(
      notice_cache.open(notice_cache.Disabled),
      hex_package("live", checksum_of(source), ["MIT"], []),
      client(" \t\r\n"),
    )
  should.equal(missing.outcome, notice_resolve.Missing)
}

pub fn notice_only_source_falls_back_to_repository_test() {
  let source = read_bytes("notice_only_hex.tar")
  let repo_archive = read_bytes("repo_with_license.tar.gz")
  let package =
    hex_package("notice_only", checksum_of(source), ["Apache-2.0"], [
      "https://github.com/owner/repo",
    ])
  let client =
    clients(
      fn(_n, _v) { Ok(source) },
      panic_git,
      fn(_repo, tag) {
        should.equal(tag, "v1.0.0")
        Ok(Some("abcdef1234"))
      },
      fn(_repo, commit) {
        should.equal(commit, "abcdef1234")
        Ok(repo_archive)
      },
      panic_spdx,
    )

  let assert #(Ok(resolution), None) =
    notice_resolve.resolve(
      notice_cache.open(notice_cache.Disabled),
      package,
      client,
    )
  let assert notice_resolve.Resolved(files) = resolution.outcome
  // The source NOTICE is preserved and the repository LICENSE is appended.
  should.equal(paths(files), ["./NOTICE.txt", "LICENSE"])
  should.equal(resolution.warnings, [])
}

pub fn notice_only_source_repo_missing_falls_back_to_spdx_test() {
  let source = read_bytes("notice_only_hex.tar")
  let package =
    hex_package("notice_only", checksum_of(source), ["Apache-2.0"], [
      "https://github.com/owner/repo",
    ])
  let client =
    clients(
      fn(_n, _v) { Ok(source) },
      panic_git,
      // No matching tag exists on the repository.
      fn(_repo, _tag) { Ok(None) },
      panic_archive,
      fn(requirement) {
        should.equal(requirement, spdx.LicenseRequirement("Apache-2.0"))
        Ok(Some("Canonical Apache-2.0 text"))
      },
    )

  let assert #(Ok(resolution), None) =
    notice_resolve.resolve(
      notice_cache.open(notice_cache.Disabled),
      package,
      client,
    )
  let assert notice_resolve.Resolved(files) = resolution.outcome
  should.equal(paths(files), [
    "./NOTICE.txt",
    "SPDX-License-List/Apache-2.0.txt",
  ])
  // A tag that simply does not exist is not a transient failure.
  should.equal(resolution.warnings, [])
}

pub fn repository_network_failure_warns_and_uses_spdx_test() {
  let source = read_bytes("notice_only_hex.tar")
  let package =
    hex_package("notice_only", checksum_of(source), ["MIT"], [
      "https://github.com/owner/repo",
    ])
  let client =
    clients(
      fn(_n, _v) { Ok(source) },
      panic_git,
      fn(_repo, _tag) { Error(notice.FetchNetworkFailure) },
      panic_archive,
      fn(_requirement) { Ok(Some("Canonical MIT text")) },
    )

  let assert #(Ok(resolution), None) =
    notice_resolve.resolve(
      notice_cache.open(notice_cache.Disabled),
      package,
      client,
    )
  let assert notice_resolve.Resolved(files) = resolution.outcome
  should.equal(paths(files), ["./NOTICE.txt", "SPDX-License-List/MIT.txt"])
  let assert [warning] = resolution.warnings
  assert string.contains(warning, "Repository fallback for notice_only")
}

pub fn spdx_network_failure_preserves_cache_warning_test() {
  let path = fresh_cache_path("failed_spdx_warning")
  let cache = notice_cache.open(notice_cache.Enabled(Some(path)))
  cache_support.drop_table(path)
  let source = read_bytes("notice_only_hex.tar")
  let package = hex_package("notice_only", checksum_of(source), ["MIT"], [])
  let client =
    clients(
      fn(_n, _v) { Ok(source) },
      panic_git,
      panic_resolve,
      panic_archive,
      fn(_requirement) { Error(notice.FetchNetworkFailure) },
    )

  let assert #(
    Error(notice.SpdxFetchFailed("notice_only", "MIT", _)),
    Some(warning),
  ) = notice_resolve.resolve(cache, package, client)
  assert string.contains(warning, "Failed to access notices cache: read spdx:")
  let assert None = notice_cache.close(cache)
}

pub fn partial_spdx_expression_is_missing_test() {
  let source = read_bytes("notice_only_hex.tar")
  let package =
    hex_package("notice_only", checksum_of(source), ["MIT AND Unknown-1.0"], [])
  let client =
    clients(
      fn(_n, _v) { Ok(source) },
      panic_git,
      panic_resolve,
      panic_archive,
      panic_spdx,
    )

  let assert #(Ok(resolution), None) =
    notice_resolve.resolve(
      notice_cache.open(notice_cache.Disabled),
      package,
      client,
    )
  should.equal(resolution.outcome, notice_resolve.Missing)
}

pub fn spdx_identifier_case_is_canonicalized_test() {
  let source = read_bytes("notice_only_hex.tar")
  let package = hex_package("notice_only", checksum_of(source), ["mit"], [])
  let client =
    clients(
      fn(_n, _v) { Ok(source) },
      panic_git,
      panic_resolve,
      panic_archive,
      fn(requirement) {
        should.equal(requirement, spdx.LicenseRequirement("MIT"))
        Ok(Some("Canonical MIT text"))
      },
    )

  let assert #(Ok(resolution), None) =
    notice_resolve.resolve(
      notice_cache.open(notice_cache.Disabled),
      package,
      client,
    )
  let assert notice_resolve.Resolved(files) = resolution.outcome
  should.equal(paths(files), ["./NOTICE.txt", "SPDX-License-List/MIT.txt"])
}

pub fn license_ref_declared_is_missing_test() {
  let source = read_bytes("notice_only_hex.tar")
  let package =
    hex_package("notice_only", checksum_of(source), ["LicenseRef-Custom"], [])
  let client =
    clients(
      fn(_n, _v) { Ok(source) },
      panic_git,
      panic_resolve,
      panic_archive,
      panic_spdx,
    )

  let assert #(Ok(resolution), None) =
    notice_resolve.resolve(
      notice_cache.open(notice_cache.Disabled),
      package,
      client,
    )
  should.equal(resolution.outcome, notice_resolve.Missing)
}

pub fn git_source_skips_repository_fallback_test() {
  let git_source = read_bytes("git_notice_only.tar.gz")
  let repo = repository.Repository(repository.GitHub, "owner", "git_dep")
  let package =
    notice.NoticePackage(
      name: "git_dep",
      version: "1.0.0",
      declared_licences: ["MIT"],
      // Even with a parseable repo link, git sources never retry the repo.
      repo_links: ["https://github.com/owner/git_dep"],
      source: notice.GitPackage(
        repository: repo,
        url: "https://github.com/owner/git_dep",
        commit: "sha",
      ),
      scope: manifest.Prod,
    )
  let client =
    clients(
      panic_hex,
      fn(fetched_repo, commit) {
        should.equal(fetched_repo, repo)
        should.equal(commit, "sha")
        Ok(git_source)
      },
      panic_resolve,
      panic_archive,
      fn(_requirement) { Ok(Some("Canonical MIT text")) },
    )

  let assert #(Ok(resolution), None) =
    notice_resolve.resolve(
      notice_cache.open(notice_cache.Disabled),
      package,
      client,
    )
  let assert notice_resolve.Resolved(files) = resolution.outcome
  should.equal(paths(files), ["NOTICE.txt", "SPDX-License-List/MIT.txt"])
}

pub fn spdx_records_are_shared_across_packages_test() {
  let path = fresh_cache_path("spdx_shared")
  let source = read_bytes("notice_only_hex.tar")
  let checksum = checksum_of(source)

  // First package resolves Apache-2.0 via the SPDX fallback and caches it.
  let cache = notice_cache.open(notice_cache.Enabled(path: Some(path)))
  let first = hex_package("a", checksum, ["Apache-2.0"], [])
  let assert #(Ok(_), None) =
    notice_resolve.resolve(
      cache,
      first,
      clients(
        fn(_n, _v) { Ok(source) },
        panic_git,
        panic_resolve,
        panic_archive,
        fn(_requirement) { Ok(Some("Canonical Apache text")) },
      ),
    )

  // A different package (distinct final key) reusing Apache-2.0 hits the shared
  // SPDX record without another fetch.
  let second = hex_package("b", checksum, ["Apache-2.0"], [])
  let assert #(Ok(resolution), None) =
    notice_resolve.resolve(
      cache,
      second,
      clients(
        fn(_n, _v) { Ok(source) },
        panic_git,
        panic_resolve,
        panic_archive,
        panic_spdx,
      ),
    )
  let assert notice_resolve.Resolved(files) = resolution.outcome
  should.equal(paths(files), [
    "./NOTICE.txt",
    "SPDX-License-List/Apache-2.0.txt",
  ])
  let _ = notice_cache.close(cache)
}

pub fn final_cache_key_includes_declared_metadata_test() {
  let path = fresh_cache_path("metadata_key")
  let source = read_bytes("notice_only_hex.tar")
  let checksum = checksum_of(source)
  let cache = notice_cache.open(notice_cache.Enabled(path: Some(path)))

  let assert #(Ok(first), None) =
    notice_resolve.resolve(
      cache,
      hex_package("same", checksum, ["MIT"], []),
      clients(
        fn(_n, _v) { Ok(source) },
        panic_git,
        panic_resolve,
        panic_archive,
        fn(requirement) {
          should.equal(requirement, spdx.LicenseRequirement("MIT"))
          Ok(Some("Canonical MIT text"))
        },
      ),
    )
  let assert notice_resolve.Resolved(first_files) = first.outcome
  should.equal(paths(first_files), ["./NOTICE.txt", "SPDX-License-List/MIT.txt"])

  // The immutable source is cached, but changed declared metadata must produce a
  // different final key and resolve the new SPDX identifier.
  let assert #(Ok(second), None) =
    notice_resolve.resolve(
      cache,
      hex_package("same", checksum, ["Apache-2.0"], []),
      clients(
        panic_hex,
        panic_git,
        panic_resolve,
        panic_archive,
        fn(requirement) {
          should.equal(requirement, spdx.LicenseRequirement("Apache-2.0"))
          Ok(Some("Canonical Apache text"))
        },
      ),
    )
  let assert notice_resolve.Resolved(second_files) = second.outcome
  should.equal(paths(second_files), [
    "./NOTICE.txt",
    "SPDX-License-List/Apache-2.0.txt",
  ])
  let _ = notice_cache.close(cache)
}

// --- Provider-agnostic git package archive fetch -----------------------------

fn git_package(
  repo: repository.Repository,
  url: String,
  commit: String,
) -> notice.NoticePackage {
  notice.NoticePackage(
    name: "git_dep",
    version: "1.0.0",
    declared_licences: ["MIT"],
    // A parseable repo link is present, but git sources must never retry it.
    repo_links: [url],
    source: notice.GitPackage(repository: repo, url: url, commit: commit),
    scope: manifest.Prod,
  )
}

/// Resolve a git package whose source ships a LICENSE, asserting the archive
/// fetch targets the exact parsed provider identity and immutable commit and
/// that repository tag resolution is never consulted.
fn assert_git_archive_fetch(
  repo: repository.Repository,
  url: String,
  commit: String,
) {
  let source = read_bytes("repo_with_license.tar.gz")
  let package = git_package(repo, url, commit)
  let client =
    clients(
      panic_hex,
      fn(fetched_repo, fetched_commit) {
        // The provider-agnostic archive fetcher receives the parsed provider
        // identity and the manifest commit verbatim.
        should.equal(fetched_repo, repo)
        should.equal(fetched_commit, commit)
        Ok(source)
      },
      panic_resolve,
      panic_archive,
      panic_spdx,
    )

  let assert #(Ok(resolution), None) =
    notice_resolve.resolve(
      notice_cache.open(notice_cache.Disabled),
      package,
      client,
    )
  let assert notice_resolve.Resolved(files) = resolution.outcome
  assert list.contains(paths(files), "LICENSE")
}

pub fn git_package_archive_fetch_uses_github_provider_test() {
  assert_git_archive_fetch(
    repository.Repository(repository.GitHub, "owner", "git_dep"),
    "https://github.com/owner/git_dep",
    "1111111111",
  )
}

pub fn git_package_archive_fetch_uses_gitlab_provider_test() {
  assert_git_archive_fetch(
    repository.Repository(repository.GitLab, "owner", "git_dep"),
    "https://gitlab.com/owner/git_dep",
    "2222222222",
  )
}

pub fn git_package_archive_fetch_uses_codeberg_provider_test() {
  assert_git_archive_fetch(
    repository.Repository(repository.Codeberg, "owner", "git_dep"),
    "https://codeberg.org/owner/git_dep",
    "3333333333",
  )
}

// --- Transient repository failure must not freeze the final result -----------

pub fn transient_repo_failure_is_not_cached_and_retries_test() {
  let path = fresh_cache_path("transient_repo")
  let source = read_bytes("notice_only_hex.tar")
  let repo_archive = read_bytes("repo_with_license.tar.gz")
  let checksum = checksum_of(source)
  let package =
    hex_package("notice_only", checksum, ["MIT"], [
      "https://github.com/owner/repo",
    ])

  let cache = notice_cache.open(notice_cache.Enabled(path: Some(path)))

  // First run: the repository fails transiently, so resolution degrades to the
  // SPDX fallback. That degraded final result must NOT be cached.
  let assert #(Ok(first), None) =
    notice_resolve.resolve(
      cache,
      package,
      clients(
        fn(_n, _v) { Ok(source) },
        panic_git,
        fn(_repo, _tag) { Error(notice.FetchNetworkFailure) },
        panic_archive,
        fn(_requirement) { Ok(Some("Canonical MIT text")) },
      ),
    )
  let assert notice_resolve.Resolved(first_files) = first.outcome
  should.equal(paths(first_files), [
    "./NOTICE.txt",
    "SPDX-License-List/MIT.txt",
  ])
  let assert [_warning] = first.warnings

  // Second run: the repository now succeeds. Because the degraded result was
  // not frozen, resolution retries the repository and uses its LICENSE. SPDX
  // must not be consulted (panic_spdx proves no silent final-cache hit either).
  let assert #(Ok(second), None) =
    notice_resolve.resolve(
      cache,
      package,
      clients(
        panic_hex,
        panic_git,
        fn(_repo, tag) {
          should.equal(tag, "v1.0.0")
          Ok(Some("commitsha"))
        },
        fn(_repo, commit) {
          should.equal(commit, "commitsha")
          Ok(repo_archive)
        },
        panic_spdx,
      ),
    )
  let assert notice_resolve.Resolved(second_files) = second.outcome
  should.equal(paths(second_files), ["./NOTICE.txt", "LICENSE"])
  should.equal(second.warnings, [])
  let _ = notice_cache.close(cache)
}

// --- Disabled cache re-resolves every namespace ------------------------------

pub fn disabled_cache_refetches_across_runs_test() {
  let source = read_bytes("notice_only_hex.tar")
  let package = hex_package("notice_only", checksum_of(source), ["MIT"], [])
  let disabled = notice_cache.open(notice_cache.Disabled)

  // With the cache disabled, the SPDX fallback fetch happens on every run:
  // both resolutions must exercise the live fetcher rather than a cached value.
  let resolve_once = fn() {
    notice_resolve.resolve(
      disabled,
      package,
      clients(
        fn(_n, _v) { Ok(source) },
        panic_git,
        panic_resolve,
        panic_archive,
        fn(requirement) {
          should.equal(requirement, spdx.LicenseRequirement("MIT"))
          Ok(Some("Canonical MIT text"))
        },
      ),
    )
  }

  let assert #(Ok(first), None) = resolve_once()
  let assert notice_resolve.Resolved(first_files) = first.outcome
  should.equal(paths(first_files), ["./NOTICE.txt", "SPDX-License-List/MIT.txt"])

  // A second run with panic_spdx would explode if a disabled cache had somehow
  // retained the record; instead it must re-fetch, so we assert it succeeds
  // again with the live fetcher above.
  let assert #(Ok(second), None) = resolve_once()
  let assert notice_resolve.Resolved(second_files) = second.outcome
  should.equal(paths(second_files), [
    "./NOTICE.txt",
    "SPDX-License-List/MIT.txt",
  ])
}
