import gleam/list
import gleam/option.{None, Some}
import gleam/string
import gleeunit/should
import licence_audit/manifest
import licence_audit/notices
import licence_audit/notices_cache
import licence_audit/notices_resolve
import licence_audit/repository
import licence_audit/source_archive
import licence_audit/spdx
import simplifile

const archive_fixture_dir = "test/fixtures/notices/archive_fixture"

const tmp_dir = "build/tmp/notices_resolve_test"

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
) -> notices.NoticePackage {
  notices.NoticePackage(
    name: name,
    version: "1.0.0",
    declared_licences: declared,
    repo_links: repo_links,
    source: notices.HexPackage(outer_checksum: checksum),
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
  hex: fn(String, String) -> Result(BitArray, notices.FetchError),
  git: fn(repository.Repository, String) -> Result(BitArray, notices.FetchError),
  resolve: fn(repository.Repository, String) ->
    Result(option.Option(String), notices.FetchError),
  archive: fn(repository.Repository, String) ->
    Result(BitArray, notices.FetchError),
  spdx_fetch: fn(spdx.Requirement) ->
    Result(option.Option(String), notices.FetchError),
) -> notices.Clients {
  notices.Clients(
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

fn paths(files: List(notices.NoticeFile)) -> List(String) {
  list.map(files, fn(file) { file.path }) |> list.sort(string.compare)
}

fn fresh_cache_path(name: String) -> String {
  let _ = simplifile.create_directory_all(tmp_dir)
  let path = tmp_dir <> "/" <> name <> ".dets"
  let _ = simplifile.delete(path)
  path
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

  let assert Ok(resolution) =
    notices_resolve.resolve(
      notices_cache.open(notices_cache.Disabled),
      package,
      client,
    )
  let assert notices_resolve.Resolved(files) = resolution.outcome
  should.equal(paths(files), ["./LICENSE", "./NOTICE.txt"])
  should.equal(resolution.warnings, [])
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

  let assert Ok(resolution) =
    notices_resolve.resolve(
      notices_cache.open(notices_cache.Disabled),
      package,
      client,
    )
  let assert notices_resolve.Resolved(files) = resolution.outcome
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

  let assert Ok(resolution) =
    notices_resolve.resolve(
      notices_cache.open(notices_cache.Disabled),
      package,
      client,
    )
  let assert notices_resolve.Resolved(files) = resolution.outcome
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
      fn(_repo, _tag) { Error(notices.FetchNetworkFailure) },
      panic_archive,
      fn(_requirement) { Ok(Some("Canonical MIT text")) },
    )

  let assert Ok(resolution) =
    notices_resolve.resolve(
      notices_cache.open(notices_cache.Disabled),
      package,
      client,
    )
  let assert notices_resolve.Resolved(files) = resolution.outcome
  should.equal(paths(files), ["./NOTICE.txt", "SPDX-License-List/MIT.txt"])
  let assert [warning] = resolution.warnings
  assert string.contains(warning, "Repository fallback for notice_only")
}

pub fn spdx_network_failure_is_hard_error_test() {
  let source = read_bytes("notice_only_hex.tar")
  let package = hex_package("notice_only", checksum_of(source), ["MIT"], [])
  let client =
    clients(
      fn(_n, _v) { Ok(source) },
      panic_git,
      panic_resolve,
      panic_archive,
      fn(_requirement) { Error(notices.FetchNetworkFailure) },
    )

  let assert Error(notices.SpdxFetchFailed("notice_only", "MIT", _)) =
    notices_resolve.resolve(
      notices_cache.open(notices_cache.Disabled),
      package,
      client,
    )
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

  let assert Ok(resolution) =
    notices_resolve.resolve(
      notices_cache.open(notices_cache.Disabled),
      package,
      client,
    )
  should.equal(resolution.outcome, notices_resolve.Missing)
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

  let assert Ok(resolution) =
    notices_resolve.resolve(
      notices_cache.open(notices_cache.Disabled),
      package,
      client,
    )
  let assert notices_resolve.Resolved(files) = resolution.outcome
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

  let assert Ok(resolution) =
    notices_resolve.resolve(
      notices_cache.open(notices_cache.Disabled),
      package,
      client,
    )
  should.equal(resolution.outcome, notices_resolve.Missing)
}

pub fn git_source_skips_repository_fallback_test() {
  let git_source = read_bytes("git_notice_only.tar.gz")
  let repo = repository.Repository(repository.GitHub, "owner", "git_dep")
  let package =
    notices.NoticePackage(
      name: "git_dep",
      version: "1.0.0",
      declared_licences: ["MIT"],
      // Even with a parseable repo link, git sources never retry the repo.
      repo_links: ["https://github.com/owner/git_dep"],
      source: notices.GitPackage(
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

  let assert Ok(resolution) =
    notices_resolve.resolve(
      notices_cache.open(notices_cache.Disabled),
      package,
      client,
    )
  let assert notices_resolve.Resolved(files) = resolution.outcome
  should.equal(paths(files), ["NOTICE.txt", "SPDX-License-List/MIT.txt"])
}

pub fn spdx_records_are_shared_across_packages_test() {
  let path = fresh_cache_path("spdx_shared")
  let source = read_bytes("notice_only_hex.tar")
  let checksum = checksum_of(source)

  // First package resolves Apache-2.0 via the SPDX fallback and caches it.
  let cache = notices_cache.open(notices_cache.Enabled(path: Some(path)))
  let first = hex_package("a", checksum, ["Apache-2.0"], [])
  let assert Ok(_) =
    notices_resolve.resolve(
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
  let assert Ok(resolution) =
    notices_resolve.resolve(
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
  let assert notices_resolve.Resolved(files) = resolution.outcome
  should.equal(paths(files), [
    "./NOTICE.txt",
    "SPDX-License-List/Apache-2.0.txt",
  ])
  let _ = notices_cache.close(cache)
}

pub fn final_cache_key_includes_declared_metadata_test() {
  let path = fresh_cache_path("metadata_key")
  let source = read_bytes("notice_only_hex.tar")
  let checksum = checksum_of(source)
  let cache = notices_cache.open(notices_cache.Enabled(path: Some(path)))

  let assert Ok(first) =
    notices_resolve.resolve(
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
  let assert notices_resolve.Resolved(first_files) = first.outcome
  should.equal(paths(first_files), ["./NOTICE.txt", "SPDX-License-List/MIT.txt"])

  // The immutable source is cached, but changed declared metadata must produce a
  // different final key and resolve the new SPDX identifier.
  let assert Ok(second) =
    notices_resolve.resolve(
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
  let assert notices_resolve.Resolved(second_files) = second.outcome
  should.equal(paths(second_files), [
    "./NOTICE.txt",
    "SPDX-License-List/Apache-2.0.txt",
  ])
  let _ = notices_cache.close(cache)
}

// --- Provider-agnostic git package archive fetch -----------------------------

fn git_package(
  repo: repository.Repository,
  url: String,
  commit: String,
) -> notices.NoticePackage {
  notices.NoticePackage(
    name: "git_dep",
    version: "1.0.0",
    declared_licences: ["MIT"],
    // A parseable repo link is present, but git sources must never retry it.
    repo_links: [url],
    source: notices.GitPackage(repository: repo, url: url, commit: commit),
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

  let assert Ok(resolution) =
    notices_resolve.resolve(
      notices_cache.open(notices_cache.Disabled),
      package,
      client,
    )
  let assert notices_resolve.Resolved(files) = resolution.outcome
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

  let cache = notices_cache.open(notices_cache.Enabled(path: Some(path)))

  // First run: the repository fails transiently, so resolution degrades to the
  // SPDX fallback. That degraded final result must NOT be cached.
  let assert Ok(first) =
    notices_resolve.resolve(
      cache,
      package,
      clients(
        fn(_n, _v) { Ok(source) },
        panic_git,
        fn(_repo, _tag) { Error(notices.FetchNetworkFailure) },
        panic_archive,
        fn(_requirement) { Ok(Some("Canonical MIT text")) },
      ),
    )
  let assert notices_resolve.Resolved(first_files) = first.outcome
  should.equal(paths(first_files), [
    "./NOTICE.txt",
    "SPDX-License-List/MIT.txt",
  ])
  let assert [_warning] = first.warnings

  // Second run: the repository now succeeds. Because the degraded result was
  // not frozen, resolution retries the repository and uses its LICENSE. SPDX
  // must not be consulted (panic_spdx proves no silent final-cache hit either).
  let assert Ok(second) =
    notices_resolve.resolve(
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
  let assert notices_resolve.Resolved(second_files) = second.outcome
  should.equal(paths(second_files), ["./NOTICE.txt", "LICENSE"])
  should.equal(second.warnings, [])
  let _ = notices_cache.close(cache)
}

// --- Disabled cache re-resolves every namespace ------------------------------

pub fn disabled_cache_refetches_across_runs_test() {
  let source = read_bytes("notice_only_hex.tar")
  let package = hex_package("notice_only", checksum_of(source), ["MIT"], [])
  let disabled = notices_cache.open(notices_cache.Disabled)

  // With the cache disabled, the SPDX fallback fetch happens on every run:
  // both resolutions must exercise the live fetcher rather than a cached value.
  let resolve_once = fn() {
    notices_resolve.resolve(
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

  let assert Ok(first) = resolve_once()
  let assert notices_resolve.Resolved(first_files) = first.outcome
  should.equal(paths(first_files), ["./NOTICE.txt", "SPDX-License-List/MIT.txt"])

  // A second run with panic_spdx would explode if a disabled cache had somehow
  // retained the record; instead it must re-fetch, so we assert it succeeds
  // again with the live fetcher above.
  let assert Ok(second) = resolve_once()
  let assert notices_resolve.Resolved(second_files) = second.outcome
  should.equal(paths(second_files), [
    "./NOTICE.txt",
    "SPDX-License-List/MIT.txt",
  ])
}
