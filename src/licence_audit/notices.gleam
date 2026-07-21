import gleam/bool
import gleam/dict.{type Dict}
import gleam/dynamic/decode
import gleam/http.{Get, Https}
import gleam/http/request.{type Request, Request}
import gleam/http/response.{type Response}
import gleam/httpc
import gleam/int
import gleam/json
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/order
import gleam/result
import gleam/string
import licence_audit/hex
import licence_audit/httpc_adaptive
import licence_audit/manifest
import licence_audit/repository
import licence_audit/source_archive
import licence_audit/spdx
import simplifile

const source_fetch_timeout_ms = 30_000

/// Timeout for the small JSON metadata requests used by the fallback path
/// (repository tag resolution and SPDX detail records).
const metadata_fetch_timeout_ms = 10_000

pub type PackageSource {
  HexPackage(outer_checksum: String)
  /// A dependency fetched directly from a git host at an immutable manifest
  /// commit. `repository` is the normalized provider identity used to build the
  /// archive request; `url` is the original manifest-recorded source URL,
  /// preserved verbatim for rendering.
  GitPackage(repository: repository.Repository, url: String, commit: String)
  PathPackage(path: String)
}

pub type FetchError {
  FetchNetworkFailure
  /// A request timed out at the 30s source-archive default. Kept as a
  /// nullary variant for source compatibility with existing callers/tests
  /// that construct or match on `FetchTimeout` directly.
  FetchTimeout
  /// A request timed out at a duration other than the 30s source-archive
  /// default (e.g. the 10s metadata fetches used by the repository/SPDX
  /// fallback). Carries the timeout in seconds so `describe_fetch_error`
  /// reports the actual configured duration rather than assuming 30s.
  FetchTimeoutAfter(seconds: Int)
  FetchUnexpectedResponse(status: Int)
}

pub type NoticePackage {
  NoticePackage(
    name: String,
    version: String,
    declared_licences: List(String),
    /// Candidate source-repository URLs (from Hex `meta.links` or a local
    /// `gleam.toml`), consulted by the repository fallback when the package's
    /// own source archive ships no licence text.
    repo_links: List(String),
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

type LicenceProduct {
  LicenceProduct(package: NoticePackage, paths: List(String))
}

type LicenceGroup {
  LicenceGroup(text: String, products: List(LicenceProduct))
}

/// Injected HTTP clients for every network operation the notices flow performs.
/// Bundling them keeps call signatures stable as the fallback grows and lets
/// tests substitute deterministic fakes without touching the network.
pub type Clients {
  Clients(
    fetch_hex_tarball: fn(String, String) -> Result(BitArray, FetchError),
    /// Fetch a git package's source archive at its immutable manifest commit.
    /// Provider-agnostic: the `repository.Repository` carries the parsed
    /// provider (GitHub, GitLab, or Codeberg) so the correct archive endpoint
    /// is used. Never resolves tags or HEAD — the commit is fixed.
    fetch_git_archive: fn(repository.Repository, String) ->
      Result(BitArray, FetchError),
    /// Resolve a repository tag to an immutable commit SHA. `Ok(Some(sha))`
    /// resolved, `Ok(None)` tag not found (try the next candidate), `Error`
    /// transient network/API failure (surface a warning and fall through).
    resolve_commit: fn(repository.Repository, String) ->
      Result(Option(String), FetchError),
    fetch_repo_archive: fn(repository.Repository, String) ->
      Result(BitArray, FetchError),
    fetch_spdx_index: fn(spdx.IndexKind) -> Result(List(String), FetchError),
    /// Fetch canonical SPDX text for a requirement. `Ok(Some(text))` resolved,
    /// `Ok(None)` unknown identifier, `Error` transient network failure.
    fetch_spdx: fn(spdx.Requirement) -> Result(Option(String), FetchError),
  )
}

/// The default clients, wired to the real Hex, provider, and SPDX endpoints.
pub fn default_clients() -> Clients {
  Clients(
    fetch_hex_tarball: fetch_hex_tarball_from_hex,
    fetch_git_archive: fetch_git_archive_from_provider,
    resolve_commit: resolve_commit_from_provider,
    fetch_repo_archive: fetch_repo_archive_from_provider,
    fetch_spdx_index: fetch_spdx_index,
    fetch_spdx: fetch_spdx_text,
  )
}

/// Build `Clients` from just a Hex tarball fetcher and a legacy GitHub tarball
/// fetcher (`fn(owner, repo, commit)`), defaulting the fallback (repository +
/// SPDX) clients to their real network implementations. Retained so existing
/// callers that only override the tarball fetchers keep working; the GitHub
/// fetcher is adapted to the provider-agnostic `fetch_git_archive` client by
/// projecting the parsed repository's owner/repo, so it only serves GitHub git
/// packages. The fully-injected/default flow supports every provider.
pub fn clients_with_tarball_fetchers(
  fetch_hex_tarball: fn(String, String) -> Result(BitArray, FetchError),
  fetch_github_tarball: fn(String, String, String) ->
    Result(BitArray, FetchError),
) -> Clients {
  Clients(
    ..default_clients(),
    fetch_hex_tarball: fetch_hex_tarball,
    fetch_git_archive: fn(repo: repository.Repository, commit: String) {
      case repo.provider {
        repository.GitHub -> fetch_github_tarball(repo.owner, repo.repo, commit)
        repository.GitLab | repository.Codeberg ->
          fetch_git_archive_from_provider(repo, commit)
      }
    },
  )
}

pub type Error {
  MissingLicenceText(packages: List(String))
  MetadataFailed(package: String, reason: String)
  UnsupportedSource(package: String, source: String, detail: String)
  FetchFailed(package: String, reason: String)
  ArchiveFailed(package: String, reason: String)
  ChecksumMismatch(package: String, expected: String, actual: String)
  PathReadFailed(package: String, path: String, reason: String)
  SpdxFetchFailed(package: String, id: String, reason: String)
  OutputWriteFailed(path: String, reason: String)
}

type ArchiveRootPath {
  ArchiveRootPath(root: String, path: String)
  NoArchiveRootPath
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

pub fn packages_from_entries(
  entries: List(manifest.SbomEntry),
  scopes: Dict(String, manifest.Scope),
  metadata_for: fn(manifest.SbomEntry) -> Result(hex.PackageMetadata, Error),
) -> Result(List(NoticePackage), Error) {
  list.try_map(entries, fn(entry) {
    use source <- result.try(package_source(entry))
    use metadata <- result.try(metadata_for(entry))
    Ok(NoticePackage(
      name: entry.name,
      version: entry.version,
      declared_licences: metadata.licences,
      repo_links: repo_link_urls(metadata.links),
      source: source,
      scope: scope_for(scopes, entry.name),
    ))
  })
}

/// Extract the URL of each metadata link, preserving order and de-duplicating.
/// These become the candidate repositories the fallback follows.
fn repo_link_urls(links: List(#(String, String))) -> List(String) {
  links
  |> list.filter(fn(pair) { is_repository_link_label(pair.0) })
  |> list.fold([], fn(seen, pair) {
    case list.contains(seen, pair.1) {
      True -> seen
      False -> [pair.1, ..seen]
    }
  })
  |> list.reverse
}

fn is_repository_link_label(label: String) -> Bool {
  list.contains(
    ["repository", "source", "source code", "github", "gitlab", "codeberg"],
    string.lowercase(string.trim(label)),
  )
}

pub fn package_source(
  entry: manifest.SbomEntry,
) -> Result(PackageSource, Error) {
  case entry.provenance {
    manifest.HexProvenance(outer_checksum, _) -> Ok(HexPackage(outer_checksum))
    manifest.PathProvenance(path) -> Ok(PathPackage(path))
    manifest.GitProvenance(repo, commit) ->
      case repository.parse(repo) {
        Ok(repository_value) ->
          Ok(GitPackage(repository: repository_value, url: repo, commit: commit))
        Error(_) ->
          Error(UnsupportedSource(
            package: entry.name,
            source: "git",
            detail: "repo: " <> repo,
          ))
      }
    manifest.UnknownProvenance(source) ->
      Error(UnsupportedSource(
        package: entry.name,
        source: source,
        detail: "unsupported source",
      ))
  }
}

pub fn licence_files(
  files: List(source_archive.ArchiveFile),
) -> Result(List(NoticeFile), source_archive.ArchiveError) {
  files
  |> strip_common_archive_root
  |> matched_archive_files
  |> list.try_map(to_notice_file)
}

/// Filter raw archive files down to the matched notice/licence files, mapping
/// any extraction failure into a `notices.Error` tagged with `package_name`.
pub fn notice_files_of(
  package_name: String,
  files: List(source_archive.ArchiveFile),
) -> Result(List(NoticeFile), Error) {
  licence_files(files)
  |> result.map_error(fn(error) {
    ArchiveFailed(
      package: package_name,
      reason: source_archive.describe_error(error),
    )
  })
}

/// Serialise notice files for the on-disk cache as a JSON array of
/// `{path, contents}` objects.
pub fn encode_notice_files(files: List(NoticeFile)) -> String {
  json.to_string(
    json.array(files, fn(file) {
      json.object([
        #("path", json.string(file.path)),
        #("contents", json.string(file.contents)),
      ])
    }),
  )
}

/// Parse notice files written by `encode_notice_files`. Returns `Error(Nil)` on
/// any malformed entry so the caller can treat it as a cache miss.
pub fn decode_notice_files(encoded: String) -> Result(List(NoticeFile), Nil) {
  json.parse(encoded, decode.list(notice_file_decoder()))
  |> result.replace_error(Nil)
}

fn notice_file_decoder() -> decode.Decoder(NoticeFile) {
  use path <- decode.field("path", decode.string)
  use contents <- decode.field("contents", decode.string)
  decode.success(NoticeFile(path: path, contents: contents))
}

pub fn entries_from_sources(
  packages: List(NoticePackage),
  read_source: fn(NoticePackage) -> Result(List(NoticeFile), Error),
) -> Result(List(NoticeEntry), Error) {
  entries_from_sources_loop(packages, read_source, [], [])
}

pub fn read_remote_source(
  package: NoticePackage,
  fetch_hex_tarball: fn(String, String) -> Result(BitArray, FetchError),
  fetch_git_archive: fn(repository.Repository, String) ->
    Result(BitArray, FetchError),
) -> Result(List(source_archive.ArchiveFile), Error) {
  case package.source {
    HexPackage(outer_checksum) ->
      read_hex_source(package, outer_checksum, fetch_hex_tarball)
    GitPackage(repo, _url, commit) ->
      read_git_source(package, repo, commit, fetch_git_archive)
    PathPackage(path) -> read_path_source(package.name, path)
  }
}

fn fetch_hex_tarball_from_hex(
  name: String,
  version: String,
) -> Result(BitArray, FetchError) {
  fetch_tarball(hex_tarball_request(name, version))
}

/// Real `fetch_git_archive` client: download a git package's gzip tar archive
/// directly from its provider at the immutable manifest commit. This is the
/// provider-agnostic replacement for a GitHub-only tarball fetcher; the
/// `repository.Repository` selects the correct host and archive path.
fn fetch_git_archive_from_provider(
  repo: repository.Repository,
  commit: String,
) -> Result(BitArray, FetchError) {
  fetch_tarball(repository.archive_request(repo, commit))
}

/// Real `resolve_commit` client: query the provider's API to turn `tag` into an
/// immutable commit SHA. A 404 means the tag doesn't exist (`Ok(None)`), so the
/// caller can try the next candidate; other non-2xx and transport errors are
/// transient failures.
fn resolve_commit_from_provider(
  repo: repository.Repository,
  tag: String,
) -> Result(Option(String), FetchError) {
  use #(status, body) <- result.try(
    fetch_json(repository.commit_request(repo, tag)),
  )
  commit_response(repo, status, body)
}

/// Pure mapping of a repository commit-resolution HTTP `#(status, body)` to an
/// outcome, split out from the network call so status handling is testable
/// without live traffic: 404 → tag not found, 2xx → decode the SHA (a missing
/// field is also "not found"), any other status → transient failure.
pub fn commit_response(
  repo: repository.Repository,
  status: Int,
  body: String,
) -> Result(Option(String), FetchError) {
  case repo.provider, status {
    _, 404 -> Ok(None)
    // GitHub's commits API returns 422 when a syntactically valid ref does not
    // resolve, so this is a tag miss rather than a transient provider failure.
    repository.GitHub, 422 -> Ok(None)
    _, status if status >= 200 && status < 300 ->
      case repository.decode_commit(repo, body) {
        Ok(sha) -> Ok(Some(sha))
        Error(_) -> Ok(None)
      }
    _, status -> Error(FetchUnexpectedResponse(status))
  }
}

/// Real `fetch_repo_archive` client: download the provider's gzip tar archive at
/// an immutable commit.
fn fetch_repo_archive_from_provider(
  repo: repository.Repository,
  commit: String,
) -> Result(BitArray, FetchError) {
  fetch_tarball(repository.archive_request(repo, commit))
}

/// Real `fetch_spdx` client: fetch a canonical SPDX detail record from the
/// pinned License List revision. A 404 means the identifier is unknown
/// (`Ok(None)`).
fn fetch_spdx_text(
  requirement: spdx.Requirement,
) -> Result(Option(String), FetchError) {
  use #(status, body) <- result.try(
    fetch_json(spdx.detail_request(requirement)),
  )
  spdx_response(requirement, status, body)
}

fn fetch_spdx_index(kind: spdx.IndexKind) -> Result(List(String), FetchError) {
  use #(status, body) <- result.try(fetch_json(spdx.index_request(kind)))
  case status {
    status if status >= 200 && status < 300 ->
      spdx.decode_index(kind, body)
      |> result.replace_error(FetchUnexpectedResponse(status))
    status -> Error(FetchUnexpectedResponse(status))
  }
}

/// Pure mapping of an SPDX detail-record HTTP `#(status, body)` to an outcome,
/// split out from the network call so status handling is testable without live
/// traffic: 404 → unknown identifier, 2xx → decode the canonical text (a
/// missing field is also "unknown"), any other status → transient failure.
pub fn spdx_response(
  requirement: spdx.Requirement,
  status: Int,
  body: String,
) -> Result(Option(String), FetchError) {
  case status {
    404 -> Ok(None)
    status if status >= 200 && status < 300 ->
      case spdx.decode_text(requirement, body) {
        Ok(text) -> Ok(Some(text))
        Error(_) -> Ok(None)
      }
    status -> Error(FetchUnexpectedResponse(status))
  }
}

/// Dispatch a small JSON GET, returning `#(status, body)` or a transport
/// error mapped onto `FetchError`.
fn fetch_json(request: Request(String)) -> Result(#(Int, String), FetchError) {
  let request = request.set_header(request, "user-agent", "licence_audit")
  case httpc_adaptive.dispatch(request, timeout_ms: metadata_fetch_timeout_ms) {
    Ok(response) -> Ok(#(response.status, response.body))
    Error(httpc_adaptive.ResponseTimeout) ->
      Error(FetchTimeoutAfter(metadata_fetch_timeout_ms / 1000))
    Error(_) -> Error(FetchNetworkFailure)
  }
}

pub fn describe_fetch_error(error: FetchError) -> String {
  case error {
    FetchNetworkFailure -> "network failure"
    FetchTimeout ->
      "timed out after " <> int.to_string(source_fetch_timeout_ms / 1000) <> "s"
    FetchTimeoutAfter(seconds) ->
      "timed out after " <> int.to_string(seconds) <> "s"
    FetchUnexpectedResponse(status) ->
      "unexpected HTTP response " <> int.to_string(status)
  }
}

pub fn render(
  entries: List(NoticeEntry),
  manifest_path manifest_path: String,
) -> String {
  let header =
    "Third-party licences\n"
    <> "Generated by licence_audit notices from "
    <> manifest_path
    <> ".\n\n"
  let licence_sections =
    entries
    |> licence_groups
    |> list.map(render_licence_group)
  let notice_sections =
    entries
    |> ancillary_notice_entries
    |> list.sort(by: fn(a, b) { compare_package(a.package, b.package) })
    |> list.map(render_notice_entry)
  let sections = list.append(licence_sections, notice_sections)

  case sections {
    [] -> header
    _ -> header <> string.join(sections, "\n")
  }
}

pub fn describe_error(error: Error) -> String {
  case error {
    MissingLicenceText(packages) ->
      "Missing licence text for packages: "
      <> string.join(list.sort(packages, by: string.compare), ", ")
    MetadataFailed(package, reason) ->
      "Failed to resolve licence metadata for " <> package <> ": " <> reason
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
    SpdxFetchFailed(package, id, reason) ->
      "Failed to fetch canonical SPDX text for "
      <> package
      <> " ("
      <> id
      <> "): "
      <> reason
    OutputWriteFailed(path, reason) ->
      "Failed to write notices to " <> path <> ": " <> reason
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

fn read_hex_source(
  package: NoticePackage,
  expected_checksum: String,
  fetch_hex_tarball: fn(String, String) -> Result(BitArray, FetchError),
) -> Result(List(source_archive.ArchiveFile), Error) {
  use bytes <- result.try(
    fetch_hex_tarball(package.name, package.version)
    |> result.map_error(fn(error) {
      FetchFailed(package.name, describe_fetch_error(error))
    }),
  )
  use actual_checksum <- result.try(
    source_archive.sha256_hex(bytes)
    |> result.map_error(fn(error) {
      ArchiveFailed(package.name, source_archive.describe_error(error))
    }),
  )
  use <- bool.guard(
    when: string.uppercase(expected_checksum) != actual_checksum,
    return: Error(ChecksumMismatch(
      package.name,
      expected_checksum,
      actual_checksum,
    )),
  )
  source_archive.extract_hex_contents(bytes)
  |> result.map_error(fn(error) {
    ArchiveFailed(package.name, source_archive.describe_error(error))
  })
}

fn read_git_source(
  package: NoticePackage,
  repo: repository.Repository,
  commit: String,
  fetch_git_archive: fn(repository.Repository, String) ->
    Result(BitArray, FetchError),
) -> Result(List(source_archive.ArchiveFile), Error) {
  use bytes <- result.try(
    fetch_git_archive(repo, commit)
    |> result.map_error(fn(error) {
      FetchFailed(package.name, describe_fetch_error(error))
    }),
  )
  source_archive.extract_tar_gz(bytes)
  |> result.map_error(fn(error) {
    ArchiveFailed(package.name, source_archive.describe_error(error))
  })
}

fn read_path_source(
  package_name: String,
  path: String,
) -> Result(List(source_archive.ArchiveFile), Error) {
  use files <- result.try(read_path_files(package_name, path))

  files
  |> list.sort(string.compare)
  |> list.try_map(read_path_file(package_name, path, _))
}

fn read_path_files(
  package_name: String,
  path: String,
) -> Result(List(String), Error) {
  use children <- result.try(
    simplifile.read_directory(at: path)
    |> result.map_error(fn(error) {
      PathReadFailed(package_name, path, simplifile.describe_error(error))
    }),
  )
  use files, child <- list.try_fold(over: children, from: [])
  let child_path = join_path(path, child)
  use info <- result.try(
    simplifile.link_info(child_path)
    |> result.map_error(fn(error) {
      PathReadFailed(package_name, child_path, simplifile.describe_error(error))
    }),
  )

  case simplifile.file_info_type(info) {
    simplifile.File -> Ok([child_path, ..files])
    simplifile.Directory -> {
      use nested_files <- result.try(read_path_files(package_name, child_path))
      Ok(list.append(files, nested_files))
    }
    simplifile.Symlink | simplifile.Other -> Ok(files)
  }
}

fn read_path_file(
  package_name: String,
  root: String,
  file_path: String,
) -> Result(source_archive.ArchiveFile, Error) {
  use contents <- result.try(
    simplifile.read_bits(from: file_path)
    |> result.map_error(fn(error) {
      PathReadFailed(package_name, file_path, simplifile.describe_error(error))
    }),
  )
  Ok(source_archive.ArchiveFile(
    path: relative_path(file_path, root),
    contents: contents,
  ))
}

fn join_path(parent: String, child: String) -> String {
  case string.ends_with(parent, "/") {
    True -> parent <> child
    False -> parent <> "/" <> child
  }
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

fn fetch_tarball(request: Request(BitArray)) -> Result(BitArray, FetchError) {
  let request = request.set_header(request, "user-agent", "licence_audit")
  case
    httpc.configure()
    |> httpc.timeout(source_fetch_timeout_ms)
    |> httpc.dispatch_bits(request)
  {
    Ok(response) -> decode_fetch_response(response)
    Error(httpc.ResponseTimeout) -> Error(FetchTimeout)
    Error(_) -> Error(FetchNetworkFailure)
  }
}

fn decode_fetch_response(
  response: Response(BitArray),
) -> Result(BitArray, FetchError) {
  case response.status {
    status if status >= 200 && status < 300 -> Ok(response.body)
    status -> Error(FetchUnexpectedResponse(status))
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

fn entries_from_sources_loop(
  packages: List(NoticePackage),
  read_source: fn(NoticePackage) -> Result(List(NoticeFile), Error),
  entries: List(NoticeEntry),
  missing: List(String),
) -> Result(List(NoticeEntry), Error) {
  case packages {
    [] ->
      case list.reverse(missing) {
        [] -> Ok(list.reverse(entries))
        missing_packages -> Error(MissingLicenceText(missing_packages))
      }
    [package, ..rest] ->
      case read_source(package) {
        Error(error) -> Error(error)
        Ok([]) ->
          entries_from_sources_loop(rest, read_source, entries, [
            package.name,
            ..missing
          ])
        Ok(notice_files) ->
          entries_from_sources_loop(
            rest,
            read_source,
            [NoticeEntry(package: package, files: notice_files), ..entries],
            missing,
          )
      }
  }
}

fn matched_archive_files(
  files: List(source_archive.ArchiveFile),
) -> List(source_archive.ArchiveFile) {
  let root_matches =
    files
    |> list.filter(fn(file) { is_root_notice_file(file.path) })
    |> sort_archive_files

  case root_matches {
    [] ->
      files
      |> list.filter(fn(file) { is_any_notice_file(file.path) })
      |> sort_archive_files
    _ -> root_matches
  }
}

fn strip_common_archive_root(
  files: List(source_archive.ArchiveFile),
) -> List(source_archive.ArchiveFile) {
  case common_archive_root(files) {
    Ok(_) -> list.map(files, strip_archive_root)
    Error(Nil) -> files
  }
}

fn common_archive_root(
  files: List(source_archive.ArchiveFile),
) -> Result(String, Nil) {
  case files {
    [] -> Error(Nil)
    [first, ..rest] ->
      case archive_root_path(first.path) {
        ArchiveRootPath(root: root, path: _) -> {
          use <- bool.guard(
            when: !list.all(rest, fn(file) { shares_archive_root(file, root) }),
            return: Error(Nil),
          )
          Ok(root)
        }
        NoArchiveRootPath -> Error(Nil)
      }
  }
}

fn shares_archive_root(file: source_archive.ArchiveFile, root: String) -> Bool {
  case archive_root_path(file.path) {
    ArchiveRootPath(root: other, path: _) -> other == root
    NoArchiveRootPath -> False
  }
}

fn strip_archive_root(
  file: source_archive.ArchiveFile,
) -> source_archive.ArchiveFile {
  case archive_root_path(file.path) {
    ArchiveRootPath(root: _, path: path) ->
      source_archive.ArchiveFile(path: path, contents: file.contents)
    NoArchiveRootPath -> file
  }
}

fn archive_root_path(path: String) -> ArchiveRootPath {
  let normalized = drop_optional_current_dir(path)
  case string.split(normalized, on: "/") {
    [root, next, ..rest] -> {
      let stripped_path = string.join([next, ..rest], "/")
      use <- bool.guard(
        when: root == "" || stripped_path == "",
        return: NoArchiveRootPath,
      )
      ArchiveRootPath(root: root, path: stripped_path)
    }
    _ -> NoArchiveRootPath
  }
}

fn to_notice_file(
  file: source_archive.ArchiveFile,
) -> Result(NoticeFile, source_archive.ArchiveError) {
  use contents <- result.try(source_archive.text_contents(file))
  Ok(NoticeFile(path: file.path, contents: contents))
}

fn sort_archive_files(
  files: List(source_archive.ArchiveFile),
) -> List(source_archive.ArchiveFile) {
  list.sort(files, by: fn(a, b) { string.compare(a.path, b.path) })
}

fn sort_notice_files(files: List(NoticeFile)) -> List(NoticeFile) {
  list.sort(files, by: fn(a, b) { string.compare(a.path, b.path) })
}

fn is_root_notice_file(path: String) -> Bool {
  let normalized = drop_optional_current_dir(path)
  !string.contains(normalized, "/") && is_notice_basename(normalized)
}

fn is_any_notice_file(path: String) -> Bool {
  path
  |> drop_optional_current_dir
  |> basename
  |> is_notice_basename
}

fn drop_optional_current_dir(path: String) -> String {
  use <- bool.guard(when: !string.starts_with(path, "./"), return: path)
  string.drop_start(path, 2)
}

fn basename(path: String) -> String {
  case string.split(path, on: "/") |> list.reverse {
    [name, ..] -> name
    [] -> path
  }
}

fn is_notice_basename(name: String) -> Bool {
  matches_basename(name, ["license", "licence", "copying", "notice"])
}

/// A licence-text file, as opposed to an ancillary NOTICE/attribution file.
/// `COPYING` is the GNU convention for licence text, so it counts as a licence.
fn is_licence_basename(name: String) -> Bool {
  matches_basename(name, ["license", "licence", "copying"])
}

fn matches_basename(name: String, bases: List(String)) -> Bool {
  let lower = string.lowercase(name)
  list.any(bases, fn(base) {
    lower == base
    || lower == base <> ".txt"
    || lower == base <> ".md"
    || lower == base <> ".rst"
    || lower == base <> ".adoc"
  })
}

/// Whether `files` already contain an actual licence-text file (LICENSE,
/// LICENCE, or COPYING). A package whose source ships only a NOTICE file — or
/// nothing — returns `False` and must obtain its licence via the fallback.
pub fn has_licence_file(files: List(NoticeFile)) -> Bool {
  list.any(files, fn(file) {
    file.path
    |> drop_optional_current_dir
    |> basename
    |> is_licence_basename
  })
}

/// Keep only the licence-text files from a list, dropping ancillary NOTICE
/// files. Used to lift a licence out of a fallback repository archive without
/// pulling in that repo's own NOTICE.
pub fn licence_files_only(files: List(NoticeFile)) -> List(NoticeFile) {
  list.filter(files, fn(file) {
    file.path
    |> drop_optional_current_dir
    |> basename
    |> is_licence_basename
  })
}

/// Extract the licence-text files from a fallback repository's gzip tar
/// archive. Ancillary NOTICE files from the repository are dropped; only the
/// actual licence text is lifted. Extraction failures are tagged to
/// `package_name`.
pub fn repo_licence_files(
  package_name: String,
  bytes: BitArray,
) -> Result(List(NoticeFile), Error) {
  use files <- result.try(
    source_archive.extract_tar_gz(bytes)
    |> result.map_error(fn(error) {
      ArchiveFailed(package_name, source_archive.describe_error(error))
    }),
  )
  use notices <- result.try(notice_files_of(package_name, files))
  Ok(licence_files_only(notices))
}

/// Build the synthetic notice file for a resolved SPDX record, labelling its
/// origin via a `SPDX-License-List/<id>.txt` path. The canonical text is stored
/// verbatim.
pub fn spdx_file(requirement: spdx.Requirement, text: String) -> NoticeFile {
  NoticeFile(path: spdx.synthetic_path(requirement), contents: text)
}

fn compare_package(a: NoticePackage, b: NoticePackage) -> order.Order {
  case string.compare(a.name, b.name) {
    order.Eq -> string.compare(a.version, b.version)
    other -> other
  }
}

fn licence_groups(entries: List(NoticeEntry)) -> List(LicenceGroup) {
  entries
  |> list.fold(dict.new(), fn(groups, entry) {
    entry.files
    |> list.filter(is_licence_file)
    |> list.fold(groups, fn(inner, file) {
      let text = normalized_file_contents(file.contents)
      let products = dict.get(inner, text) |> result.unwrap([])
      dict.insert(
        inner,
        text,
        add_licence_product(products, entry.package, file.path),
      )
    })
  })
  |> dict.to_list
  |> list.map(fn(group) {
    LicenceGroup(
      text: group.0,
      products: list.sort(group.1, by: compare_licence_product),
    )
  })
  |> list.sort(by: compare_licence_group)
}

fn add_licence_product(
  products: List(LicenceProduct),
  package: NoticePackage,
  path: String,
) -> List(LicenceProduct) {
  case products {
    [] -> [LicenceProduct(package:, paths: [path])]
    [product, ..rest] ->
      case compare_package(product.package, package) {
        order.Eq -> [
          LicenceProduct(
            ..product,
            paths: [path, ..product.paths] |> list.unique,
          ),
          ..rest
        ]
        _ -> [product, ..add_licence_product(rest, package, path)]
      }
  }
}

fn compare_licence_product(
  a: LicenceProduct,
  b: LicenceProduct,
) -> order.Order {
  compare_package(a.package, b.package)
}

fn compare_licence_group(a: LicenceGroup, b: LicenceGroup) -> order.Order {
  case a.products, b.products {
    [a_product, ..], [b_product, ..] ->
      case compare_licence_product(a_product, b_product) {
        order.Eq -> string.compare(a.text, b.text)
        other -> other
      }
    [], [] -> string.compare(a.text, b.text)
    [], _ -> order.Lt
    _, [] -> order.Gt
  }
}

fn ancillary_notice_entries(entries: List(NoticeEntry)) -> List(NoticeEntry) {
  list.filter_map(entries, fn(entry) {
    let files = list.filter(entry.files, fn(file) { !is_licence_file(file) })
    case files {
      [] -> Error(Nil)
      _ -> Ok(NoticeEntry(..entry, files: files))
    }
  })
}

fn is_licence_file(file: NoticeFile) -> Bool {
  let path = drop_optional_current_dir(file.path)
  string.starts_with(path, "SPDX-License-List/")
  || path |> basename |> is_licence_basename
}

fn render_licence_group(group: LicenceGroup) -> String {
  separator("=")
  <> "\n"
  <> "Products using this licence:\n"
  <> string.concat(list.map(group.products, render_licence_product))
  <> separator("-")
  <> "\n"
  <> group.text
}

fn render_licence_product(product: LicenceProduct) -> String {
  "  "
  <> product.package.name
  <> " "
  <> product.package.version
  <> "\n"
  <> "    Source: "
  <> source_text(product.package.source)
  <> "\n"
  <> "    Declared licences: "
  <> declared_licences_text(product.package.declared_licences)
  <> "\n"
  <> "    Licence files: "
  <> string.join(list.sort(product.paths, by: string.compare), ", ")
  <> "\n"
}

fn render_notice_entry(entry: NoticeEntry) -> String {
  let files = sort_notice_files(entry.files)
  separator("=")
  <> "\n"
  <> "Additional notices for "
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
  <> "Notice files: "
  <> string.join(list.map(files, fn(file) { file.path }), ", ")
  <> "\n"
  <> separator("-")
  <> "\n"
  <> render_files(files)
}

fn render_files(files: List(NoticeFile)) -> String {
  files
  |> list.map(fn(file) { normalized_file_contents(file.contents) })
  |> string.join(with: "\n")
}

fn normalized_file_contents(contents: String) -> String {
  contents
  |> normalize_line_endings
  |> ensure_trailing_newline
}

fn source_text(source: PackageSource) -> String {
  case source {
    HexPackage(_) -> "hex"
    GitPackage(_repo, url, commit) -> "git " <> url <> " @ " <> commit
    PathPackage(path) -> "path " <> path
  }
}

fn declared_licences_text(licences: List(String)) -> String {
  case licences {
    [] -> "unknown"
    _ -> string.join(licences, ", ")
  }
}

fn normalize_line_endings(text: String) -> String {
  text
  |> string.replace("\r\n", "\n")
  |> string.replace("\r", "\n")
}

fn ensure_trailing_newline(text: String) -> String {
  use <- bool.guard(when: string.ends_with(text, "\n"), return: text)
  text <> "\n"
}

fn separator(char: String) -> String {
  string.repeat(char, times: 80)
}
