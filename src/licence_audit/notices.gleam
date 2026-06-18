import gleam/bool
import gleam/dict.{type Dict}
import gleam/http.{Get, Https}
import gleam/http/request.{type Request, Request}
import gleam/http/response.{type Response}
import gleam/httpc
import gleam/int
import gleam/list
import gleam/option.{None}
import gleam/order
import gleam/result
import gleam/string
import licence_audit/hex
import licence_audit/manifest
import licence_audit/sbom
import licence_audit/source_archive
import simplifile

const source_fetch_timeout_ms = 8000

pub type PackageSource {
  HexPackage(outer_checksum: String)
  GitHubPackage(repo: String, commit: String)
  PathPackage(path: String)
}

pub type FetchError {
  FetchNetworkFailure
  FetchUnexpectedResponse(status: Int)
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

pub fn package_source(
  entry: manifest.SbomEntry,
) -> Result(PackageSource, Error) {
  case entry.provenance {
    manifest.HexProvenance(outer_checksum, _) -> Ok(HexPackage(outer_checksum))
    manifest.PathProvenance(path) -> Ok(PathPackage(path))
    manifest.GitProvenance(repo, commit) ->
      case sbom.parse_github_repo(repo) {
        Ok(_) -> Ok(GitHubPackage(repo: repo, commit: commit))
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

pub fn entries_from_sources(
  packages: List(NoticePackage),
  read_source: fn(NoticePackage) ->
    Result(List(source_archive.ArchiveFile), Error),
) -> Result(List(NoticeEntry), Error) {
  entries_from_sources_loop(packages, read_source, [], [])
}

pub fn read_remote_source(
  package: NoticePackage,
  fetch_hex_tarball: fn(String, String) -> Result(BitArray, FetchError),
  fetch_github_tarball: fn(String, String, String) ->
    Result(BitArray, FetchError),
) -> Result(List(source_archive.ArchiveFile), Error) {
  case package.source {
    HexPackage(outer_checksum) ->
      read_hex_source(package, outer_checksum, fetch_hex_tarball)
    GitHubPackage(repo, commit) ->
      read_github_source(package, repo, commit, fetch_github_tarball)
    PathPackage(path) -> read_path_source(package.name, path)
  }
}

pub fn fetch_hex_tarball_from_hex(
  name: String,
  version: String,
) -> Result(BitArray, FetchError) {
  fetch_tarball(hex_tarball_request(name, version))
}

pub fn fetch_github_tarball_from_github(
  owner: String,
  repo: String,
  commit: String,
) -> Result(BitArray, FetchError) {
  fetch_tarball(github_tarball_request(owner, repo, commit))
}

pub fn describe_fetch_error(error: FetchError) -> String {
  case error {
    FetchNetworkFailure -> "network failure"
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
  let sections =
    entries
    |> list.sort(by: fn(a, b) { compare_package(a.package, b.package) })
    |> list.map(render_entry)

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

fn read_github_source(
  package: NoticePackage,
  repo: String,
  commit: String,
  fetch_github_tarball: fn(String, String, String) ->
    Result(BitArray, FetchError),
) -> Result(List(source_archive.ArchiveFile), Error) {
  case sbom.parse_github_repo(repo) {
    Error(_) -> Error(UnsupportedSource(package.name, "git", "repo: " <> repo))
    Ok(#(owner, repo_name)) -> {
      use bytes <- result.try(
        fetch_github_tarball(owner, repo_name, commit)
        |> result.map_error(fn(error) {
          FetchFailed(package.name, describe_fetch_error(error))
        }),
      )
      source_archive.extract_tar_gz(bytes)
      |> result.map_error(fn(error) {
        ArchiveFailed(package.name, source_archive.describe_error(error))
      })
    }
  }
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

fn entries_from_sources_loop(
  packages: List(NoticePackage),
  read_source: fn(NoticePackage) ->
    Result(List(source_archive.ArchiveFile), Error),
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
        Ok(files) ->
          case licence_files(files) {
            Error(error) ->
              Error(ArchiveFailed(
                package: package.name,
                reason: source_archive.describe_error(error),
              ))
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
  |> list.map(fn(file) {
    file.contents
    |> normalize_line_endings
    |> ensure_trailing_newline
  })
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
