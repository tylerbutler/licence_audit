//// Per-package licence-materials resolution with the fallback chain.
////
//// Resolution order, honouring source-archive priority:
////
//// 1. **Source archive.** Read the package's own source (Hex tarball, git
////    archive at the manifest commit, or a local path) and keep every notice
////    file it ships. If that includes an actual licence file (LICENSE /
////    LICENCE / COPYING) resolution stops here.
//// 2. **Repository fallback** (Hex packages only — git sources are already the
////    repository at an immutable commit, so a retry cannot help). Follow the
////    package's declared repository links, resolve a deterministic tag
////    (`v<version>` then `<version>`) to an immutable commit SHA, download the
////    repository archive at that SHA, and lift its licence text. Any NOTICE
////    file found in step 1 is preserved alongside the recovered licence.
//// 3. **SPDX fallback.** Expand the declared SPDX identifiers/expressions to
////    canonical licence text from the pinned SPDX License List revision.
////
//// Every network result is cached in the shared `notices_cache` under an
//// immutable key so repeated runs — and packages that share an SPDX licence —
//// avoid redundant traffic. Repository network/API failures are non-fatal:
//// they surface a deferred warning and resolution continues to the SPDX
//// fallback. When that happens the final per-package result is deliberately
//// *not* cached, so a later run retries the repository instead of being frozen
//// on the degraded SPDX material; successful per-namespace values (SPDX
//// records, tag→commit resolutions, repository archives) are still cached. An
//// SPDX network failure with no cached record, when a fallback is required, is
//// a hard error.

import gleam/bit_array
import gleam/json
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string

import licence_audit/cache_dir
import licence_audit/notice
import licence_audit/notice_cache
import licence_audit/repository
import licence_audit/source_archive
import licence_audit/spdx

/// The result of resolving one package.
pub type Outcome {
  /// Licence materials were found (source, repository, or SPDX fallback).
  Resolved(files: List(notice.NoticeFile))
  /// No licence text could be obtained; the package is reported as missing.
  Missing
}

pub type Resolution {
  Resolution(outcome: Outcome, warnings: List(String))
}

/// Resolve a single package's licence materials, consulting and populating the
/// cache. `package` must already have any path source resolved to a concrete
/// location.
pub fn resolve(
  cache: notice_cache.Cache,
  package: notice.NoticePackage,
  clients: notice.Clients,
) -> #(Result(Resolution, notice.Error), Option(String)) {
  case final_key(package) {
    Ok(key) -> {
      use cached <- cache_dir.with_warning(cached_final_files(
        cache,
        key,
        package,
      ))
      case cached {
        Ok(files) -> #(
          Ok(Resolution(outcome: Resolved(files), warnings: [])),
          None,
        )
        Error(_) -> {
          use resolution <- cache_dir.try_with_warning(resolve_fresh(
            cache,
            package,
            clients,
          ))
          let warning = case resolution.outcome, resolution.warnings {
            // Only freeze the final per-package result when resolution was
            // clean. A transient repository failure surfaces a warning and
            // degrades us to the SPDX fallback; caching that degraded material
            // would pin it forever, so we skip the final cache and let a later
            // run retry the repository. Successful SPDX records and other
            // per-namespace values are still cached inside `resolve_fresh`.
            Resolved(files), [] -> notice_cache.put_files(cache, key, files)
            Resolved(_), [_, ..] -> None
            Missing, _ -> None
          }
          #(Ok(resolution), warning)
        }
      }
    }
    Error(_) -> resolve_fresh(cache, package, clients)
  }
}

fn cached_final_files(
  cache: notice_cache.Cache,
  key: String,
  package: notice.NoticePackage,
) -> #(Result(List(notice.NoticeFile), Nil), Option(String)) {
  use files <- cache_dir.try_with_warning(notice_cache.get_files(cache, key))
  case notice.has_licence_file(files) {
    True -> #(Ok(files), None)
    False -> {
      use requirements <- cache_dir.try_with_warning(#(
        spdx.required_identifiers(package.declared_licences),
        None,
      ))
      use synthetic <- cache_dir.try_with_warning(
        list.fold(requirements, #(Ok([]), None), fn(acc, requirement) {
          use collected <- cache_dir.try_with_warning(acc)
          use file <- cache_dir.try_with_warning(cached_spdx_file(
            cache,
            requirement,
          ))
          #(Ok([file, ..collected]), None)
        }),
      )
      case synthetic != [] && list.all(synthetic, list.contains(files, _)) {
        True -> #(Ok(files), None)
        False -> #(Error(Nil), None)
      }
    }
  }
}

fn cached_spdx_file(
  cache: notice_cache.Cache,
  requirement: spdx.Requirement,
) -> #(Result(notice.NoticeFile, Nil), Option(String)) {
  let kind = spdx.index_kind(requirement)
  let index_key =
    "spdx-index:" <> spdx.license_list_commit <> ":" <> spdx.index_slug(kind)
  use encoded <- cache_dir.try_with_warning(notice_cache.get_text(
    cache,
    index_key,
  ))
  use ids <- cache_dir.try_with_warning(#(
    spdx.decode_cached_index(encoded),
    None,
  ))
  use canonical <- cache_dir.try_with_warning(#(
    spdx.canonical_requirement(requirement, ids),
    None,
  ))
  use text <- cache_dir.try_with_warning(notice_cache.get_text(
    cache,
    spdx_key(canonical),
  ))
  #(Ok(notice.spdx_file(canonical, text)), None)
}

// Version material keys so old empty selections cannot hide nested licences.
fn final_key(package: notice.NoticePackage) -> Result(String, Nil) {
  use source <- result.try(source_identity(package))
  use metadata <- result.try(metadata_fingerprint(package))
  Ok(
    "pkg:v2:"
    <> source
    <> ":metadata:"
    <> metadata
    <> ":spdx:"
    <> spdx.license_list_commit,
  )
}

fn source_key(package: notice.NoticePackage) -> Result(String, Nil) {
  source_identity(package)
  |> result.map(fn(identity) { "source:v2:" <> identity })
}

fn source_identity(package: notice.NoticePackage) -> Result(String, Nil) {
  let base = package.name <> "@" <> package.version <> "@"
  case package.source {
    notice.HexPackage(checksum) ->
      Ok(base <> "hex:" <> string.uppercase(checksum))
    notice.GitPackage(repo, _url, commit) ->
      Ok(base <> "git:" <> repository.describe(repo) <> "@" <> commit)
    notice.PathPackage(_) -> Error(Nil)
  }
}

fn metadata_fingerprint(package: notice.NoticePackage) -> Result(String, Nil) {
  let encoded =
    json.to_string(
      json.object([
        #(
          "declared_licences",
          json.array(package.declared_licences, json.string),
        ),
        #("repo_links", json.array(package.repo_links, json.string)),
      ]),
    )
  source_archive.sha256_hex(bit_array.from_string(encoded))
  |> result.replace_error(Nil)
}

fn resolve_fresh(
  cache: notice_cache.Cache,
  package: notice.NoticePackage,
  clients: notice.Clients,
) -> #(Result(Resolution, notice.Error), Option(String)) {
  use source_notices <- cache_dir.try_with_warning(read_source_notices(
    cache,
    package,
    clients,
  ))

  case notice.has_licence_file(source_notices) {
    True -> #(
      Ok(Resolution(outcome: Resolved(source_notices), warnings: [])),
      None,
    )
    False -> fallback(cache, package, source_notices, clients)
  }
}

fn read_source_notices(
  cache: notice_cache.Cache,
  package: notice.NoticePackage,
  clients: notice.Clients,
) -> #(Result(List(notice.NoticeFile), notice.Error), Option(String)) {
  case source_key(package) {
    Ok(key) -> {
      use cached <- cache_dir.with_warning(notice_cache.get_files(cache, key))
      case cached {
        Ok(files) -> #(Ok(files), None)
        Error(_) -> {
          use files <- cache_dir.try_with_warning(#(
            read_source_notices_live(package, clients),
            None,
          ))
          #(Ok(files), notice_cache.put_files(cache, key, files))
        }
      }
    }
    Error(_) -> #(read_source_notices_live(package, clients), None)
  }
}

fn read_source_notices_live(
  package: notice.NoticePackage,
  clients: notice.Clients,
) -> Result(List(notice.NoticeFile), notice.Error) {
  notice.read_source_notices(package, clients)
}

fn fallback(
  cache: notice_cache.Cache,
  package: notice.NoticePackage,
  preserved: List(notice.NoticeFile),
  clients: notice.Clients,
) -> #(Result(Resolution, notice.Error), Option(String)) {
  // Repository fallback applies only to Hex packages: git sources are already
  // the repository at an immutable commit, and path sources are local.
  use #(repo_files, warnings) <- cache_dir.with_warning(case package.source {
    notice.HexPackage(_) -> repository_fallback(cache, package, clients)
    notice.GitPackage(_, _, _) | notice.PathPackage(_) -> #(#(None, []), None)
  })

  case repo_files {
    Some(licence_files) -> #(
      Ok(Resolution(
        outcome: Resolved(list.append(preserved, licence_files)),
        warnings: warnings,
      )),
      None,
    )
    None -> {
      use spdx_files <- cache_dir.try_with_warning(spdx_fallback(
        cache,
        package,
        clients,
      ))
      case spdx_files {
        [] -> #(Ok(Resolution(outcome: Missing, warnings: warnings)), None)
        files -> #(
          Ok(Resolution(
            outcome: Resolved(list.append(preserved, files)),
            warnings: warnings,
          )),
          None,
        )
      }
    }
  }
}

// --- Repository fallback -----------------------------------------------------

fn repository_fallback(
  cache: notice_cache.Cache,
  package: notice.NoticePackage,
  clients: notice.Clients,
) -> #(#(Option(List(notice.NoticeFile)), List(String)), Option(String)) {
  let repos = list.filter_map(package.repo_links, repository.parse)
  try_repos(cache, package, repos, clients, [])
}

fn try_repos(
  cache: notice_cache.Cache,
  package: notice.NoticePackage,
  repos: List(repository.Repository),
  clients: notice.Clients,
  warnings: List(String),
) -> #(#(Option(List(notice.NoticeFile)), List(String)), Option(String)) {
  case repos {
    [] -> #(#(None, warnings), None)
    [repo, ..rest] -> {
      use #(files, new_warnings) <- cache_dir.with_warning(try_repo(
        cache,
        package,
        repo,
        clients,
      ))
      let warnings = list.append(warnings, new_warnings)
      case files {
        Some(licence_files) -> #(#(Some(licence_files), warnings), None)
        None -> try_repos(cache, package, rest, clients, warnings)
      }
    }
  }
}

/// A non-fatal failure encountered while following one repository fallback
/// candidate. Contains the data needed to describe the failure (rather than a
/// pre-formatted `String`) so callers other than `try_repo` could match on the
/// cause without re-parsing a message.
type RepoFallbackError {
  TagResolutionFailed(
    package: notice.NoticePackage,
    repo: repository.Repository,
    tag: String,
    reason: notice.FetchError,
  )
  RepoArchiveFetchFailed(
    package: notice.NoticePackage,
    repo: repository.Repository,
    reason: notice.FetchError,
  )
  RepoArchiveExtractFailed(
    package: notice.NoticePackage,
    repo: repository.Repository,
    reason: notice.Error,
  )
}

fn describe_repo_fallback_error(error: RepoFallbackError) -> String {
  case error {
    TagResolutionFailed(package, repo, tag, reason) ->
      "Repository fallback for "
      <> package.name
      <> ": could not resolve tag "
      <> tag
      <> " at "
      <> repository.describe(repo)
      <> " ("
      <> notice.describe_fetch_error(reason)
      <> "); trying declared SPDX licences"
    RepoArchiveFetchFailed(package, repo, reason) ->
      repo_warning(package, repo, notice.describe_fetch_error(reason))
    RepoArchiveExtractFailed(package, repo, reason) ->
      repo_warning(package, repo, notice.describe_error(reason))
  }
}

fn try_repo(
  cache: notice_cache.Cache,
  package: notice.NoticePackage,
  repo: repository.Repository,
  clients: notice.Clients,
) -> #(#(Option(List(notice.NoticeFile)), List(String)), Option(String)) {
  use commit <- cache_dir.with_warning(resolve_commit(
    cache,
    package,
    repo,
    clients,
  ))
  case commit {
    Error(error) -> #(#(None, [describe_repo_fallback_error(error)]), None)
    Ok(None) -> #(#(None, []), None)
    Ok(Some(commit)) -> {
      use files <- cache_dir.with_warning(repo_licence_files(
        cache,
        package,
        repo,
        commit,
        clients,
      ))
      case files {
        Error(error) -> #(#(None, [describe_repo_fallback_error(error)]), None)
        Ok([]) -> #(#(None, []), None)
        Ok(licence_files) -> #(#(Some(licence_files), []), None)
      }
    }
  }
}

/// Resolve the first tag candidate that maps to a commit. `Ok(Some(sha))` on
/// success, `Ok(None)` when no candidate tag exists, `Error(error)` on a
/// transient failure (the warning is surfaced and the caller continues).
fn resolve_commit(
  cache: notice_cache.Cache,
  package: notice.NoticePackage,
  repo: repository.Repository,
  clients: notice.Clients,
) -> #(Result(Option(String), RepoFallbackError), Option(String)) {
  resolve_commit_loop(
    cache,
    package,
    repo,
    repository.tag_candidates(package.version),
    clients,
  )
}

fn resolve_commit_loop(
  cache: notice_cache.Cache,
  package: notice.NoticePackage,
  repo: repository.Repository,
  tags: List(String),
  clients: notice.Clients,
) -> #(Result(Option(String), RepoFallbackError), Option(String)) {
  case tags {
    [] -> #(Ok(None), None)
    [tag, ..rest] -> {
      let key = "tag:" <> repository.describe(repo) <> "@" <> tag
      use cached <- cache_dir.with_warning(notice_cache.get_text(cache, key))
      case cached {
        Ok(commit) -> #(Ok(Some(commit)), None)
        Error(_) ->
          resolve_commit_tag(cache, package, repo, tag, rest, clients, key)
      }
    }
  }
}

fn resolve_commit_tag(
  cache: notice_cache.Cache,
  package: notice.NoticePackage,
  repo: repository.Repository,
  tag: String,
  rest: List(String),
  clients: notice.Clients,
  key: String,
) -> #(Result(Option(String), RepoFallbackError), Option(String)) {
  case clients.resolve_commit(repo, tag) {
    Ok(Some(commit)) -> #(
      Ok(Some(commit)),
      notice_cache.put_text(cache, key, commit),
    )
    Ok(None) -> resolve_commit_loop(cache, package, repo, rest, clients)
    Error(fetch_error) -> #(
      Error(TagResolutionFailed(package, repo, tag, fetch_error)),
      None,
    )
  }
}

/// Fetch (or read from cache) the licence-text files from a repository archive
/// at an immutable commit. `Error(error)` on a transient network or archive
/// failure.
fn repo_licence_files(
  cache: notice_cache.Cache,
  package: notice.NoticePackage,
  repo: repository.Repository,
  commit: String,
  clients: notice.Clients,
) -> #(Result(List(notice.NoticeFile), RepoFallbackError), Option(String)) {
  let key = "repo:v2:" <> repository.describe(repo) <> "@" <> commit
  use cached <- cache_dir.with_warning(notice_cache.get_files(cache, key))
  case cached {
    Ok(files) -> #(Ok(notice.licence_files_only(files)), None)
    Error(_) ->
      case clients.fetch_repo_archive(repo, commit) {
        Error(fetch_error) -> #(
          Error(RepoArchiveFetchFailed(package, repo, fetch_error)),
          None,
        )
        Ok(bytes) ->
          case notice.repo_licence_files(package.name, bytes) {
            Ok(files) -> #(Ok(files), notice_cache.put_files(cache, key, files))
            Error(error) -> #(
              Error(RepoArchiveExtractFailed(package, repo, error)),
              None,
            )
          }
      }
  }
}

fn repo_warning(
  package: notice.NoticePackage,
  repo: repository.Repository,
  reason: String,
) -> String {
  "Repository fallback for "
  <> package.name
  <> " at "
  <> repository.describe(repo)
  <> " failed ("
  <> reason
  <> "); trying declared SPDX licences"
}

// --- SPDX fallback -----------------------------------------------------------

fn spdx_fallback(
  cache: notice_cache.Cache,
  package: notice.NoticePackage,
  clients: notice.Clients,
) -> #(Result(List(notice.NoticeFile), notice.Error), Option(String)) {
  case spdx.required_identifiers(package.declared_licences) {
    // A `LicenseRef-`/`DocumentRef-` custom licence has no canonical text and
    // cannot be synthesized: treat the package as missing.
    Error(_) -> #(Ok([]), None)
    Ok(requirements) -> {
      use canonical <- cache_dir.try_with_warning(
        canonicalize_requirements(cache, package, requirements, clients, []),
      )
      resolve_spdx_requirements(cache, package, canonical, clients, [])
    }
  }
}

fn canonicalize_requirements(
  cache: notice_cache.Cache,
  package: notice.NoticePackage,
  requirements: List(spdx.Requirement),
  clients: notice.Clients,
  canonical: List(spdx.Requirement),
) -> #(Result(List(spdx.Requirement), notice.Error), Option(String)) {
  case requirements {
    [] -> #(Ok(list.reverse(canonical)), None)
    [requirement, ..rest] -> {
      use resolved <- cache_dir.try_with_warning(canonical_requirement(
        cache,
        package,
        requirement,
        clients,
      ))
      case resolved {
        None -> #(Ok([]), None)
        Some(value) ->
          canonicalize_requirements(cache, package, rest, clients, [
            value,
            ..canonical
          ])
      }
    }
  }
}

fn canonical_requirement(
  cache: notice_cache.Cache,
  package: notice.NoticePackage,
  requirement: spdx.Requirement,
  clients: notice.Clients,
) -> #(Result(Option(spdx.Requirement), notice.Error), Option(String)) {
  let kind = spdx.index_kind(requirement)
  use ids <- cache_dir.try_with_warning(spdx_index(
    cache,
    package,
    kind,
    clients,
  ))
  #(
    Ok(case spdx.canonical_requirement(requirement, ids) {
      Ok(canonical) -> Some(canonical)
      Error(_) -> None
    }),
    None,
  )
}

fn spdx_index(
  cache: notice_cache.Cache,
  package: notice.NoticePackage,
  kind: spdx.IndexKind,
  clients: notice.Clients,
) -> #(Result(List(String), notice.Error), Option(String)) {
  let key =
    "spdx-index:" <> spdx.license_list_commit <> ":" <> spdx.index_slug(kind)
  use cached <- cache_dir.with_warning(notice_cache.get_text(cache, key))
  case cached {
    Ok(encoded) ->
      case spdx.decode_cached_index(encoded) {
        Ok(ids) -> #(Ok(ids), None)
        Error(_) -> fetch_spdx_index(cache, package, kind, key, clients)
      }
    Error(_) -> fetch_spdx_index(cache, package, kind, key, clients)
  }
}

fn fetch_spdx_index(
  cache: notice_cache.Cache,
  package: notice.NoticePackage,
  kind: spdx.IndexKind,
  key: String,
  clients: notice.Clients,
) -> #(Result(List(String), notice.Error), Option(String)) {
  case clients.fetch_spdx_index(kind) {
    Ok(ids) -> #(
      Ok(ids),
      notice_cache.put_text(cache, key, spdx.encode_index(ids)),
    )
    Error(fetch_error) -> #(
      Error(notice.SpdxFetchFailed(
        package: package.name,
        id: spdx.index_slug(kind) <> " index",
        reason: notice.describe_fetch_error(fetch_error),
      )),
      None,
    )
  }
}

fn resolve_spdx_requirements(
  cache: notice_cache.Cache,
  package: notice.NoticePackage,
  requirements: List(spdx.Requirement),
  clients: notice.Clients,
  files: List(notice.NoticeFile),
) -> #(Result(List(notice.NoticeFile), notice.Error), Option(String)) {
  case requirements {
    [] -> #(Ok(list.reverse(files)), None)
    [requirement, ..rest] -> {
      use file <- cache_dir.try_with_warning(resolve_spdx(
        cache,
        package.name,
        requirement,
        clients,
      ))
      case file {
        None -> #(Ok([]), None)
        Some(notice_file) ->
          resolve_spdx_requirements(cache, package, rest, clients, [
            notice_file,
            ..files
          ])
      }
    }
  }
}

/// Read canonical text for an already-canonical SPDX requirement, using the
/// shared pinned-record cache. Unknown identifiers return `Ok(None)`.
pub fn resolve_spdx(
  cache: notice_cache.Cache,
  package: String,
  requirement: spdx.Requirement,
  clients: notice.Clients,
) -> #(Result(Option(notice.NoticeFile), notice.Error), Option(String)) {
  let key = spdx_key(requirement)
  use cached <- cache_dir.with_warning(notice_cache.get_text(cache, key))
  case cached {
    Ok(text) -> #(Ok(Some(notice.spdx_file(requirement, text))), None)
    Error(_) ->
      case clients.fetch_spdx(requirement) {
        Ok(Some(text)) ->
          case notice.has_text(text) {
            False -> #(Ok(None), None)
            True -> #(
              Ok(Some(notice.spdx_file(requirement, text))),
              notice_cache.put_text(cache, key, text),
            )
          }
        Ok(None) -> #(Ok(None), None)
        Error(fetch_error) -> #(
          Error(notice.SpdxFetchFailed(
            package: package,
            id: requirement_id(requirement),
            reason: notice.describe_fetch_error(fetch_error),
          )),
          None,
        )
      }
  }
}

fn spdx_key(requirement: spdx.Requirement) -> String {
  case requirement {
    spdx.LicenseRequirement(id) ->
      "spdx:" <> spdx.license_list_commit <> ":license:" <> id
    spdx.ExceptionRequirement(id) ->
      "spdx:" <> spdx.license_list_commit <> ":exception:" <> id
  }
}

fn requirement_id(requirement: spdx.Requirement) -> String {
  case requirement {
    spdx.LicenseRequirement(id) -> id
    spdx.ExceptionRequirement(id) -> id
  }
}
