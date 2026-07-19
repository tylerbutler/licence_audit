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

import licence_audit/notices
import licence_audit/notices_cache
import licence_audit/repository
import licence_audit/source_archive
import licence_audit/spdx

/// The result of resolving one package.
pub type Outcome {
  /// Licence materials were found (source, repository, or SPDX fallback).
  Resolved(files: List(notices.NoticeFile))
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
  cache: notices_cache.Cache,
  package: notices.NoticePackage,
  clients: notices.Clients,
) -> Result(Resolution, notices.Error) {
  case final_key(package) {
    Ok(key) ->
      case notices_cache.get_files(cache, key) {
        Ok(files) -> Ok(Resolution(outcome: Resolved(files), warnings: []))
        Error(_) -> {
          use resolution <- result.try(resolve_fresh(cache, package, clients))
          case resolution.outcome, resolution.warnings {
            // Only freeze the final per-package result when resolution was
            // clean. A transient repository failure surfaces a warning and
            // degrades us to the SPDX fallback; caching that degraded material
            // would pin it forever, so we skip the final cache and let a later
            // run retry the repository. Successful SPDX records and other
            // per-namespace values are still cached inside `resolve_fresh`.
            Resolved(files), [] -> notices_cache.put_files(cache, key, files)
            Resolved(_), [_, ..] -> Nil
            Missing, _ -> Nil
          }
          Ok(resolution)
        }
      }
    Error(_) -> resolve_fresh(cache, package, clients)
  }
}

fn final_key(package: notices.NoticePackage) -> Result(String, Nil) {
  use source <- result.try(source_identity(package))
  use metadata <- result.try(metadata_fingerprint(package))
  Ok(
    "pkg:"
    <> source
    <> ":metadata:"
    <> metadata
    <> ":spdx:"
    <> spdx.license_list_commit,
  )
}

fn source_key(package: notices.NoticePackage) -> Result(String, Nil) {
  source_identity(package)
  |> result.map(fn(identity) { "source:" <> identity })
}

fn source_identity(package: notices.NoticePackage) -> Result(String, Nil) {
  let base = package.name <> "@" <> package.version <> "@"
  case package.source {
    notices.HexPackage(checksum) ->
      Ok(base <> "hex:" <> string.uppercase(checksum))
    notices.GitPackage(repo, _url, commit) ->
      Ok(base <> "git:" <> repository.describe(repo) <> "@" <> commit)
    notices.PathPackage(_) -> Error(Nil)
  }
}

fn metadata_fingerprint(package: notices.NoticePackage) -> Result(String, Nil) {
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
  cache: notices_cache.Cache,
  package: notices.NoticePackage,
  clients: notices.Clients,
) -> Result(Resolution, notices.Error) {
  use source_notices <- result.try(read_source_notices(cache, package, clients))

  case notices.has_licence_file(source_notices) {
    True -> Ok(Resolution(outcome: Resolved(source_notices), warnings: []))
    False -> fallback(cache, package, source_notices, clients)
  }
}

fn read_source_notices(
  cache: notices_cache.Cache,
  package: notices.NoticePackage,
  clients: notices.Clients,
) -> Result(List(notices.NoticeFile), notices.Error) {
  case source_key(package) {
    Ok(key) ->
      case notices_cache.get_files(cache, key) {
        Ok(files) -> Ok(files)
        Error(_) -> {
          use files <- result.try(read_source_notices_live(package, clients))
          notices_cache.put_files(cache, key, files)
          Ok(files)
        }
      }
    Error(_) -> read_source_notices_live(package, clients)
  }
}

fn read_source_notices_live(
  package: notices.NoticePackage,
  clients: notices.Clients,
) -> Result(List(notices.NoticeFile), notices.Error) {
  use source_files <- result.try(notices.read_remote_source(
    package,
    clients.fetch_hex_tarball,
    clients.fetch_git_archive,
  ))
  notices.notice_files_of(package.name, source_files)
}

fn fallback(
  cache: notices_cache.Cache,
  package: notices.NoticePackage,
  preserved: List(notices.NoticeFile),
  clients: notices.Clients,
) -> Result(Resolution, notices.Error) {
  // Repository fallback applies only to Hex packages: git sources are already
  // the repository at an immutable commit, and path sources are local.
  let #(repo_files, warnings) = case package.source {
    notices.HexPackage(_) -> repository_fallback(cache, package, clients)
    _ -> #(None, [])
  }

  case repo_files {
    Some(licence_files) ->
      Ok(Resolution(
        outcome: Resolved(list.append(preserved, licence_files)),
        warnings: warnings,
      ))
    None -> {
      use spdx_files <- result.try(spdx_fallback(cache, package, clients))
      case spdx_files {
        [] -> Ok(Resolution(outcome: Missing, warnings: warnings))
        files ->
          Ok(Resolution(
            outcome: Resolved(list.append(preserved, files)),
            warnings: warnings,
          ))
      }
    }
  }
}

// --- Repository fallback -----------------------------------------------------

fn repository_fallback(
  cache: notices_cache.Cache,
  package: notices.NoticePackage,
  clients: notices.Clients,
) -> #(Option(List(notices.NoticeFile)), List(String)) {
  let repos = list.filter_map(package.repo_links, repository.parse)
  try_repos(cache, package, repos, clients, [])
}

fn try_repos(
  cache: notices_cache.Cache,
  package: notices.NoticePackage,
  repos: List(repository.Repository),
  clients: notices.Clients,
  warnings: List(String),
) -> #(Option(List(notices.NoticeFile)), List(String)) {
  case repos {
    [] -> #(None, warnings)
    [repo, ..rest] -> {
      let #(files, new_warnings) = try_repo(cache, package, repo, clients)
      let warnings = list.append(warnings, new_warnings)
      case files {
        Some(licence_files) -> #(Some(licence_files), warnings)
        None -> try_repos(cache, package, rest, clients, warnings)
      }
    }
  }
}

fn try_repo(
  cache: notices_cache.Cache,
  package: notices.NoticePackage,
  repo: repository.Repository,
  clients: notices.Clients,
) -> #(Option(List(notices.NoticeFile)), List(String)) {
  case resolve_commit(cache, package, repo, clients) {
    Error(warning) -> #(None, [warning])
    Ok(None) -> #(None, [])
    Ok(Some(commit)) ->
      case repo_licence_files(cache, package, repo, commit, clients) {
        Error(warning) -> #(None, [warning])
        Ok([]) -> #(None, [])
        Ok(licence_files) -> #(Some(licence_files), [])
      }
  }
}

/// Resolve the first tag candidate that maps to a commit. `Ok(Some(sha))` on
/// success, `Ok(None)` when no candidate tag exists, `Error(warning)` on a
/// transient failure (the warning is surfaced and the caller continues).
fn resolve_commit(
  cache: notices_cache.Cache,
  package: notices.NoticePackage,
  repo: repository.Repository,
  clients: notices.Clients,
) -> Result(Option(String), String) {
  resolve_commit_loop(
    cache,
    package,
    repo,
    repository.tag_candidates(package.version),
    clients,
  )
}

fn resolve_commit_loop(
  cache: notices_cache.Cache,
  package: notices.NoticePackage,
  repo: repository.Repository,
  tags: List(String),
  clients: notices.Clients,
) -> Result(Option(String), String) {
  case tags {
    [] -> Ok(None)
    [tag, ..rest] -> {
      let key = "tag:" <> repository.describe(repo) <> "@" <> tag
      case notices_cache.get_text(cache, key) {
        Ok(commit) -> Ok(Some(commit))
        Error(_) ->
          case clients.resolve_commit(repo, tag) {
            Ok(Some(commit)) -> {
              notices_cache.put_text(cache, key, commit)
              Ok(Some(commit))
            }
            Ok(None) -> resolve_commit_loop(cache, package, repo, rest, clients)
            Error(fetch_error) ->
              Error(
                "Repository fallback for "
                <> package.name
                <> ": could not resolve tag "
                <> tag
                <> " at "
                <> repository.describe(repo)
                <> " ("
                <> notices.describe_fetch_error(fetch_error)
                <> "); trying declared SPDX licences",
              )
          }
      }
    }
  }
}

/// Fetch (or read from cache) the licence-text files from a repository archive
/// at an immutable commit. `Error(warning)` on a transient network or archive
/// failure.
fn repo_licence_files(
  cache: notices_cache.Cache,
  package: notices.NoticePackage,
  repo: repository.Repository,
  commit: String,
  clients: notices.Clients,
) -> Result(List(notices.NoticeFile), String) {
  let key = "repo:" <> repository.describe(repo) <> "@" <> commit
  case notices_cache.get_files(cache, key) {
    Ok(files) -> Ok(files)
    Error(_) ->
      case clients.fetch_repo_archive(repo, commit) {
        Error(fetch_error) ->
          Error(repo_warning(
            package,
            repo,
            notices.describe_fetch_error(fetch_error),
          ))
        Ok(bytes) ->
          case notices.repo_licence_files(package.name, bytes) {
            Ok(files) -> {
              notices_cache.put_files(cache, key, files)
              Ok(files)
            }
            Error(error) ->
              Error(repo_warning(package, repo, notices.describe_error(error)))
          }
      }
  }
}

fn repo_warning(
  package: notices.NoticePackage,
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
  cache: notices_cache.Cache,
  package: notices.NoticePackage,
  clients: notices.Clients,
) -> Result(List(notices.NoticeFile), notices.Error) {
  case spdx.required_identifiers(package.declared_licences) {
    // A `LicenseRef-`/`DocumentRef-` custom licence has no canonical text and
    // cannot be synthesized: treat the package as missing.
    Error(_) -> Ok([])
    Ok(requirements) -> {
      use canonical <- result.try(
        canonicalize_requirements(cache, package, requirements, clients, []),
      )
      resolve_spdx_requirements(cache, package, canonical, clients, [])
    }
  }
}

fn canonicalize_requirements(
  cache: notices_cache.Cache,
  package: notices.NoticePackage,
  requirements: List(spdx.Requirement),
  clients: notices.Clients,
  canonical: List(spdx.Requirement),
) -> Result(List(spdx.Requirement), notices.Error) {
  case requirements {
    [] -> Ok(list.reverse(canonical))
    [requirement, ..rest] -> {
      use resolved <- result.try(canonical_requirement(
        cache,
        package,
        requirement,
        clients,
      ))
      case resolved {
        None -> Ok([])
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
  cache: notices_cache.Cache,
  package: notices.NoticePackage,
  requirement: spdx.Requirement,
  clients: notices.Clients,
) -> Result(Option(spdx.Requirement), notices.Error) {
  let kind = spdx.index_kind(requirement)
  use ids <- result.try(spdx_index(cache, package, kind, clients))
  Ok(case spdx.canonical_requirement(requirement, ids) {
    Ok(canonical) -> Some(canonical)
    Error(_) -> None
  })
}

fn spdx_index(
  cache: notices_cache.Cache,
  package: notices.NoticePackage,
  kind: spdx.IndexKind,
  clients: notices.Clients,
) -> Result(List(String), notices.Error) {
  let key =
    "spdx-index:" <> spdx.license_list_commit <> ":" <> spdx.index_slug(kind)
  case notices_cache.get_text(cache, key) {
    Ok(encoded) ->
      case spdx.decode_cached_index(encoded) {
        Ok(ids) -> Ok(ids)
        Error(_) -> fetch_spdx_index(cache, package, kind, key, clients)
      }
    Error(_) -> fetch_spdx_index(cache, package, kind, key, clients)
  }
}

fn fetch_spdx_index(
  cache: notices_cache.Cache,
  package: notices.NoticePackage,
  kind: spdx.IndexKind,
  key: String,
  clients: notices.Clients,
) -> Result(List(String), notices.Error) {
  case clients.fetch_spdx_index(kind) {
    Ok(ids) -> {
      notices_cache.put_text(cache, key, spdx.encode_index(ids))
      Ok(ids)
    }
    Error(fetch_error) ->
      Error(notices.SpdxFetchFailed(
        package: package.name,
        id: spdx.index_slug(kind) <> " index",
        reason: notices.describe_fetch_error(fetch_error),
      ))
  }
}

fn resolve_spdx_requirements(
  cache: notices_cache.Cache,
  package: notices.NoticePackage,
  requirements: List(spdx.Requirement),
  clients: notices.Clients,
  files: List(notices.NoticeFile),
) -> Result(List(notices.NoticeFile), notices.Error) {
  case requirements {
    [] -> Ok(list.reverse(files))
    [requirement, ..rest] -> {
      use file <- result.try(resolve_spdx(cache, package, requirement, clients))
      case file {
        None -> Ok([])
        Some(notice_file) ->
          resolve_spdx_requirements(cache, package, rest, clients, [
            notice_file,
            ..files
          ])
      }
    }
  }
}

fn resolve_spdx(
  cache: notices_cache.Cache,
  package: notices.NoticePackage,
  requirement: spdx.Requirement,
  clients: notices.Clients,
) -> Result(Option(notices.NoticeFile), notices.Error) {
  let key = spdx_key(requirement)
  case notices_cache.get_text(cache, key) {
    Ok(text) -> Ok(Some(notices.spdx_file(requirement, text)))
    Error(_) ->
      case clients.fetch_spdx(requirement) {
        Ok(Some(text)) -> {
          notices_cache.put_text(cache, key, text)
          Ok(Some(notices.spdx_file(requirement, text)))
        }
        Ok(None) -> Ok(None)
        Error(fetch_error) ->
          Error(notices.SpdxFetchFailed(
            package: package.name,
            id: requirement_id(requirement),
            reason: notices.describe_fetch_error(fetch_error),
          ))
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
