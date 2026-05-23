//// Read-through cache for Hex package licence metadata.
////
//// Wraps a fetcher with a DETS-backed cache keyed by `name@version`. The
//// cache is purely an optimisation: any failure to open, read, or write
//// falls back silently to the network fetcher and records a deferred
//// warning so the caller can surface it after the audit finishes.

import envoy
import gleam/dynamic/decode
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import simplifile
import slate
import slate/set as dets_set

import licence_audit/hex
import licence_audit/manifest
import licence_audit/progress

/// Configures how the cache module behaves for a given run.
pub type Mode {
  /// Cache enabled; `path` overrides the default location when `Some`.
  Enabled(path: Option(String))
  /// Bypass the cache entirely (no read, no write, no file opened).
  Disabled
}

/// Opaque cache handle. May or may not hold an open DETS table.
pub opaque type Cache {
  Cache(
    table: Option(dets_set.Set(String, List(String))),
    warning: Option(String),
  )
}

const cache_subdir = "licence_audit"

const cache_filename = "hex.dets"

/// Open a cache according to `mode`.
///
/// Never returns an error. If the cache file can't be opened or the parent
/// directory can't be created, the returned `Cache` is in a passthrough
/// state and carries a deferred warning message accessible via `close`.
pub fn open(mode: Mode) -> Cache {
  case mode {
    Disabled -> Cache(table: None, warning: None)
    Enabled(path) ->
      case resolve_path(path) {
        Error(message) -> Cache(table: None, warning: Some(message))
        Ok(resolved) ->
          case ensure_parent_dir(resolved) {
            Error(message) -> Cache(table: None, warning: Some(message))
            Ok(_) -> open_table(resolved)
          }
      }
  }
}

/// Close the cache (if open) and return any deferred warning.
///
/// The warning, if `Some`, describes the most recent non-fatal cache
/// failure (open, write, or close). Callers should surface it as the
/// last log entry of the run.
pub fn close(cache: Cache) -> Option(String) {
  case cache.table {
    None -> cache.warning
    Some(table) ->
      case dets_set.close(table) {
        Ok(_) -> cache.warning
        Error(error) ->
          Some("Failed to close licence cache: " <> slate.error_message(error))
      }
  }
}

/// Build a fetcher that consults the cache before falling through to
/// `fetcher`. Emits verbose progress detail events for hits, misses, and
/// passthrough. Successful upstream fetches are best-effort written back
/// to the cache; write failures do not cause the audit to fail.
pub fn wrap(
  cache: Cache,
  fetcher: fn(String) -> Result(hex.PackageMetadata, hex.Error),
) -> fn(manifest.Package, progress.Reporter) ->
  #(Result(hex.PackageMetadata, hex.Error), progress.Reporter) {
  fn(package: manifest.Package, reporter: progress.Reporter) {
    let key = cache_key(package)
    case cache.table {
      None -> {
        let reporter =
          progress.detail(
            reporter,
            "Cache disabled; fetching " <> key <> " from Hex",
          )
        #(fetcher(package.name), reporter)
      }
      Some(table) ->
        case dets_set.lookup(from: table, key: key) {
          Ok(licences) -> {
            let reporter = progress.detail(reporter, "Cache hit for " <> key)
            #(Ok(hex.PackageMetadata(licences: licences)), reporter)
          }
          Error(_) -> {
            let reporter =
              progress.detail(
                reporter,
                "Cache miss for " <> key <> "; fetching from Hex",
              )
            case fetcher(package.name) {
              Error(error) -> #(Error(error), reporter)
              Ok(metadata) -> {
                let reporter = case
                  dets_set.insert(
                    into: table,
                    key: key,
                    value: metadata.licences,
                  )
                {
                  Ok(_) ->
                    progress.detail(
                      reporter,
                      "Cached licence metadata for " <> key,
                    )
                  Error(error) ->
                    progress.detail(
                      reporter,
                      "Failed to write cache entry for "
                        <> key
                        <> ": "
                        <> slate.error_message(error),
                    )
                }
                #(Ok(metadata), reporter)
              }
            }
          }
        }
    }
  }
}

/// Resolve the cache file path, honouring an explicit override.
pub fn resolve_path(override: Option(String)) -> Result(String, String) {
  case override {
    Some(path) -> Ok(path)
    None -> default_path()
  }
}

/// Default cache path: `${XDG_CACHE_HOME:-$HOME/.cache}/licence_audit/hex.dets`.
pub fn default_path() -> Result(String, String) {
  case envoy.get("XDG_CACHE_HOME") {
    Ok(dir) if dir != "" -> Ok(join_path(dir))
    _ ->
      case envoy.get("HOME") {
        Ok(home) if home != "" -> Ok(join_path(home <> "/.cache"))
        _ ->
          Error(
            "Unable to determine licence cache directory: neither XDG_CACHE_HOME nor HOME is set",
          )
      }
  }
}

fn join_path(base: String) -> String {
  base <> "/" <> cache_subdir <> "/" <> cache_filename
}

fn ensure_parent_dir(path: String) -> Result(Nil, String) {
  let parent = parent_directory(path)
  case parent {
    "" -> Ok(Nil)
    dir ->
      simplifile.create_directory_all(dir)
      |> result.map_error(fn(_) {
        "Unable to create licence cache directory: " <> dir
      })
  }
}

fn parent_directory(path: String) -> String {
  // Strip everything after the final '/'. Slate is Erlang-only so we
  // only need POSIX semantics here.
  case list.reverse(string.split(path, on: "/")) {
    [] -> ""
    [_] -> ""
    [_, ..rest] -> string.join(list.reverse(rest), with: "/")
  }
}

fn open_table(path: String) -> Cache {
  let key_decoder = decode.string
  let value_decoder = decode.list(of: decode.string)
  case
    dets_set.open(path, key_decoder: key_decoder, value_decoder: value_decoder)
  {
    Ok(table) -> Cache(table: Some(table), warning: None)
    Error(error) ->
      Cache(
        table: None,
        warning: Some(
          "Unable to open licence cache at "
          <> path
          <> ": "
          <> slate.error_message(error),
        ),
      )
  }
}

fn cache_key(package: manifest.Package) -> String {
  package.name <> "@" <> package.version
}
