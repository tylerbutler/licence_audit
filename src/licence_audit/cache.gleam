//// Read-through cache for Hex package licence metadata.
////
//// Wraps a fetcher with a DETS-backed cache keyed by `name@version`. The
//// cache is purely an optimisation: any failure to open, read, or write
//// falls back silently to the network fetcher and records a deferred
//// warning so the caller can surface it after the audit finishes.

import envoy
import gleam/dynamic/decode
import gleam/int
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
  Cache(table: Option(dets_set.Set(String, String)), warning: Option(String))
}

const cache_subdir = "licence_audit"

/// On-disk cache format version. Bump on any incompatible change to the cached
/// value shape (see `hex.encode_cache_entry`). The version is encoded into the
/// cache filename so a file written by an older format is simply ignored rather
/// than read back with the wrong decoder. `hex.decode_cache_entry` also treats
/// any unparseable entry as a miss, so minor/forward-compatible drift self-heals
/// without a bump — reserve bumps for changes that would mis-decode old data
/// (v1 was a bare `List(String)` of licences; v2 is a JSON metadata object).
const cache_format_version = 2

fn cache_filename() -> String {
  "hex-v" <> int.to_string(cache_format_version) <> ".dets"
}

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
        Error(error) ->
          Cache(table: None, warning: Some(describe_path_error(error)))
        Ok(resolved) ->
          case ensure_parent_dir(resolved) {
            Error(error) ->
              Cache(table: None, warning: Some(describe_path_error(error)))
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
        case lookup_entry(table, key) {
          Ok(metadata) -> {
            let reporter = progress.detail(reporter, "Cache hit for " <> key)
            #(Ok(metadata), reporter)
          }
          Error(_) -> {
            let reporter =
              progress.detail(
                reporter,
                "Cache miss for " <> key <> "; fetching from Hex",
              )
            fetch_and_store(table, key, fetcher(package.name), reporter)
          }
        }
    }
  }
}

/// Handle a cache miss: record the fetch result and, on success, best-effort
/// write it back to `table`. Write failures are surfaced as a verbose detail
/// event but never fail the fetch.
fn lookup_entry(
  table: dets_set.Set(String, String),
  key: String,
) -> Result(hex.PackageMetadata, Nil) {
  // A stored value that no longer parses (e.g. partial format drift) is
  // reported as a miss so the caller refetches rather than failing.
  case dets_set.lookup(from: table, key: key) {
    Ok(encoded) -> hex.decode_cache_entry(encoded)
    Error(_) -> Error(Nil)
  }
}

fn fetch_and_store(
  table: dets_set.Set(String, String),
  key: String,
  fetched: Result(hex.PackageMetadata, hex.Error),
  reporter: progress.Reporter,
) -> #(Result(hex.PackageMetadata, hex.Error), progress.Reporter) {
  case fetched {
    Error(error) -> #(Error(error), reporter)
    Ok(metadata) -> {
      let reporter = case
        dets_set.insert(
          into: table,
          key: key,
          value: hex.encode_cache_entry(metadata),
        )
      {
        Ok(_) ->
          progress.detail(reporter, "Cached licence metadata for " <> key)
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

/// Why a cache file path could not be resolved or prepared.
type PathError {
  CacheDirUnknown
  CacheDirCreateFailed(dir: String, reason: String)
}

fn describe_path_error(error: PathError) -> String {
  case error {
    CacheDirUnknown ->
      "Unable to determine licence cache directory: neither XDG_CACHE_HOME nor HOME is set"
    CacheDirCreateFailed(dir, reason) ->
      "Unable to create licence cache directory " <> dir <> ": " <> reason
  }
}

/// Resolve the cache file path, honouring an explicit override.
fn resolve_path(override: Option(String)) -> Result(String, PathError) {
  case override {
    Some(path) -> Ok(path)
    None -> default_path()
  }
}

/// Default cache path: `${XDG_CACHE_HOME:-$HOME/.cache}/licence_audit/hex.dets`.
fn default_path() -> Result(String, PathError) {
  case envoy.get("XDG_CACHE_HOME") {
    Ok(dir) if dir != "" -> Ok(join_path(dir))
    _ ->
      case envoy.get("HOME") {
        Ok(home) if home != "" -> Ok(join_path(home <> "/.cache"))
        _ -> Error(CacheDirUnknown)
      }
  }
}

fn join_path(base: String) -> String {
  base <> "/" <> cache_subdir <> "/" <> cache_filename()
}

fn ensure_parent_dir(path: String) -> Result(Nil, PathError) {
  let parent = parent_directory(path)
  case parent {
    "" -> Ok(Nil)
    dir ->
      simplifile.create_directory_all(dir)
      |> result.map_error(fn(err) {
        CacheDirCreateFailed(dir: dir, reason: simplifile.describe_error(err))
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
  let value_decoder = decode.string
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
