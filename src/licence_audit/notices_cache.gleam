//// Read-through cache for extracted notice/licence files.
////
//// Wraps the `notices` source-read step with a DETS-backed cache keyed by a
//// content address (Hex `outer_checksum` or GitHub `commit`). Because the key
//// is content-addressed, cached entries are immutable and never expire: a hit
//// is always valid for the exact package version it was stored for.
////
//// The cache is purely an optimisation. Any failure to open, read, or write
//// falls back silently to the live source read and (for open failures) records
//// a deferred warning surfaced via `close`. Path (local) dependencies are not
//// cacheable and always read live.

import gleam/dynamic/decode
import gleam/int
import gleam/option.{type Option, None, Some}
import gleam/string
import slate
import slate/set as dets_set

import licence_audit/cache_dir
import licence_audit/notices

/// Configures how the cache behaves for a given run.
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

/// On-disk cache format version. Bump on any incompatible change to the cached
/// value shape (see `notices.encode_notice_files`) **or** to the set of files
/// considered notice/licence files (see `notices.licence_files`): a cached
/// entry reflects the matching logic in effect when it was written, so changing
/// which files are extracted requires a bump to avoid serving outdated results.
/// The version is encoded into the filename so a file written by an older
/// format is ignored rather than mis-decoded; `notices.decode_notice_files`
/// also treats any unparseable entry as a miss, so forward-compatible drift
/// self-heals without a bump.
const cache_format_version = 1

fn cache_filename() -> String {
  "notices-v" <> int.to_string(cache_format_version) <> ".dets"
}

/// Open a cache according to `mode`.
///
/// Never returns an error. If the cache file can't be opened or the parent
/// directory can't be created, the returned `Cache` is in a passthrough state
/// and carries a deferred warning accessible via `close`.
pub fn open(mode: Mode) -> Cache {
  case mode {
    Disabled -> Cache(table: None, warning: None)
    Enabled(path) ->
      case cache_dir.resolve_path(path, cache_filename()) {
        Error(error) ->
          Cache(
            table: None,
            warning: Some(cache_dir.describe_path_error(error)),
          )
        Ok(resolved) ->
          case cache_dir.ensure_parent_dir(resolved) {
            Error(error) ->
              Cache(
                table: None,
                warning: Some(cache_dir.describe_path_error(error)),
              )
            Ok(_) -> open_table(resolved)
          }
      }
  }
}

/// Close the cache (if open) and return any deferred warning.
pub fn close(cache: Cache) -> Option(String) {
  case cache.table {
    None -> cache.warning
    Some(table) ->
      case dets_set.close(table) {
        Ok(_) -> cache.warning
        Error(error) ->
          Some("Failed to close notices cache: " <> slate.error_message(error))
      }
  }
}

/// Read a package's notice files, consulting the cache first.
///
/// On a hit, returns the stored notice files without any network or extraction
/// work. On a miss, calls `read` and best-effort writes the result back. When
/// the cache is disabled or the package is not cacheable (a path dependency),
/// `read` is called directly.
pub fn read_cached(
  cache: Cache,
  package: notices.NoticePackage,
  read: fn(notices.NoticePackage) ->
    Result(List(notices.NoticeFile), notices.Error),
) -> Result(List(notices.NoticeFile), notices.Error) {
  case cache.table, cache_key(package) {
    Some(table), Ok(key) ->
      case lookup(table, key) {
        Ok(files) -> Ok(files)
        Error(_) ->
          case read(package) {
            Ok(files) -> {
              store(table, key, files)
              Ok(files)
            }
            Error(error) -> Error(error)
          }
      }
    _, _ -> read(package)
  }
}

/// Content-addressed cache key for a package, or `Error(Nil)` when the source
/// is not cacheable (path dependencies, whose contents are local and mutable).
fn cache_key(package: notices.NoticePackage) -> Result(String, Nil) {
  let base = package.name <> "@" <> package.version <> "@"
  case package.source {
    notices.HexPackage(outer_checksum) ->
      Ok(base <> "hex:" <> string.uppercase(outer_checksum))
    notices.GitHubPackage(_repo, commit) -> Ok(base <> "git:" <> commit)
    notices.PathPackage(_) -> Error(Nil)
  }
}

fn lookup(
  table: dets_set.Set(String, String),
  key: String,
) -> Result(List(notices.NoticeFile), Nil) {
  case dets_set.lookup(from: table, key: key) {
    Ok(encoded) -> notices.decode_notice_files(encoded)
    Error(_) -> Error(Nil)
  }
}

fn store(
  table: dets_set.Set(String, String),
  key: String,
  files: List(notices.NoticeFile),
) -> Nil {
  let _ =
    dets_set.insert(
      into: table,
      key: key,
      value: notices.encode_notice_files(files),
    )
  Nil
}

fn open_table(path: String) -> Cache {
  case
    dets_set.open(
      path,
      key_decoder: decode.string,
      value_decoder: decode.string,
    )
  {
    Ok(table) -> Cache(table: Some(table), warning: None)
    Error(error) ->
      Cache(
        table: None,
        warning: Some(
          "Unable to open notices cache at "
          <> path
          <> ": "
          <> slate.error_message(error),
        ),
      )
  }
}
