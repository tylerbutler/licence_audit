//// Namespaced cache for notice/licence materials.
////
//// Caches extracted files and licence text between runs. `notice_resolve`
//// supplies immutable keys and bypasses this storage for mutable path
//// dependencies.
////
//// Returned storage errors let the resolver read live and produce deferred
//// warnings returned with each operation. Busy writes and unavailable native
//// libraries also return warnings. Use `--no-cache` to bypass the driver.

import gleam/int
import gleam/option.{type Option, None, Some}

import licence_audit/cache_dir
import licence_audit/notice

/// Configures how the cache behaves for a given run.
pub type Mode {
  /// Cache enabled; `path` overrides the default location when `Some`.
  Enabled(path: Option(String))
  /// Bypass the cache entirely (no read, no write, no file opened).
  Disabled
}

/// Opaque cache handle. Holds a store when caching is enabled and available.
pub opaque type Cache {
  Cache(table: Option(cache_dir.Store), warning: Option(String))
}

/// On-disk cache format version. Bumped to 3 for the fallback feature, which
/// changes both the cached value shape and the namespaces stored in the table:
/// alongside the final per-package materials, v3 also caches extracted source
/// materials, repository tag→commit resolutions, repository-extracted licence
/// files, pinned SPDX indexes, and canonical SPDX records shared across
/// packages. The version is encoded into the
/// cache filename so data written by an older format is ignored rather than
/// mis-decoded; `notice.decode_notice_files` also treats any unparseable entry
/// as a miss, so forward-compatible drift self-heals without a bump.
const cache_format_version = 3

fn cache_filename() -> String {
  "notices-v" <> int.to_string(cache_format_version) <> ".sqlite3"
}

/// Open a cache according to `mode`.
///
/// Returns no error value. If the cache path cannot be prepared, the returned
/// `Cache` bypasses storage and includes a deferred warning accessible via
/// `close`. An unavailable native library also bypasses storage.
pub fn open(mode: Mode) -> Cache {
  case mode {
    Disabled -> Cache(table: None, warning: None)
    Enabled(path) ->
      case cache_dir.open_table(path, cache_filename(), "notices") {
        Ok(table) -> Cache(table: Some(table), warning: None)
        Error(error) ->
          Cache(table: None, warning: Some(cache_dir.describe_error(error)))
      }
  }
}

/// Return the warning from opening the cache.
pub fn close(cache: Cache) -> Option(String) {
  cache.warning
}

/// Read a cached list of notice files stored under a namespaced `key`. Returns
/// `Error(Nil)` on a miss, when the cache is disabled, or when the stored value
/// no longer decodes (a corrupt entry is a miss so the caller refetches).
pub fn get_files(
  cache: Cache,
  key: String,
) -> #(Result(List(notice.NoticeFile), Nil), Option(String)) {
  case cache.table {
    None -> #(Error(Nil), None)
    Some(table) -> {
      use encoded <- cache_dir.try_with_warning(lookup(table, key))
      #(notice.decode_notice_files(encoded), None)
    }
  }
}

/// Best-effort write of notice files under `key`, returning any storage warning.
pub fn put_files(
  cache: Cache,
  key: String,
  files: List(notice.NoticeFile),
) -> Option(String) {
  case cache.table {
    None -> None
    Some(table) -> store(table, key, notice.encode_notice_files(files))
  }
}

/// Read a cached plain-text value (e.g. a resolved commit SHA or canonical SPDX
/// text) stored under `key`. A blank stored value is treated as a miss.
pub fn get_text(
  cache: Cache,
  key: String,
) -> #(Result(String, Nil), Option(String)) {
  case cache.table {
    None -> #(Error(Nil), None)
    Some(table) -> {
      use value <- cache_dir.try_with_warning(lookup(table, key))
      case notice.has_text(value) {
        False -> #(Error(Nil), None)
        True -> #(Ok(value), None)
      }
    }
  }
}

/// Best-effort write of a plain-text value under `key`.
pub fn put_text(cache: Cache, key: String, value: String) -> Option(String) {
  case cache.table {
    None -> None
    Some(table) -> store(table, key, value)
  }
}

fn lookup(
  table: cache_dir.Store,
  key: String,
) -> #(Result(String, Nil), Option(String)) {
  case cache_dir.lookup(table, key) {
    Ok(encoded) -> #(Ok(encoded), None)
    Error(error) -> #(Error(Nil), cache_dir.access_warning(error, "notices"))
  }
}

fn store(table: cache_dir.Store, key: String, value: String) -> Option(String) {
  case cache_dir.insert(table, key, value) {
    Ok(Nil) -> None
    Error(error) -> cache_dir.access_warning(error, "notices")
  }
}
