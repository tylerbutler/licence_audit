//// Namespaced cache for notice/licence materials.
////
//// Stores extracted files and text in atomic per-entry files. `notice_resolve`
//// supplies immutable keys and bypasses this storage for mutable path
//// dependencies.
////
//// The cache is purely an optimisation. Any failure to open, read, or write
//// lets the resolver read live. Open and close failures produce deferred
//// warnings surfaced via `close`.

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

/// Opaque cache handle. May or may not hold an open directory-backed store.
pub opaque type Cache {
  Cache(table: Option(cache_dir.Store), warning: Option(String))
}

/// On-disk cache format version. Bumped to 3 for the fallback feature, which
/// changes both the cached value shape and the namespaces stored in the table:
/// alongside the final per-package materials, v3 also caches extracted source
/// materials, repository tag→commit resolutions, repository-extracted licence
/// files, pinned SPDX indexes, and canonical SPDX records shared across
/// packages. The version is encoded into the
/// directory name so data written by an older format is ignored rather than
/// mis-decoded; `notice.decode_notice_files` also treats any unparseable entry
/// as a miss, so forward-compatible drift self-heals without a bump.
const cache_format_version = 3

fn cache_filename() -> String {
  "notices-v" <> int.to_string(cache_format_version) <> ".dets"
}

/// Open a cache according to `mode`.
///
/// Never returns an error. If the cache directory can't be opened or the parent
/// directory can't be created, the returned `Cache` is in a passthrough state
/// and includes a deferred warning accessible via `close`.
pub fn open(mode: Mode) -> Cache {
  case mode {
    Disabled -> Cache(table: None, warning: None)
    Enabled(path) ->
      case cache_dir.open_table(path, cache_filename(), "notices") {
        Ok(table) -> Cache(table: Some(table), warning: None)
        Error(warning) -> Cache(table: None, warning: Some(warning))
      }
  }
}

/// Close the cache (if open) and return any deferred warning.
pub fn close(cache: Cache) -> Option(String) {
  case cache.table {
    None -> cache.warning
    Some(table) -> cache_dir.close_table(table, "notices", cache.warning)
  }
}

/// Read a cached list of notice files stored under a namespaced `key`. Returns
/// `Error(Nil)` on a miss, when the cache is disabled, or when the stored value
/// no longer decodes (a corrupt entry is a miss so the caller refetches).
pub fn get_files(
  cache: Cache,
  key: String,
) -> Result(List(notice.NoticeFile), Nil) {
  case cache.table {
    None -> Error(Nil)
    Some(table) -> lookup(table, key)
  }
}

/// Best-effort write of notice files under `key`. A disabled cache or write
/// failure is silently ignored: the cache is purely an optimisation.
pub fn put_files(
  cache: Cache,
  key: String,
  files: List(notice.NoticeFile),
) -> Nil {
  case cache.table {
    None -> Nil
    Some(table) -> store(table, key, files)
  }
}

/// Read a cached plain-text value (e.g. a resolved commit SHA or canonical SPDX
/// text) stored under `key`. An empty stored value is treated as a miss.
pub fn get_text(cache: Cache, key: String) -> Result(String, Nil) {
  case cache.table {
    None -> Error(Nil)
    Some(table) ->
      case cache_dir.lookup(table, key) {
        Ok("") -> Error(Nil)
        Ok(value) -> Ok(value)
        Error(_) -> Error(Nil)
      }
  }
}

/// Best-effort write of a plain-text value under `key`.
pub fn put_text(cache: Cache, key: String, value: String) -> Nil {
  case cache.table {
    None -> Nil
    Some(table) -> {
      let _ = cache_dir.insert(table, key, value)
      Nil
    }
  }
}

fn lookup(
  table: cache_dir.Store,
  key: String,
) -> Result(List(notice.NoticeFile), Nil) {
  case cache_dir.lookup(table, key) {
    Ok(encoded) -> notice.decode_notice_files(encoded)
    Error(_) -> Error(Nil)
  }
}

fn store(
  table: cache_dir.Store,
  key: String,
  files: List(notice.NoticeFile),
) -> Nil {
  let _ = cache_dir.insert(table, key, notice.encode_notice_files(files))
  Nil
}
