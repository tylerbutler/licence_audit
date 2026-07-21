//// Read-through cache for Hex package licence metadata.
////
//// Wraps a fetcher with a DETS-backed cache keyed by `name@version`. The
//// cache is purely an optimisation: any failure to open, read, or write
//// falls back silently to the network fetcher and records a deferred
//// warning so the caller can surface it after the audit finishes.

import gleam/dynamic/decode
import gleam/int
import gleam/option.{type Option, None, Some}
import slate
import slate/set as dets_set

import licence_audit/cache_dir
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

const cache_entry_ttl_seconds = 86_400

const cached_at_prefix = "$cached_at:"

type TimeUnit {
  Second
}

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

/// Reporter-free read-through fetch keyed by `name@version`.
///
/// A variant of `wrap` for callers that have no progress reporter to thread
/// (e.g. the `notices` metadata lookup). Consults the cache, falls through to
/// `fetcher` on a miss, best-effort writes successful results back, and falls
/// back to a stale entry when the upstream fetch fails. All cache failures are
/// silent: the cache is purely an optimisation.
pub fn fetch_cached_quiet(
  cache: Cache,
  name: String,
  version: String,
  fetcher: fn(String) -> Result(hex.PackageMetadata, hex.Error),
) -> Result(hex.PackageMetadata, hex.Error) {
  case cache.table {
    None -> fetcher(name)
    Some(table) -> {
      let key = name <> "@" <> version
      case lookup_entry(table, key) {
        Ok(metadata) -> Ok(metadata)
        Error(_) -> fetch_and_store_quiet(table, key, fetcher(name))
      }
    }
  }
}

/// Reporter-free counterpart to `fetch_and_store`: record a cache-miss fetch
/// result and, on success, best-effort write it back to `table`. On failure,
/// fall back to a stale cached entry if one is still present and decodable.
fn fetch_and_store_quiet(
  table: dets_set.Set(String, String),
  key: String,
  fetched: Result(hex.PackageMetadata, hex.Error),
) -> Result(hex.PackageMetadata, hex.Error) {
  case fetched {
    Ok(metadata) -> {
      store_quiet(table, key, metadata)
      Ok(metadata)
    }
    Error(error) ->
      case lookup_stale(table, key) {
        Ok(metadata) -> Ok(metadata)
        Error(_) -> Error(error)
      }
  }
}

fn store_quiet(
  table: dets_set.Set(String, String),
  key: String,
  metadata: hex.PackageMetadata,
) -> Nil {
  let _ =
    dets_set.insert(
      into: table,
      key: key,
      value: hex.encode_cache_entry(metadata),
    )
  let _ =
    dets_set.insert(
      into: table,
      key: cached_at_key(key),
      value: int.to_string(now_seconds()),
    )
  Nil
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
    Ok(encoded) ->
      case hex.decode_cache_entry(encoded) {
        Error(_) -> Error(Nil)
        Ok(metadata) ->
          case cache_entry_expired(table, key) {
            True -> Error(Nil)
            False -> Ok(metadata)
          }
      }
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
    Error(error) -> fall_back_to_stale(table, key, error, reporter)
    Ok(metadata) -> {
      let reporter = case
        dets_set.insert(
          into: table,
          key: key,
          value: hex.encode_cache_entry(metadata),
        )
      {
        Ok(_) -> {
          let _ =
            dets_set.insert(
              into: table,
              key: cached_at_key(key),
              value: int.to_string(now_seconds()),
            )
          progress.detail(reporter, "Cached licence metadata for " <> key)
        }
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

/// When an upstream fetch fails, fall back to a stale (expired or unparseable
/// TTL) cached entry if one is still present and decodable. This keeps SBOM
/// enrichment (descriptions, publishers, licences, links) intact across
/// transient Hex outages rather than silently dropping it. A deferred warning
/// makes the fallback visible. If no usable stale entry exists, the original
/// fetch error is returned so the caller can surface its own warning.
fn fall_back_to_stale(
  table: dets_set.Set(String, String),
  key: String,
  error: hex.Error,
  reporter: progress.Reporter,
) -> #(Result(hex.PackageMetadata, hex.Error), progress.Reporter) {
  case lookup_stale(table, key) {
    Ok(metadata) -> {
      let reporter =
        progress.defer_warn(
          reporter,
          "Hex metadata fetch failed for "
            <> key
            <> " ("
            <> hex.describe_error(error)
            <> "); using stale cached metadata",
        )
      #(Ok(metadata), reporter)
    }
    Error(_) -> #(Error(error), reporter)
  }
}

/// Read a cached entry ignoring its TTL. Returns `Error(Nil)` when the entry is
/// absent or no longer decodable.
fn lookup_stale(
  table: dets_set.Set(String, String),
  key: String,
) -> Result(hex.PackageMetadata, Nil) {
  case dets_set.lookup(from: table, key: key) {
    Ok(encoded) -> hex.decode_cache_entry(encoded)
    Error(_) -> Error(Nil)
  }
}

fn cache_entry_expired(
  table: dets_set.Set(String, String),
  key: String,
) -> Bool {
  case cached_at_seconds(table, key) {
    Error(_) -> True
    Ok(cached_at) -> now_seconds() - cached_at > cache_entry_ttl_seconds
  }
}

fn cached_at_seconds(
  table: dets_set.Set(String, String),
  key: String,
) -> Result(Int, Nil) {
  case dets_set.lookup(from: table, key: cached_at_key(key)) {
    Error(_) -> Error(Nil)
    Ok(raw) -> int.parse(raw)
  }
}

fn cached_at_key(key: String) -> String {
  cached_at_prefix <> key
}

fn now_seconds() -> Int {
  erlang_system_time(Second)
}

@external(erlang, "erlang", "system_time")
fn erlang_system_time(unit: TimeUnit) -> Int

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
