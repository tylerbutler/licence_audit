//// Read-through cache for package metadata.
////
//// Mutable Hex API entries are keyed by `name@version` and expire after seven
//// days. Reproducible SBOM entries are keyed by an archive checksum or commit
//// and never expire. Returned storage errors fall back to the source fetcher
//// and record a deferred warning. Upstream sqlight exceptions can stop the
//// command; use `--no-cache` to bypass the driver.

import gleam/int
import gleam/option.{type Option, None, Some}
import gleam/time/timestamp

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

/// Opaque cache handle. Holds a store when caching is enabled and available.
pub opaque type Cache {
  Cache(table: Option(cache_dir.Store), warning: Option(String))
}

const cache_entry_ttl_seconds = 604_800

/// On-disk cache format version. Bump on any incompatible change to the cached
/// value shape (see `hex.encode_cache_entry`). The version is encoded into the
/// cache filename so data written by an older format is ignored
/// rather than read back with the wrong decoder. `hex.decode_cache_entry` also
/// treats any unparseable entry as a miss, so minor/forward-compatible drift
/// self-heals without a bump — reserve bumps for changes that would mis-decode
/// old data (v1 was a bare `List(String)` of licences; v2 is a JSON metadata
/// object).
const cache_format_version = 2

fn cache_filename() -> String {
  "hex-v" <> int.to_string(cache_format_version) <> ".sqlite3"
}

/// Open a cache according to `mode`.
///
/// Returns no error value. If the cache path cannot be prepared, the returned
/// `Cache` bypasses storage and includes a deferred warning accessible via
/// `close`. Upstream sqlight exceptions are not intercepted.
pub fn open(mode: Mode) -> Cache {
  case mode {
    Disabled -> Cache(table: None, warning: None)
    Enabled(path) ->
      case cache_dir.open_table(path, cache_filename(), "licence") {
        Ok(table) -> Cache(table: Some(table), warning: None)
        Error(error) ->
          Cache(table: None, warning: Some(cache_dir.describe_error(error)))
      }
  }
}

/// Return the warning from opening the cache. Operations return their own
/// warnings explicitly; no connection remains open between operations.
pub fn close(cache: Cache) -> Option(String) {
  cache.warning
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
      Some(table) -> {
        let #(cached, warning) = lookup_entry(table, key)
        let reporter = defer_warning(reporter, warning)
        case cached {
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
}

/// Reporter-free read-through fetch keyed by `name@version`.
///
/// A variant of `wrap` for callers that have no progress reporter to thread
/// (e.g. the `notices` metadata lookup). Consults the cache, falls through to
/// `fetcher` on a miss, best-effort writes successful results back, and falls
/// back to a stale entry when the upstream fetch fails. Storage failures return
/// an optional warning without replacing the fetch result.
pub fn fetch_cached_quiet(
  cache: Cache,
  name: String,
  version: String,
  fetcher: fn(String) -> Result(hex.PackageMetadata, hex.Error),
) -> #(Result(hex.PackageMetadata, hex.Error), Option(String)) {
  case cache.table {
    None -> #(fetcher(name), None)
    Some(table) -> {
      let key = name <> "@" <> version
      use cached <- cache_dir.with_warning(lookup_entry(table, key))
      case cached {
        Ok(metadata) -> #(Ok(metadata), None)
        Error(_) -> fetch_and_store_quiet(table, key, fetcher(name))
      }
    }
  }
}

/// Fetch immutable package metadata under a content-addressed key.
///
/// Unlike normal Hex package metadata, these entries never expire because the
/// key identifies a locked archive checksum or commit. The namespace version
/// invalidates entries produced by the old, incomplete archive decoder.
pub fn fetch_immutable(
  cache: Cache,
  key: String,
  fetcher: fn() -> Result(hex.PackageMetadata, error),
) -> #(Result(hex.PackageMetadata, error), Option(String)) {
  let key = "$immutable:v2:" <> key
  case cache.table {
    None -> #(fetcher(), None)
    Some(table) -> {
      use cached <- cache_dir.with_warning(lookup_stale(table, key))
      case cached {
        Ok(metadata) -> #(Ok(metadata), None)
        Error(_) ->
          case fetcher() {
            Error(error) -> #(Error(error), None)
            Ok(metadata) -> {
              let stored =
                cache_dir.insert(table, key, hex.encode_cache_entry(metadata))
              #(Ok(metadata), write_warning(stored))
            }
          }
      }
    }
  }
}

/// Reporter-free counterpart to `fetch_and_store`: record a cache-miss fetch
/// result and, on success, best-effort write it back to `table`. On failure,
/// fall back to a stale cached entry if one is still present and decodable.
fn fetch_and_store_quiet(
  table: cache_dir.Store,
  key: String,
  fetched: Result(hex.PackageMetadata, hex.Error),
) -> #(Result(hex.PackageMetadata, hex.Error), Option(String)) {
  case fetched {
    Ok(metadata) -> {
      #(Ok(metadata), write_warning(store_quiet(table, key, metadata)))
    }
    Error(error) -> {
      use cached <- cache_dir.with_warning(lookup_stale(table, key))
      case cached {
        Ok(metadata) -> #(Ok(metadata), None)
        Error(_) -> #(Error(error), None)
      }
    }
  }
}

fn store_quiet(
  table: cache_dir.Store,
  key: String,
  metadata: hex.PackageMetadata,
) -> Result(Nil, cache_dir.Error) {
  cache_dir.insert_at(
    table,
    key,
    hex.encode_cache_entry(metadata),
    Some(now_seconds()),
  )
}

fn lookup_entry(
  table: cache_dir.Store,
  key: String,
) -> #(Result(hex.PackageMetadata, Nil), Option(String)) {
  // A stored value that no longer parses (e.g. partial format drift) is
  // reported as a miss so the caller refetches rather than failing.
  case cache_dir.lookup_entry(table, key) {
    Ok(entry) -> {
      let metadata = case hex.decode_cache_entry(entry.value) {
        Error(_) -> Error(Nil)
        Ok(metadata) ->
          case cache_entry_expired(entry.cached_at) {
            True -> Error(Nil)
            False -> Ok(metadata)
          }
      }
      #(metadata, None)
    }
    Error(error) -> #(Error(Nil), cache_dir.access_warning(error, "licence"))
  }
}

/// Record successful fetches without failing them on cache storage errors.
fn fetch_and_store(
  table: cache_dir.Store,
  key: String,
  fetched: Result(hex.PackageMetadata, hex.Error),
  reporter: progress.Reporter,
) -> #(Result(hex.PackageMetadata, hex.Error), progress.Reporter) {
  case fetched {
    Error(error) -> fall_back_to_stale(table, key, error, reporter)
    Ok(metadata) -> {
      let reporter = case store_quiet(table, key, metadata) {
        Ok(_) ->
          progress.detail(reporter, "Cached licence metadata for " <> key)
        Error(error) ->
          defer_warning(
            progress.detail(
              reporter,
              "Failed to write cache entry for "
                <> key
                <> ": "
                <> cache_dir.describe_error(error),
            ),
            cache_dir.access_warning(error, "licence"),
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
  table: cache_dir.Store,
  key: String,
  error: hex.Error,
  reporter: progress.Reporter,
) -> #(Result(hex.PackageMetadata, hex.Error), progress.Reporter) {
  let #(cached, warning) = lookup_stale(table, key)
  let reporter = defer_warning(reporter, warning)
  case cached {
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
  table: cache_dir.Store,
  key: String,
) -> #(Result(hex.PackageMetadata, Nil), Option(String)) {
  case cache_dir.lookup(table, key) {
    Ok(encoded) -> #(hex.decode_cache_entry(encoded), None)
    Error(error) -> #(Error(Nil), cache_dir.access_warning(error, "licence"))
  }
}

fn write_warning(result: Result(Nil, cache_dir.Error)) -> Option(String) {
  case result {
    Ok(Nil) -> None
    Error(error) -> cache_dir.access_warning(error, "licence")
  }
}

fn defer_warning(
  reporter: progress.Reporter,
  warning: Option(String),
) -> progress.Reporter {
  case warning {
    None -> reporter
    Some(message) -> progress.defer_warn(reporter, message)
  }
}

fn cache_entry_expired(cached_at: Option(Int)) -> Bool {
  case cached_at {
    None -> True
    Some(seconds) -> now_seconds() - seconds > cache_entry_ttl_seconds
  }
}

fn now_seconds() -> Int {
  let #(seconds, _) =
    timestamp.system_time()
    |> timestamp.to_unix_seconds_and_nanoseconds
  seconds
}

fn cache_key(package: manifest.Package) -> String {
  package.name <> "@" <> package.version
}
