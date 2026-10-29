//// Shared on-disk cache storage for `licence_audit`.
////
//// Each operation opens and closes a sqlight connection. Returned errors,
//// busy-query exceptions, and native-library load failures become warnings.

import gleam/dynamic/decode
import gleam/int
import gleam/option.{type Option, None, Some}
import gleam/result
import simplifile
import sqlight

import licence_audit/env
import licence_audit/path

const cache_subdir = "licence_audit"

/// An on-disk string cache.
pub opaque type Store {
  Store(path: String)
}

pub type Entry {
  Entry(value: String, cached_at: Option(Int))
}

/// Why a cache path could not be resolved or prepared.
type PathError {
  CacheDirUnknown
  CacheDirCreateFailed(dir: String, reason: simplifile.FileError)
}

pub opaque type Error {
  PathFailed(PathError)
  OpenFailed(name: String, path: String, reason: String)
  EntryMissing
  ReadFailed(key: String, reason: String)
  WriteFailed(key: String, reason: String)
}

pub fn describe_error(error: Error) -> String {
  case error {
    PathFailed(reason) -> describe_path_error(reason)
    OpenFailed(name, path, reason) ->
      "Unable to open " <> name <> " cache at " <> path <> ": " <> reason
    EntryMissing -> "Cache entry not found"
    ReadFailed(key, reason) -> "read " <> key <> ": " <> reason
    WriteFailed(key, reason) -> "write " <> key <> ": " <> reason
  }
}

fn describe_path_error(error: PathError) -> String {
  case error {
    CacheDirUnknown ->
      "Unable to determine licence cache directory: neither XDG_CACHE_HOME nor HOME is set"
    CacheDirCreateFailed(dir, reason) ->
      "Unable to create licence cache directory "
      <> dir
      <> ": "
      <> simplifile.describe_error(reason)
  }
}

fn resolve_path(
  override: Option(String),
  filename: String,
) -> Result(String, PathError) {
  case override {
    Some(cache_path) -> Ok(cache_path)
    None -> default_path(filename)
  }
}

fn default_path(filename: String) -> Result(String, PathError) {
  case env.get("XDG_CACHE_HOME") {
    Ok(cache_home) if cache_home != "" ->
      Ok(path.join(path.join(cache_home, cache_subdir), filename))
    _ ->
      case env.get("HOME") {
        Ok(home) if home != "" ->
          Ok(path.join(
            path.join(path.join(home, ".cache"), cache_subdir),
            filename,
          ))
        _ -> Error(CacheDirUnknown)
      }
  }
}

fn ensure_cache_dir(cache_path: String) -> Result(Nil, PathError) {
  let parent = path.dirname(cache_path)
  simplifile.create_directory_all(parent)
  |> result.map_error(fn(error) {
    CacheDirCreateFailed(dir: parent, reason: error)
  })
}

/// Open a string-keyed cache store, returning its deferred warning on failure.
pub fn open_table(
  cache_path: Option(String),
  filename: String,
  name: String,
) -> Result(Store, Error) {
  use resolved <- result.try(
    resolve_path(cache_path, filename) |> result.map_error(PathFailed),
  )
  use _ <- result.try(
    ensure_cache_dir(resolved)
    |> result.map_error(fn(error) {
      OpenFailed(name, resolved, describe_path_error(error))
    }),
  )
  use _ <- result.try(
    open(resolved)
    |> result.map_error(fn(error) { OpenFailed(name, resolved, error) }),
  )
  Ok(Store(path: resolved))
}

/// Read one cache value without keeping a connection open.
pub fn lookup(store: Store, key: String) -> Result(String, Error) {
  lookup_entry(store, key) |> result.map(fn(entry) { entry.value })
}

/// Read a value and its timestamp from the same SQLite row.
pub fn lookup_entry(store: Store, key: String) -> Result(Entry, Error) {
  case read_entry(store.path, key) {
    Ok(Some(entry)) -> Ok(entry)
    Ok(None) -> Error(EntryMissing)
    Error(error) -> Error(ReadFailed(key, error))
  }
}

/// Publish an immutable cache value.
pub fn insert(store: Store, key: String, value: String) -> Result(Nil, Error) {
  insert_at(store, key, value, None)
}

/// Publish a value and optional expiry timestamp atomically.
pub fn insert_at(
  store: Store,
  key: String,
  value: String,
  cached_at: Option(Int),
) -> Result(Nil, Error) {
  write_entry(store.path, key, value, cached_at)
  |> result.map_error(fn(error) { WriteFailed(key, error) })
}

fn open(path: String) -> Result(Nil, String) {
  use connection <- with_connection(path)
  use modes <- result.try(
    sqlight.query(
      "PRAGMA journal_mode=WAL",
      on: connection,
      with: [],
      expecting: decode.field(0, decode.string, decode.success),
    )
    |> result.map_error(describe_sqlite_error),
  )
  case modes {
    ["wal"] ->
      sqlight.exec(
        "CREATE TABLE IF NOT EXISTS cache_entries (
           key TEXT PRIMARY KEY,
           value TEXT NOT NULL,
           cached_at INTEGER
         )",
        on: connection,
      )
      |> result.map_error(describe_sqlite_error)
    _ -> Error("SQLite WAL mode is unavailable")
  }
}

fn read_entry(path: String, key: String) -> Result(Option(Entry), String) {
  use connection <- with_connection(path)
  let decoder = {
    use value <- decode.field(0, decode.string)
    use cached_at <- decode.field(1, decode.optional(decode.int))
    decode.success(Entry(value, cached_at))
  }
  use entries <- result.try(
    sqlight.query(
      "SELECT value, cached_at FROM cache_entries WHERE key = ?",
      on: connection,
      with: [sqlight.text(key)],
      expecting: decoder,
    )
    |> result.map_error(describe_sqlite_error),
  )
  case entries {
    [] -> Ok(None)
    [entry] -> Ok(Some(entry))
    _ -> Error("Invalid cached value or timestamp")
  }
}

fn write_entry(
  path: String,
  key: String,
  value: String,
  cached_at: Option(Int),
) -> Result(Nil, String) {
  use connection <- with_connection(path)
  sqlight.query(
    "INSERT INTO cache_entries (key, value, cached_at) VALUES (?, ?, ?)
     ON CONFLICT(key) DO UPDATE SET
       value = excluded.value, cached_at = excluded.cached_at",
    on: connection,
    with: [
      sqlight.text(key),
      sqlight.text(value),
      sqlight.nullable(sqlight.int, cached_at),
    ],
    expecting: decode.success(Nil),
  )
  |> result.map(fn(_) { Nil })
  |> result.map_error(describe_sqlite_error)
}

fn with_connection(
  path: String,
  action: fn(sqlight.Connection) -> Result(value, String),
) -> Result(value, String) {
  use _ <- result.try(ensure_sqlite_loaded())
  // Failed native opens can still abort the VM; tracked in #168.
  use connection <- result.try(
    sqlight.open(path) |> result.map_error(describe_sqlite_error),
  )
  let #(outcome, closed) =
    run_with_connection(connection, fn(connection) {
      use _ <- result.try(
        sqlight.exec("PRAGMA busy_timeout=0", on: connection)
        |> result.map_error(describe_sqlite_error),
      )
      action(connection)
    })
  case outcome, closed {
    Ok(value), Ok(Nil) -> Ok(value)
    Error(error), Ok(Nil) -> Error(error)
    Ok(_), Error(error) -> Error(describe_sqlite_error(error))
    Error(first), Error(second) ->
      Error(first <> "; close: " <> describe_sqlite_error(second))
  }
}

@external(erlang, "cache_dir_ffi", "ensure_sqlite_loaded")
fn ensure_sqlite_loaded() -> Result(Nil, String)

@external(erlang, "cache_dir_ffi", "with_connection")
fn run_with_connection(
  connection: sqlight.Connection,
  action: fn(sqlight.Connection) -> Result(value, String),
) -> #(Result(value, String), Result(Nil, sqlight.Error))

fn describe_sqlite_error(error: sqlight.Error) -> String {
  "SQLite error "
  <> int.to_string(sqlight.error_code_to_int(error.code))
  <> ": "
  <> error.message
}

/// Describe an access failure as a warning, excluding ordinary cache misses.
pub fn access_warning(error: Error, name: String) -> Option(String) {
  case error {
    EntryMissing -> None
    PathFailed(_)
    | OpenFailed(_, _, _)
    | ReadFailed(_, _)
    | WriteFailed(_, _) ->
      Some("Failed to access " <> name <> " cache: " <> describe_error(error))
  }
}

/// Pass a cache result to its caller, keeping the latest returned warning.
pub fn with_warning(
  returned: #(value, Option(String)),
  next: fn(value) -> #(output, Option(String)),
) -> #(output, Option(String)) {
  let #(value, warning) = returned
  let #(output, next_warning) = next(value)
  #(output, option.or(next_warning, warning))
}

/// Stop on an error without losing the warning returned with it.
pub fn try_with_warning(
  returned: #(Result(value, error), Option(String)),
  next: fn(value) -> #(Result(output, error), Option(String)),
) -> #(Result(output, error), Option(String)) {
  use outcome <- with_warning(returned)
  case outcome {
    Ok(value) -> next(value)
    Error(error) -> #(Error(error), None)
  }
}
