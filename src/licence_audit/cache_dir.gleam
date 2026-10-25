//// Shared on-disk cache storage for `licence_audit`.
////
//// Each operation opens and closes a SQLite connection. WAL lets readers
//// continue during writes; busy operations are skipped without waiting.

import gleam/erlang/reference.{type Reference}
import gleam/option.{type Option, None, Some}
import gleam/result
import simplifile

import licence_audit/env
import licence_audit/path

const cache_subdir = "licence_audit"

/// An on-disk string cache.
pub opaque type Store {
  Store(path: String, warnings: Reference)
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
  WriteFailed(key: String, reason: String)
}

pub fn describe_error(error: Error) -> String {
  case error {
    PathFailed(reason) -> describe_path_error(reason)
    OpenFailed(name, path, reason) ->
      "Unable to open " <> name <> " cache at " <> path <> ": " <> reason
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
    ffi_open(resolved)
    |> result.map_error(fn(error) { OpenFailed(name, resolved, error) }),
  )
  Ok(Store(path: resolved, warnings: reference.new()))
}

/// Read one cache value without keeping a connection open.
pub fn lookup(store: Store, key: String) -> Result(String, Nil) {
  lookup_entry(store, key) |> result.map(fn(entry) { entry.value })
}

/// Read a value and its timestamp from the same SQLite row.
pub fn lookup_entry(store: Store, key: String) -> Result(Entry, Nil) {
  case ffi_lookup(store.path, key) {
    Ok(Some(entry)) -> Ok(entry)
    Ok(None) -> Error(Nil)
    Error(error) -> {
      warn(store, "read " <> key <> ": " <> error)
      Error(Nil)
    }
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
  ffi_insert(store.path, key, value, cached_at)
  |> result.map_error(fn(error) {
    let error = WriteFailed(key, error)
    warn(store, describe_error(error))
    error
  })
}

@external(erlang, "cache_dir_ffi", "open")
fn ffi_open(path: String) -> Result(Nil, String)

@external(erlang, "cache_dir_ffi", "lookup")
fn ffi_lookup(path: String, key: String) -> Result(Option(Entry), String)

@external(erlang, "cache_dir_ffi", "insert")
fn ffi_insert(
  path: String,
  key: String,
  value: String,
  cached_at: Option(Int),
) -> Result(Nil, String)

/// Close a store and return the latest deferred warning.
pub fn close_table(
  store: Store,
  name: String,
  warning: Option(String),
) -> Option(String) {
  case ffi_take_warning(store.warnings) {
    None -> warning
    Some(error) -> Some("Failed to access " <> name <> " cache: " <> error)
  }
}

@external(erlang, "cache_dir_ffi", "warn")
fn ffi_warn(warnings: Reference, warning: String) -> Nil

@external(erlang, "cache_dir_ffi", "take_warning")
fn ffi_take_warning(warnings: Reference) -> Option(String)

fn warn(store: Store, warning: String) -> Nil {
  ffi_warn(store.warnings, warning)
}
