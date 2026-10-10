//// Shared on-disk cache storage for `licence_audit`.
////
//// Each cache uses a directory next to its former DETS filename. Every key is
//// stored in a separate file and published with an atomic rename, so separate
//// Erlang VMs can safely add entries without replacing each other's writes.

import gleam/bit_array
import gleam/option.{type Option, None, Some}
import gleam/result
import simplifile

import licence_audit/env
import licence_audit/path

const cache_subdir = "licence_audit"

const entries_suffix = ".entries"

/// A directory-backed string cache.
pub type Store

/// Why a cache path could not be resolved or prepared.
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

fn resolve_path(
  override: Option(String),
  filename: String,
) -> Result(String, PathError) {
  case override {
    Some(cache_path) -> Ok(cache_path <> entries_suffix)
    None ->
      default_path(filename)
      |> result.map(fn(cache_path) { cache_path <> entries_suffix })
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
  use _ <- result.try(
    simplifile.create_directory_all(parent)
    |> result.map_error(fn(error) {
      CacheDirCreateFailed(
        dir: parent,
        reason: simplifile.describe_error(error),
      )
    }),
  )
  simplifile.create_directory_all(cache_path)
  |> result.map_error(fn(error) {
    CacheDirCreateFailed(
      dir: cache_path,
      reason: simplifile.describe_error(error),
    )
  })
}

/// Open a string-keyed cache store, returning its deferred warning on failure.
pub fn open_table(
  cache_path: Option(String),
  filename: String,
  name: String,
) -> Result(Store, String) {
  use resolved <- result.try(
    resolve_path(cache_path, filename) |> result.map_error(describe_path_error),
  )
  case ensure_cache_dir(resolved) {
    Ok(Nil) -> Ok(new_store(resolved))
    Error(error) ->
      Error(
        "Unable to open "
        <> name
        <> " cache at "
        <> resolved
        <> ": "
        <> describe_path_error(error),
      )
  }
}

/// Read one complete cache entry.
pub fn lookup(store: Store, key: String) -> Result(String, Nil) {
  case read(store, key) {
    Error(_) -> Error(Nil)
    Ok(contents) ->
      case bit_array.to_string(contents) {
        Ok(value) -> Ok(value)
        Error(_) -> {
          warn(store, "cache entry for " <> key <> " contains invalid UTF-8")
          Error(Nil)
        }
      }
  }
}

/// Atomically publish one complete cache entry.
pub fn insert(store: Store, key: String, value: String) -> Result(Nil, String) {
  write(store, key, value)
}

/// Close a store and return the latest deferred warning.
pub fn close_table(
  store: Store,
  name: String,
  warning: Option(String),
) -> Option(String) {
  case take_warning(store) {
    None -> warning
    Some(error) -> Some("Failed to access " <> name <> " cache: " <> error)
  }
}

@external(erlang, "cache_dir_ffi", "new_store")
fn new_store(path: String) -> Store

@external(erlang, "cache_dir_ffi", "read")
fn read(store: Store, key: String) -> Result(BitArray, String)

@external(erlang, "cache_dir_ffi", "write")
fn write(store: Store, key: String, value: String) -> Result(Nil, String)

@external(erlang, "cache_dir_ffi", "warn")
fn warn(store: Store, warning: String) -> Nil

@external(erlang, "cache_dir_ffi", "take_warning")
fn take_warning(store: Store) -> Option(String)
