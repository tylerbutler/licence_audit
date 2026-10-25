//// Shared on-disk cache storage for `licence_audit`.
////
//// Reads and writes use short exclusive sessions so concurrent CLI runs
//// can share cached entries without corrupting or overwriting each other's
//// data.

import gleam/dynamic/decode
import gleam/erlang/reference.{type Reference}
import gleam/option.{type Option, None, Some}
import gleam/result
import simplifile
import slate
import slate/exclusive
import slate/set

import licence_audit/env
import licence_audit/path

const cache_subdir = "licence_audit"

const lock_wait = exclusive.WaitUpTo(5000)

/// An on-disk string cache.
pub opaque type Store {
  Store(path: String, warnings: Reference)
}

/// Why a cache path could not be resolved or prepared.
type PathError {
  CacheDirUnknown
  CacheDirCreateFailed(dir: String, reason: simplifile.FileError)
}

pub opaque type Error {
  PathFailed(PathError)
  OpenFailed(name: String, path: String, reason: PathError)
  WriteFailed(key: String, reason: exclusive.SessionError)
}

pub fn describe_error(error: Error) -> String {
  case error {
    PathFailed(reason) -> describe_path_error(reason)
    OpenFailed(name, path, reason) ->
      "Unable to open "
      <> name
      <> " cache at "
      <> path
      <> ": "
      <> describe_path_error(reason)
    WriteFailed(key, reason) ->
      "write " <> key <> ": " <> exclusive.error_message(reason)
  }
}

fn describe_path_error(error: PathError) -> String {
  case error {
    CacheDirUnknown ->
      "Unable to determine licence cache directory: set XDG_CACHE_HOME, HOME, or Windows LOCALAPPDATA/USERPROFILE"
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
  case default_directory(is_windows(), env.get) {
    Ok(directory) -> Ok(path.join(path.join(directory, cache_subdir), filename))
    Error(Nil) -> Error(CacheDirUnknown)
  }
}

pub fn default_directory(
  windows: Bool,
  get: fn(String) -> Result(String, Nil),
) -> Result(String, Nil) {
  case get("XDG_CACHE_HOME") {
    Ok(cache_home) if cache_home != "" -> Ok(cache_home)
    _ ->
      case windows {
        True ->
          case get("LOCALAPPDATA") {
            Ok(local) if local != "" -> Ok(local)
            _ ->
              case get("USERPROFILE") {
                Ok(profile) if profile != "" ->
                  Ok(path.join(profile, "AppData/Local"))
                _ -> unix_cache_directory(get)
              }
          }
        False -> unix_cache_directory(get)
      }
  }
}

fn unix_cache_directory(
  get: fn(String) -> Result(String, Nil),
) -> Result(String, Nil) {
  case get("HOME") {
    Ok(home) if home != "" -> Ok(path.join(home, ".cache"))
    _ -> Error(Nil)
  }
}

@external(erlang, "cache_dir_ffi", "is_windows")
fn is_windows() -> Bool

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
  case ensure_cache_dir(resolved) {
    Ok(Nil) -> Ok(Store(path: resolved, warnings: reference.new()))
    Error(error) -> Error(OpenFailed(name, resolved, error))
  }
}

/// Read one cache entry in a short exclusive session.
pub fn lookup(store: Store, key: String) -> Result(String, Nil) {
  case
    set.with_exclusive_table(
      path: store.path,
      repair: slate.AutoRepair,
      access: slate.ReadWrite,
      wait: lock_wait,
      key_decoder: decode.string,
      value_decoder: decode.string,
      callback: fn(table) { set.lookup(table, key: key) },
    )
  {
    Ok(value) -> Ok(value)
    Error(exclusive.SessionFailed(exclusive.CallbackFailure(slate.NotFound))) ->
      Error(Nil)
    Error(error) -> {
      warn(store, "read " <> key <> ": " <> exclusive.error_message(error))
      Error(Nil)
    }
  }
}

/// Publish one cache entry in a short exclusive session.
pub fn insert(store: Store, key: String, value: String) -> Result(Nil, Error) {
  set.with_exclusive_table(
    path: store.path,
    repair: slate.AutoRepair,
    access: slate.ReadWrite,
    wait: lock_wait,
    key_decoder: decode.string,
    value_decoder: decode.string,
    callback: fn(table) { set.insert(table, key, value) },
  )
  |> result.map_error(fn(error) {
    let error = WriteFailed(key, error)
    warn(store, describe_error(error))
    error
  })
}

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
