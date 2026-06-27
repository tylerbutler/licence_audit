//// Shared on-disk cache path resolution for `licence_audit`.
////
//// Both the Hex metadata cache (`cache.gleam`) and the notices source-archive
//// cache (`notices_cache.gleam`) store DETS files under the same directory:
//// `${XDG_CACHE_HOME:-$HOME/.cache}/licence_audit/`. This module centralises
//// the path logic so the two caches stay consistent.

import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import simplifile

import licence_audit/env

const cache_subdir = "licence_audit"

/// Why a cache file path could not be resolved or prepared.
pub type PathError {
  CacheDirUnknown
  CacheDirCreateFailed(dir: String, reason: String)
}

pub fn describe_path_error(error: PathError) -> String {
  case error {
    CacheDirUnknown ->
      "Unable to determine licence cache directory: neither XDG_CACHE_HOME nor HOME is set"
    CacheDirCreateFailed(dir, reason) ->
      "Unable to create licence cache directory " <> dir <> ": " <> reason
  }
}

/// Resolve the cache file path for `filename`, honouring an explicit override.
/// When `override` is `Some`, it is used verbatim; otherwise the default
/// `${XDG_CACHE_HOME:-$HOME/.cache}/licence_audit/<filename>` is used.
pub fn resolve_path(
  override: Option(String),
  filename: String,
) -> Result(String, PathError) {
  case override {
    Some(path) -> Ok(path)
    None -> default_path(filename)
  }
}

fn default_path(filename: String) -> Result(String, PathError) {
  case env.get("XDG_CACHE_HOME") {
    Ok(dir) if dir != "" -> Ok(join_path(dir, filename))
    _ ->
      case env.get("HOME") {
        Ok(home) if home != "" -> Ok(join_path(home <> "/.cache", filename))
        _ -> Error(CacheDirUnknown)
      }
  }
}

fn join_path(base: String, filename: String) -> String {
  base <> "/" <> cache_subdir <> "/" <> filename
}

/// Ensure the parent directory of `path` exists, creating it if needed.
pub fn ensure_parent_dir(path: String) -> Result(Nil, PathError) {
  case parent_directory(path) {
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
