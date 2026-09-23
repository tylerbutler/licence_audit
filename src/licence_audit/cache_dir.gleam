//// Shared on-disk cache path resolution for `licence_audit`.
////
//// Both the Hex metadata cache (`cache.gleam`) and the notices source-archive
//// cache (`notice_cache.gleam`) store DETS files under the same directory:
//// `${XDG_CACHE_HOME:-$HOME/.cache}/licence_audit/`. This module centralises
//// the path logic so the two caches stay consistent.

import gleam/dynamic/decode
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import simplifile
import slate
import slate/set as dets_set

import licence_audit/env

const cache_subdir = "licence_audit"

/// Why a cache file path could not be resolved or prepared.
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

/// Resolve the cache file path for `filename`, honouring an explicit override.
/// When `override` is `Some`, it is used verbatim; otherwise the default
/// `${XDG_CACHE_HOME:-$HOME/.cache}/licence_audit/<filename>` is used.
fn resolve_path(
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
fn ensure_parent_dir(path: String) -> Result(Nil, PathError) {
  case parent_directory(path) {
    "" -> Ok(Nil)
    dir ->
      simplifile.create_directory_all(dir)
      |> result.map_error(fn(err) {
        CacheDirCreateFailed(dir: dir, reason: simplifile.describe_error(err))
      })
  }
}

/// Prepare and open a string-keyed cache table, returning its deferred warning
/// on failure.
pub fn open_table(
  path: Option(String),
  filename: String,
  name: String,
) -> Result(dets_set.Set(String, String), String) {
  use resolved <- result.try(
    resolve_path(path, filename) |> result.map_error(describe_path_error),
  )
  use _ <- result.try(
    ensure_parent_dir(resolved) |> result.map_error(describe_path_error),
  )
  case
    dets_set.open(
      resolved,
      key_decoder: decode.string,
      value_decoder: decode.string,
    )
  {
    Ok(table) -> Ok(table)
    Error(error) ->
      Error(
        "Unable to open "
        <> name
        <> " cache at "
        <> resolved
        <> ": "
        <> slate.error_message(error),
      )
  }
}

/// Close a table; a close failure replaces an earlier deferred warning.
pub fn close_table(
  table: dets_set.Set(String, String),
  name: String,
  warning: Option(String),
) -> Option(String) {
  case dets_set.close(table) {
    Ok(_) -> warning
    Error(error) ->
      Some(
        "Failed to close " <> name <> " cache: " <> slate.error_message(error),
      )
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
