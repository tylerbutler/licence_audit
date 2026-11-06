//// Shared on-disk cache storage for `licence_audit`.
////
//// Each entry is one JSON file named by the SHA-256 hash of its key. A write
//// goes to a unique temporary file in the same directory, which is then
//// renamed over the entry. Readers therefore see the old entry, the new entry,
//// or no entry, but never a partial file. Concurrent commands need no locks:
//// when two writers race on one key, either value is acceptable.
////
//// OTP's Windows rename moves an existing destination aside before it moves
//// the new file into place, so a reader can see no entry for a short time.
//// That is an ordinary cache miss.

import gleam/bit_array
import gleam/crypto
import gleam/dynamic/decode
import gleam/json
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import simplifile

import licence_audit/env
import licence_audit/path

const cache_subdir = "licence_audit"

const entry_suffix = ".json"

const temporary_suffix = ".tmp"

/// An on-disk string cache rooted at one directory.
pub opaque type Store {
  Store(directory: String)
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
  directory: String,
) -> Result(String, PathError) {
  case override {
    Some(cache_path) -> Ok(cache_path)
    None -> default_path(directory)
  }
}

fn default_path(directory: String) -> Result(String, PathError) {
  case env.get("XDG_CACHE_HOME") {
    Ok(cache_home) if cache_home != "" ->
      Ok(path.join(path.join(cache_home, cache_subdir), directory))
    _ ->
      case env.get("HOME") {
        Ok(home) if home != "" ->
          Ok(path.join(
            path.join(path.join(home, ".cache"), cache_subdir),
            directory,
          ))
        _ -> Error(CacheDirUnknown)
      }
  }
}

fn ensure_cache_dir(directory: String) -> Result(Nil, PathError) {
  simplifile.create_directory_all(directory)
  |> result.map_error(fn(error) {
    CacheDirCreateFailed(dir: directory, reason: error)
  })
}

/// Open a string-keyed cache store, returning its deferred warning on failure.
///
/// `cache_path` overrides the store directory. Otherwise the store uses
/// `directory` below the user cache directory.
pub fn open_table(
  cache_path: Option(String),
  directory: String,
  name: String,
) -> Result(Store, Error) {
  use resolved <- result.try(
    resolve_path(cache_path, directory) |> result.map_error(PathFailed),
  )
  use _ <- result.try(
    ensure_cache_dir(resolved)
    |> result.map_error(fn(error) {
      OpenFailed(name, resolved, describe_path_error(error))
    }),
  )
  Ok(Store(directory: resolved))
}

/// Read one cache value.
pub fn lookup(store: Store, key: String) -> Result(String, Error) {
  lookup_entry(store, key) |> result.map(fn(entry) { entry.value })
}

/// Read a value and its timestamp from the same entry file.
pub fn lookup_entry(store: Store, key: String) -> Result(Entry, Error) {
  case simplifile.read(entry_path(store, key)) {
    Ok(contents) ->
      decode_entry(contents, key)
      |> result.map_error(fn(reason) { ReadFailed(key, reason) })
    Error(simplifile.Enoent) -> Error(EntryMissing)
    Error(error) -> Error(ReadFailed(key, simplifile.describe_error(error)))
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
  let destination = entry_path(store, key)
  let temporary = temporary_path(destination)
  let contents = encode_entry(key, value, cached_at)
  let fail = fn(error) {
    let _ = simplifile.delete(temporary)
    Error(WriteFailed(key, simplifile.describe_error(error)))
  }
  case simplifile.write(to: temporary, contents: contents) {
    Error(error) -> fail(error)
    Ok(Nil) ->
      case simplifile.rename(at: temporary, to: destination) {
        Ok(Nil) -> Ok(Nil)
        Error(error) ->
          // On Windows, a rename that loses a race with another writer can
          // fail. The other writer's entry is an equally valid cache value.
          case simplifile.is_file(destination) {
            Ok(True) -> {
              let _ = simplifile.delete(temporary)
              Ok(Nil)
            }
            Ok(False) | Error(_) -> fail(error)
          }
      }
  }
}

fn entry_path(store: Store, key: String) -> String {
  let digest =
    crypto.hash(crypto.Sha256, bit_array.from_string(key))
    |> bit_array.base16_encode
    |> string.lowercase
  path.join(store.directory, digest <> entry_suffix)
}

/// A temporary name that is unique across concurrent VMs.
fn temporary_path(destination: String) -> String {
  let nonce =
    crypto.strong_random_bytes(12)
    |> bit_array.base16_encode
    |> string.lowercase
  destination <> "." <> nonce <> temporary_suffix
}

fn encode_entry(key: String, value: String, cached_at: Option(Int)) -> String {
  json.object([
    #("key", json.string(key)),
    #("cached_at", json.nullable(cached_at, json.int)),
    #("value", json.string(value)),
  ])
  |> json.to_string
}

fn decode_entry(contents: String, key: String) -> Result(Entry, String) {
  let decoder = {
    use stored_key <- decode.field("key", decode.string)
    use cached_at <- decode.field("cached_at", decode.optional(decode.int))
    use value <- decode.field("value", decode.string)
    decode.success(#(stored_key, Entry(value, cached_at)))
  }
  case json.parse(from: contents, using: decoder) {
    Ok(#(stored_key, entry)) if stored_key == key -> Ok(entry)
    Ok(_) -> Error("Cache entry belongs to a different key")
    Error(_) -> Error("Invalid cached value or timestamp")
  }
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
