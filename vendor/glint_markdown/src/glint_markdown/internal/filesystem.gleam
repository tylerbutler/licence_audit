//// Narrow filesystem support for the executor. All writes are staged on the
//// destination filesystem; there is deliberately no truncating-write fallback.

import filepath
import gleam/int
import gleam/option.{type Option, None, Some}
import gleam/result
import simplifile

/// Resolve native path components and symbolic links, including existing
/// parents of missing files. Unlike lexical expansion, `link/..` is resolved
/// relative to the link's referent. The result uses forward-slash separators.
///
/// simplifile 2.4 has no read-link/canonical-path API; newer simplifile's
/// `resolve` only performs lexical expansion, not symlink resolution.
@external(erlang, "glint_markdown_filesystem_ffi", "canonical_path")
@external(javascript, "./filesystem_ffi.mjs", "canonical_path")
pub fn canonical_path(path: String) -> Result(String, String)

/// Atomically replace a resolved destination. Existing symbolic links must
/// already have been resolved by `canonical_path`; newly encountered links are
/// refused. Changed hardlinked files are refused rather than silently severed.
pub fn replace(path: String, contents: BitArray) -> Result(Nil, String) {
  replace_with(path, contents, simplifile.write_bits)
}

/// The staging writer owns only the temporary file, never the destination.
/// This internal seam also permits testing partial-write failures without
/// depending on disk exhaustion or permissions (tests may run as root).
pub fn replace_with(
  path: String,
  contents: BitArray,
  write: fn(String, BitArray) -> Result(Nil, simplifile.FileError),
) -> Result(Nil, String) {
  use original <- result.try(snapshot(path))
  let parent = filepath.directory_name(path)
  use _ <- result.try(
    simplifile.create_directory_all(parent)
    |> operation("create parent directory " <> parent),
  )
  use temporary_directory <- result.try(reserve_directory(parent, 0))
  let temporary_path = temporary_directory <> "/contents"
  let replacement = {
    use _ <- result.try(
      simplifile.set_permissions_octal(temporary_directory, 0o700)
      |> operation("protect temporary directory " <> temporary_directory),
    )
    use _ <- result.try(
      write(temporary_path, contents)
      |> operation("write temporary file " <> temporary_path),
    )
    use _ <- result.try(preserve_permissions(temporary_path, original))
    use _ <- result.try(verify_destination(path, original))
    simplifile.rename(temporary_path, path)
    |> operation("rename " <> temporary_path <> " to " <> path)
  }

  // Do not remove stale reservations that we did not create. Cleanup errors
  // are reported alongside the primary error, including after a successful
  // rename (when the destination has already been replaced).
  case simplifile.delete(temporary_directory), replacement {
    Ok(_), outcome -> outcome
    Error(cleanup_error), Ok(_) ->
      Error(
        "replacement completed, but cleanup of "
        <> temporary_directory
        <> " failed: "
        <> simplifile.describe_error(cleanup_error),
      )
    Error(cleanup_error), Error(reason) ->
      Error(
        reason
        <> "; cleanup of "
        <> temporary_directory
        <> " failed: "
        <> simplifile.describe_error(cleanup_error),
      )
  }
}

fn snapshot(path: String) -> Result(Option(simplifile.FileInfo), String) {
  case simplifile.link_info(path) {
    Error(simplifile.Enoent) -> Ok(None)
    Error(reason) ->
      Error(
        "inspect destination "
        <> path
        <> ": "
        <> simplifile.describe_error(reason),
      )
    Ok(information) ->
      case simplifile.file_info_type(information) {
        simplifile.File if information.nlinks > 1 ->
          Error(
            "refusing atomic replacement of hardlinked file "
            <> path
            <> " ("
            <> int.to_string(information.nlinks)
            <> " links)",
          )
        simplifile.File -> Ok(Some(information))
        simplifile.Symlink ->
          Error("destination became a symbolic link: " <> path)
        simplifile.Directory | simplifile.Other ->
          Error("destination is not a regular file: " <> path)
      }
  }
}

fn verify_destination(
  path: String,
  original: Option(simplifile.FileInfo),
) -> Result(Nil, String) {
  use current <- result.try(snapshot(path))
  case original, current {
    None, None -> Ok(Nil)
    Some(before), Some(after)
      if before.dev == after.dev
      && before.inode == after.inode
      && before.size == after.size
      && before.mode == after.mode
      && before.mtime_seconds == after.mtime_seconds
      && before.ctime_seconds == after.ctime_seconds
    -> Ok(Nil)
    None, Some(_) | Some(_), None | Some(_), Some(_) ->
      Error("destination changed while staging replacement: " <> path)
  }
}

fn preserve_permissions(
  temporary_path: String,
  original: Option(simplifile.FileInfo),
) -> Result(Nil, String) {
  case original {
    None -> Ok(Nil)
    Some(information) ->
      simplifile.set_permissions_octal(
        temporary_path,
        int.bitwise_and(information.mode, 0o7777),
      )
      |> operation("preserve permissions on " <> temporary_path)
  }
}

fn reserve_directory(parent: String, attempt: Int) -> Result(String, String) {
  case attempt >= 128 {
    True -> Error("could not reserve a temporary directory in " <> parent)
    False -> {
      let path = parent <> "/.glint-markdown-" <> int.to_string(attempt)
      case simplifile.create_directory(path) {
        Ok(_) -> Ok(path)
        Error(simplifile.Eexist) -> reserve_directory(parent, attempt + 1)
        Error(reason) ->
          Error(
            "reserve temporary directory "
            <> path
            <> ": "
            <> simplifile.describe_error(reason),
          )
      }
    }
  }
}

fn operation(
  outcome: Result(Nil, simplifile.FileError),
  description: String,
) -> Result(Nil, String) {
  result.map_error(outcome, fn(reason) {
    description <> ": " <> simplifile.describe_error(reason)
  })
}
