import gleam/bit_array
import gleam/bool
import gleam/crypto
import gleam/list
import gleam/result
import gleam/string

pub type ArchiveError {
  InvalidArchive
  MissingContentsArchive
  MissingRootFile
  InvalidText(path: String)
}

pub type ArchiveFile {
  ArchiveFile(path: String, contents: BitArray)
}

@external(erlang, "source_archive_ffi", "extract_tar")
fn extract_tar_raw(
  data: BitArray,
) -> Result(List(#(String, BitArray)), ArchiveError)

@external(erlang, "source_archive_ffi", "extract_tar_gz")
fn extract_tar_gz_raw(
  data: BitArray,
) -> Result(List(#(String, BitArray)), ArchiveError)

@external(erlang, "source_archive_ffi", "extract_tar_selected")
fn extract_tar_selected_raw(
  data: BitArray,
  select: fn(List(String)) -> List(#(String, String)),
) -> Result(List(#(String, BitArray)), ArchiveError)

@external(erlang, "source_archive_ffi", "extract_tar_gz_selected")
fn extract_tar_gz_selected_raw(
  data: BitArray,
  select: fn(List(String)) -> List(#(String, String)),
) -> Result(List(#(String, BitArray)), ArchiveError)

@external(erlang, "source_archive_ffi", "extract_root_file_tar_gz")
pub fn extract_root_file_tar_gz(
  data: BitArray,
  filename: String,
) -> Result(BitArray, ArchiveError)

pub fn extract_tar(data: BitArray) -> Result(List(ArchiveFile), ArchiveError) {
  use files <- result.try(extract_tar_raw(data))
  Ok(files_to_archive_files(files))
}

pub fn extract_tar_gz(
  data: BitArray,
) -> Result(List(ArchiveFile), ArchiveError) {
  use files <- result.try(extract_tar_gz_raw(data))
  Ok(files_to_archive_files(files))
}

/// Select archive members from the full regular-file inventory before loading
/// their contents. Each selected pair contains the member and its output path.
pub fn extract_tar_gz_selected(
  data: BitArray,
  select: fn(List(String)) -> List(#(String, String)),
) -> Result(List(ArchiveFile), ArchiveError) {
  extract_tar_gz_selected_raw(data, select)
  |> result.map(files_to_archive_files)
}

/// Scope the full inventory before selecting files or inferring package roots.
pub fn package_paths(
  paths: List(String),
  directory: String,
) -> List(#(String, String)) {
  let normalized =
    list.map(paths, fn(path) {
      #(path, case string.starts_with(path, "./") {
        True -> string.drop_start(path, 2)
        False -> path
      })
    })
  let has_root = case normalized {
    [] -> False
    [#(_, first), ..] -> {
      let root = case string.split(first, "/") {
        [root, _, ..] -> root
        _ -> ""
      }
      root != ""
      && list.all(normalized, fn(pair) {
        string.starts_with(pair.1, root <> "/")
      })
    }
  }
  normalized
  |> list.filter_map(fn(pair) {
    let relative = case has_root {
      True -> pair.1 |> string.split("/") |> list.drop(1) |> string.join("/")
      False -> pair.1
    }
    case directory {
      "" -> Ok(#(pair.0, relative))
      _ ->
        case string.starts_with(relative, directory <> "/") {
          True ->
            Ok(#(
              pair.0,
              string.drop_start(relative, string.length(directory) + 1),
            ))
          False -> Error(Nil)
        }
    }
  })
}

pub fn extract_package_file_tar_gz(
  data: BitArray,
  directory: String,
  filename: String,
) -> Result(BitArray, ArchiveError) {
  use files <- result.try(
    extract_tar_gz_selected(data, fn(paths) {
      let matches =
        package_paths(paths, directory)
        |> list.filter(fn(pair) { pair.1 == filename })
      case matches {
        [match] -> [match]
        _ -> []
      }
    }),
  )
  case files {
    [file] -> Ok(file.contents)
    _ -> Error(MissingRootFile)
  }
}

pub fn extract_hex_contents_selected(
  data: BitArray,
  select: fn(List(String)) -> List(#(String, String)),
) -> Result(List(ArchiveFile), ArchiveError) {
  use files <- result.try(
    extract_tar_selected_raw(data, fn(paths) {
      paths
      |> list.filter(fn(path) { path == "contents.tar.gz" })
      |> list.map(fn(path) { #(path, path) })
    }),
  )
  use contents <- result.try(
    list.key_find(files, "contents.tar.gz")
    |> result.replace_error(MissingContentsArchive),
  )
  extract_tar_gz_selected(contents, select)
}

pub fn extract_hex_contents(
  data: BitArray,
) -> Result(List(ArchiveFile), ArchiveError) {
  use files <- result.try(extract_tar_raw(data))
  use contents <- result.try(
    list.key_find(files, "contents.tar.gz")
    |> result.replace_error(MissingContentsArchive),
  )
  extract_tar_gz(contents)
}

pub fn text_contents(file: ArchiveFile) -> Result(String, ArchiveError) {
  case bit_array.to_string(file.contents) {
    Ok(text) -> Ok(text)
    Error(_) -> Error(InvalidText(path: file.path))
  }
}

pub fn sha256_hex(data: BitArray) -> Result(String, ArchiveError) {
  use <- bool.guard(
    when: bit_array.bit_size(data) % 8 != 0,
    return: Error(InvalidArchive),
  )

  Ok(
    crypto.hash(crypto.Sha256, data)
    |> bit_array.base16_encode
    |> string.uppercase,
  )
}

fn files_to_archive_files(
  files: List(#(String, BitArray)),
) -> List(ArchiveFile) {
  list.map(files, fn(file) {
    let #(path, contents) = file
    ArchiveFile(path: path, contents: contents)
  })
}

pub fn describe_error(error: ArchiveError) -> String {
  case error {
    InvalidArchive -> "invalid archive"
    MissingContentsArchive -> "Hex tarball missing contents.tar.gz"
    MissingRootFile -> "archive missing root file"
    InvalidText(path) -> "archive file is not valid UTF-8: " <> path
  }
}
