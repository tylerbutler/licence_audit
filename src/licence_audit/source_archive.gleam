import gleam/bit_array
import gleam/list
import gleam/result
import gleam/string

pub type ArchiveError {
  InvalidArchive
  MissingContentsArchive
  InvalidText(path: String)
}

pub type ArchiveFile {
  ArchiveFile(path: String, contents: String)
}

@external(erlang, "source_archive_ffi", "extract_tar")
fn extract_tar_raw(
  data: BitArray,
) -> Result(List(#(String, BitArray)), ArchiveError)

@external(erlang, "source_archive_ffi", "extract_tar_gz")
fn extract_tar_gz_raw(
  data: BitArray,
) -> Result(List(#(String, BitArray)), ArchiveError)

@external(erlang, "sbom_uuid_ffi", "sha256")
fn sha256(data: BitArray) -> BitArray

pub fn extract_tar(data: BitArray) -> Result(List(ArchiveFile), ArchiveError) {
  use files <- result.try(extract_tar_raw(data))
  files_to_text(files)
}

pub fn extract_tar_gz(
  data: BitArray,
) -> Result(List(ArchiveFile), ArchiveError) {
  use files <- result.try(extract_tar_gz_raw(data))
  files_to_text(files)
}

pub fn extract_hex_contents(
  data: BitArray,
) -> Result(List(ArchiveFile), ArchiveError) {
  use files <- result.try(extract_tar_raw(data))
  use contents <- result.try(find_file_bits(files, "contents.tar.gz"))
  extract_tar_gz(contents)
}

pub fn sha256_hex(data: BitArray) -> String {
  sha256(data)
  |> bit_array.base16_encode
  |> string.uppercase
}

fn files_to_text(
  files: List(#(String, BitArray)),
) -> Result(List(ArchiveFile), ArchiveError) {
  list.try_map(files, fn(file) {
    let #(path, contents) = file
    case bit_array.to_string(contents) {
      Ok(text) -> Ok(ArchiveFile(path: path, contents: text))
      Error(_) -> Error(InvalidText(path: path))
    }
  })
}

fn find_file_bits(
  files: List(#(String, BitArray)),
  wanted: String,
) -> Result(BitArray, ArchiveError) {
  case files {
    [] -> Error(MissingContentsArchive)
    [file, ..rest] -> {
      let #(path, contents) = file
      case path == wanted {
        True -> Ok(contents)
        False -> find_file_bits(rest, wanted)
      }
    }
  }
}

pub fn describe_error(error: ArchiveError) -> String {
  case error {
    InvalidArchive -> "invalid archive"
    MissingContentsArchive -> "Hex tarball missing contents.tar.gz"
    InvalidText(path) -> "archive file is not valid UTF-8: " <> path
  }
}
