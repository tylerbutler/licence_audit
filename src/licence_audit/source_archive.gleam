import gleam/bit_array
import gleam/bool
import gleam/list
import gleam/result
import gleam/string

pub type ArchiveError {
  InvalidArchive
  MissingContentsArchive
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

@external(erlang, "sbom_uuid_ffi", "sha256")
fn sha256(data: BitArray) -> BitArray

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

pub fn extract_hex_contents(
  data: BitArray,
) -> Result(List(ArchiveFile), ArchiveError) {
  use files <- result.try(extract_tar_raw(data))
  use contents <- result.try(find_file_bits(files, "contents.tar.gz"))
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

  Ok(sha256(data) |> bit_array.base16_encode |> string.uppercase)
}

fn files_to_archive_files(
  files: List(#(String, BitArray)),
) -> List(ArchiveFile) {
  list.map(files, fn(file) {
    let #(path, contents) = file
    ArchiveFile(path: path, contents: contents)
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
