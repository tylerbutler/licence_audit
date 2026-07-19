import gleam/bit_array
import gleam/list
import gleam/string
import gleeunit/should
import licence_audit/source_archive
import simplifile

const fixture_dir = "test/fixtures/notices/archive_fixture"

pub fn sha256_hex_is_uppercase_test() {
  let assert Ok(bits) = simplifile.read_bits(fixture_dir <> "/hex.tar")

  let assert Ok(digest) = source_archive.sha256_hex(bits)

  should.equal(string.uppercase(digest), digest)
  should.equal(string.length(digest), 64)
}

pub fn sha256_hex_rejects_non_byte_aligned_bits_test() {
  should.equal(
    source_archive.sha256_hex(<<1:size(1)>>),
    Error(source_archive.InvalidArchive),
  )
}

pub fn text_contents_decodes_valid_utf8_test() {
  let file =
    source_archive.ArchiveFile(
      path: "./LICENSE",
      contents: bit_array.from_string("Fixture licence text\n"),
    )

  should.equal(source_archive.text_contents(file), Ok("Fixture licence text\n"))
}

pub fn text_contents_rejects_invalid_utf8_test() {
  let file = source_archive.ArchiveFile(path: "./image.bin", contents: <<255>>)

  should.equal(
    source_archive.text_contents(file),
    Error(source_archive.InvalidText("./image.bin")),
  )
}

pub fn extract_tar_gz_returns_text_files_test() {
  let assert Ok(bits) = simplifile.read_bits(fixture_dir <> "/contents.tar.gz")

  let assert Ok(files) = source_archive.extract_tar_gz(bits)

  let paths = list.map(files, fn(file) { file.path })
  assert list.contains(paths, "./LICENSE")
  assert list.contains(paths, "./NOTICE.txt")
  let assert [licence] =
    list.filter(files, fn(file) { file.path == "./LICENSE" })
  should.equal(
    source_archive.text_contents(licence),
    Ok("Fixture licence text\n"),
  )
}

pub fn extract_tar_gz_allows_binary_non_license_members_test() {
  let assert Ok(bits) =
    simplifile.read_bits(fixture_dir <> "/contents_with_binary.tar.gz")

  let assert Ok(files) = source_archive.extract_tar_gz(bits)

  let paths = list.map(files, fn(file) { file.path })
  assert list.contains(paths, "./LICENSE")
  assert list.contains(paths, "./image.bin")
  let assert [licence] =
    list.filter(files, fn(file) { file.path == "./LICENSE" })
  should.equal(
    source_archive.text_contents(licence),
    Ok("Fixture licence text\n"),
  )
}

pub fn extract_hex_contents_reads_inner_contents_tarball_test() {
  let assert Ok(bits) = simplifile.read_bits(fixture_dir <> "/hex.tar")

  let assert Ok(files) = source_archive.extract_hex_contents(bits)

  let paths = list.map(files, fn(file) { file.path })
  assert list.contains(paths, "./LICENSE")
  assert list.contains(paths, "./NOTICE.txt")
}

pub fn extract_tar_rejects_invalid_archive_test() {
  let result = source_archive.extract_tar(<<"not a tar":utf8>>)

  should.equal(result, Error(source_archive.InvalidArchive))
}

pub fn extract_tar_rejects_non_byte_aligned_bits_test() {
  let result = source_archive.extract_tar(<<1:size(1)>>)

  should.equal(result, Error(source_archive.InvalidArchive))
}

pub fn extract_tar_gz_rejects_non_byte_aligned_bits_test() {
  let result = source_archive.extract_tar_gz(<<1:size(1)>>)

  should.equal(result, Error(source_archive.InvalidArchive))
}
