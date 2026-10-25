import gleam/bit_array
import gleam/list
import gleam/string
import gleeunit/should
import licence_audit/notice
import licence_audit/source_archive
import simplifile

const fixture_dir = "test/fixtures/notices/archive_fixture"

@external(erlang, "source_archive_test_ffi", "with_tar_gz")
pub fn with_tar_gz(
  entries: List(#(String, BitArray)),
  check: fn(BitArray) -> a,
) -> a

@external(erlang, "source_archive_test_ffi", "large_binary")
fn large_binary() -> BitArray

@external(erlang, "source_archive_test_ffi", "with_inflation_count")
fn with_inflation_count(check: fn() -> a) -> #(a, Int)

@external(erlang, "source_archive_test_ffi", "gunzip")
fn gunzip(bytes: BitArray) -> BitArray

pub fn selected_extraction_omits_large_unrelated_member_test() {
  with_tar_gz(
    [
      #("repo/LICENSE", <<"Licence text":utf8>>),
      #("repo/assets/large.bin", large_binary()),
      #("repo/vendor/LICENSE", <<"Vendored licence":utf8>>),
    ],
    fn(bytes) {
      let #(extracted, inflations) =
        with_inflation_count(fn() {
          source_archive.extract_tar_gz_selected(
            bytes,
            notice.selected_notice_paths,
          )
        })
      should.equal(inflations, 1)
      let assert Ok(files) = extracted
      should.equal(files, [
        source_archive.ArchiveFile("LICENSE", <<"Licence text":utf8>>),
      ])
      should.equal(
        list.fold(files, 0, fn(total, file) {
          total + bit_array.byte_size(file.contents)
        }),
        12,
      )
    },
  )
}

pub fn selected_extraction_preserves_full_inventory_root_test() {
  with_tar_gz(
    [
      #("repo/README.md", <<"readme":utf8>>),
      #("repo/vendor/LICENSE", <<"licence":utf8>>),
    ],
    fn(bytes) {
      should.equal(
        source_archive.extract_tar_gz_selected(
          bytes,
          notice.selected_notice_paths,
        ),
        Ok([source_archive.ArchiveFile("vendor/LICENSE", <<"licence":utf8>>)]),
      )
    },
  )
}

pub fn selected_extraction_does_not_infer_root_from_selected_subset_test() {
  with_tar_gz(
    [
      #("README.md", <<"readme":utf8>>),
      #("vendor/LICENSE", <<"licence":utf8>>),
    ],
    fn(bytes) {
      should.equal(
        source_archive.extract_tar_gz_selected(
          bytes,
          notice.selected_notice_paths,
        ),
        Ok([source_archive.ArchiveFile("vendor/LICENSE", <<"licence":utf8>>)]),
      )
    },
  )
}

pub fn selected_extraction_handles_no_matches_test() {
  with_tar_gz([#("repo/README.md", <<"readme":utf8>>)], fn(bytes) {
    let #(extracted, inflations) =
      with_inflation_count(fn() {
        source_archive.extract_tar_gz_selected(
          bytes,
          notice.selected_notice_paths,
        )
      })
    should.equal(extracted, Ok([]))
    should.equal(inflations, 1)
  })
  should.equal(
    source_archive.extract_tar_gz_selected(
      <<1:size(1)>>,
      notice.selected_notice_paths,
    ),
    Error(source_archive.InvalidArchive),
  )
}

pub fn selected_extraction_accepts_uncompressed_tar_like_otp_test() {
  with_tar_gz([#("repo/LICENSE", <<"licence":utf8>>)], fn(bytes) {
    should.equal(
      source_archive.extract_tar_gz_selected(
        gunzip(bytes),
        notice.selected_notice_paths,
      ),
      source_archive.extract_tar_gz_selected(
        bytes,
        notice.selected_notice_paths,
      ),
    )
  })
}

pub fn selected_extraction_reports_invalid_gzip_test() {
  should.equal(
    source_archive.extract_tar_gz_selected(
      <<31, 139, 0>>,
      notice.selected_notice_paths,
    ),
    Error(source_archive.InvalidArchive),
  )
}

pub fn selected_extraction_preserves_unicode_names_test() {
  with_tar_gz(
    [
      #("repo/README.md", <<"readme":utf8>>),
      #("repo/LICENCE-\u{00F1}", <<"licence":utf8>>),
    ],
    fn(bytes) {
      should.equal(
        source_archive.extract_tar_gz_selected(
          bytes,
          notice.selected_notice_paths,
        ),
        Ok([source_archive.ArchiveFile("LICENCE-\u{00F1}", <<"licence":utf8>>)]),
      )
    },
  )
}

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

pub fn extract_root_file_tar_gz_reads_only_root_metadata_test() {
  let assert Ok(bits) =
    simplifile.read_bits("test/fixtures/sbom_metadata/git.tar.gz")
  let assert Ok(contents) =
    source_archive.extract_root_file_tar_gz(bits, "gleam.toml")
  let assert Ok(text) = bit_array.to_string(contents)

  assert string.contains(text, "Metadata from the locked Git archive")
  should.equal(
    source_archive.extract_root_file_tar_gz(bits, "missing.toml"),
    Error(source_archive.MissingRootFile),
  )
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
