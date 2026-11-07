import gleam/bit_array
import gleam/list
import gleam/result
import gleam/string
import gleeunit/should
import licence_audit/notice
import licence_audit/source_archive
import simplifile

const fixture_dir = "test/fixtures/notices/archive_fixture"

pub fn with_beryl_archive(check: fn(BitArray) -> a) -> a {
  with_tar_gz(
    [
      #("beryl-abcdef/gleam.toml", <<
        "name = \"beryl\"\nversion = \"1.0.0\"\nlicences = [\"BSD-3-Clause\"]\ndescription = \"Repository root metadata\"\n":utf8,
      >>),
      #("beryl-abcdef/LICENSE", <<"Repository root licence":utf8>>),
      #("beryl-abcdef/packages/beryl_protocol/gleam.toml", <<
        "name = \"beryl_protocol\"\nversion = \"1.0.0\"\nlicences = [\"MIT\"]\ndescription = \"Selected protocol metadata\"\n":utf8,
      >>),
      #("beryl-abcdef/packages/beryl_protocol/LICENSE", <<
        "Protocol licence":utf8,
      >>),
      #("beryl-abcdef/packages/beryl_protocol/NOTICE", <<
        "Protocol attribution":utf8,
      >>),
      #("beryl-abcdef/packages/beryl_protocol/vendor/LICENSE", <<
        "Vendored licence":utf8,
      >>),
      #("beryl-abcdef/packages/beryl_sibling/gleam.toml", <<
        "name = \"beryl_sibling\"\nversion = \"1.0.0\"\nlicences = [\"Apache-2.0\"]\ndescription = \"Sibling package metadata\"\n":utf8,
      >>),
      #("beryl-abcdef/packages/beryl_sibling/LICENSE", <<
        "Sibling licence":utf8,
      >>),
      #("beryl-abcdef/packages/beryl_protocol_extra/LICENSE", <<
        "Prefix sibling licence":utf8,
      >>),
      #("beryl-abcdef/packages/notice_only/NOTICE", <<
        "Only package attribution":utf8,
      >>),
      #("beryl-abcdef/packages/nested_only/legal/LICENSE", <<
        "Nested package licence":utf8,
      >>),
      #("beryl-abcdef/packages/blank_root/LICENSE", <<" \t\n":utf8>>),
      #("beryl-abcdef/packages/blank_root/NOTICE", <<
        "Blank-root package attribution":utf8,
      >>),
      #("beryl-abcdef/packages/blank_root/legal/COPYING", <<
        "Nested copying text":utf8,
      >>),
    ],
    check,
  )
}

pub fn package_metadata_lookup_respects_subdirectory_test() {
  with_beryl_archive(fn(bytes) {
    let assert Ok(contents) =
      source_archive.extract_package_file_tar_gz(
        bytes,
        "packages/beryl_protocol",
        "gleam.toml",
      )
    let assert Ok(text) = bit_array.to_string(contents)
    assert string.contains(text, "Selected protocol metadata")
    should.equal(
      source_archive.extract_package_file_tar_gz(
        bytes,
        "packages/notice_only",
        "gleam.toml",
      ),
      Error(source_archive.MissingRootFile),
    )
    should.equal(
      source_archive.extract_package_file_tar_gz(
        bytes,
        "packages/beryl",
        "gleam.toml",
      ),
      Error(source_archive.MissingRootFile),
    )
  })
}

pub fn package_paths_preserve_package_relative_directories_test() {
  should.equal(
    source_archive.package_paths(
      ["./repo/packages/dep/legal/LICENSE", "./repo/packages/dep_extra/LICENSE"],
      "packages/dep",
    ),
    [#("./repo/packages/dep/legal/LICENSE", "legal/LICENSE")],
  )
  should.equal(
    source_archive.package_paths(
      ["README.md", "packages/dep/LICENSE"],
      "packages/dep",
    ),
    [#("packages/dep/LICENSE", "LICENSE")],
  )
}

pub fn package_metadata_does_not_require_repository_root_metadata_test() {
  let metadata = <<"name = \"beryl_protocol\"\nlicences = [\"MIT\"]\n":utf8>>
  with_tar_gz(
    [
      #("beryl-abcdef/README.md", <<"Monorepo readme":utf8>>),
      #("beryl-abcdef/packages/beryl_protocol/gleam.toml", metadata),
      #("beryl-abcdef/packages/beryl_sibling/LICENSE", <<
        "Sibling licence":utf8,
      >>),
    ],
    fn(bytes) {
      should.equal(
        source_archive.extract_package_file_tar_gz(
          bytes,
          "packages/beryl_protocol",
          "gleam.toml",
        ),
        Ok(metadata),
      )
    },
  )
}

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

@external(erlang, "source_archive_test_ffi", "gzip")
fn gzip(bytes: BitArray) -> BitArray

@external(erlang, "source_archive_test_ffi", "corrupt_crc")
fn corrupt_crc(bytes: BitArray) -> BitArray

@external(erlang, "source_archive_test_ffi", "incompressible_binary")
fn incompressible_binary() -> BitArray

@external(erlang, "source_archive_ffi", "extract_tar")
fn extract_tar_with_limit(
  bytes: BitArray,
  limit: Int,
) -> Result(List(#(String, BitArray)), source_archive.ArchiveError)

@external(erlang, "source_archive_ffi", "extract_tar_gz")
fn extract_tar_gz_with_limit(
  bytes: BitArray,
  limit: Int,
) -> Result(List(#(String, BitArray)), source_archive.ArchiveError)

@external(erlang, "source_archive_ffi", "extract_tar_selected")
fn extract_tar_selected_with_limit(
  bytes: BitArray,
  select: fn(List(String)) -> List(#(String, String)),
  limit: Int,
) -> Result(List(#(String, BitArray)), source_archive.ArchiveError)

@external(erlang, "source_archive_ffi", "extract_tar_gz_selected")
fn extract_tar_gz_selected_with_limit(
  bytes: BitArray,
  select: fn(List(String)) -> List(#(String, String)),
  limit: Int,
) -> Result(List(#(String, BitArray)), source_archive.ArchiveError)

@external(erlang, "source_archive_ffi", "extract_root_file_tar_gz")
fn extract_root_with_limit(
  bytes: BitArray,
  filename: String,
  limit: Int,
) -> Result(BitArray, source_archive.ArchiveError)

@external(erlang, "source_archive_ffi", "prepare_tar")
fn prepare_tar(
  bytes: BitArray,
  limit: Int,
) -> Result(BitArray, source_archive.ArchiveError)

@external(erlang, "source_archive_test_ffi", "with_inflate_stats")
fn with_inflate_stats(check: fn() -> a) -> #(a, Int, Int)

pub fn tar_preparation_enforces_exact_byte_limit_test() {
  list.each([63, 64, 65], fn(size) {
    let bytes = bit_array.from_string(string.repeat("x", size))
    let expected = case size > 64 {
      True -> Error(source_archive.InvalidArchive)
      False -> Ok(bytes)
    }
    should.equal(prepare_tar(bytes, 64), expected)
    should.equal(prepare_tar(gzip(bytes), 64), expected)
  })
}

pub fn gzip_bomb_stops_inflation_and_closes_resource_test() {
  let bytes = gzip(large_binary())
  let #(outcome, calls, closes) =
    with_inflate_stats(fn() { prepare_tar(bytes, 64) })
  should.equal(outcome, Error(source_archive.InvalidArchive))
  should.equal(calls, 1)
  should.equal(closes, 1)
}

pub fn concatenated_gzip_members_share_output_limit_test() {
  let first = bit_array.from_string(string.repeat("x", 63))
  let first_gzip = gzip(first)
  list.each([0, 1, 2], fn(extra) {
    let second = bit_array.from_string(string.repeat("y", extra))
    let gzip = bit_array.concat([first_gzip, gzip(second)])
    let expected = case extra > 1 {
      True -> Error(source_archive.InvalidArchive)
      False -> Ok(bit_array.concat([first, second]))
    }
    should.equal(prepare_tar(gzip, 64), expected)
  })
  let later = gzip(<<"second member":utf8>>)
  let assert Ok(truncated) =
    bit_array.slice(later, 0, bit_array.byte_size(later) - 1)
  list.each([corrupt_crc(later), truncated], fn(later) {
    let #(outcome, _, closes) =
      with_inflate_stats(fn() {
        prepare_tar(bit_array.concat([first_gzip, later]), 100)
      })
    should.equal(outcome, Error(source_archive.InvalidArchive))
    should.equal(closes, 1)
  })
}

pub fn concatenated_members_support_all_tar_and_hex_paths_test() {
  with_tar_gz(
    [
      #("gleam.toml", <<"metadata":utf8>>),
      #("LICENSE", <<"licence":utf8>>),
      #("assets/random.bin", incompressible_binary()),
    ],
    fn(bytes) {
      let plain = gunzip(bytes)
      let size = bit_array.byte_size(plain)
      list.each([512, 16_384], fn(split) {
        let assert Ok(first) = bit_array.slice(plain, 0, split)
        let assert Ok(rest) = bit_array.slice(plain, split, size - split)
        let members = bit_array.concat([gzip(first), gzip(rest)])
        assert bit_array.byte_size(members) > 16_384
        should.equal(prepare_tar(members, size), Ok(plain))
        should.equal(
          prepare_tar(members, size - 1),
          Error(source_archive.InvalidArchive),
        )
        should.equal(
          source_archive.extract_tar_gz(members),
          source_archive.extract_tar(plain),
        )
        should.equal(
          source_archive.extract_tar_gz_selected(
            members,
            notice.selected_notice_paths,
          ),
          Ok([source_archive.ArchiveFile("LICENSE", <<"licence":utf8>>)]),
        )
        should.equal(
          source_archive.extract_root_file_tar_gz(members, "gleam.toml"),
          Ok(<<"metadata":utf8>>),
        )
        with_tar_gz([#("contents.tar.gz", members)], fn(outer) {
          should.equal(
            source_archive.extract_hex_contents(gunzip(outer)),
            source_archive.extract_tar(plain),
          )
          should.equal(
            source_archive.extract_hex_contents_selected(
              gunzip(outer),
              notice.selected_notice_paths,
            ),
            Ok([source_archive.ArchiveFile("LICENSE", <<"licence":utf8>>)]),
          )
        })
      })
    },
  )
}

pub fn corrupt_and_truncated_gzip_close_resource_test() {
  let bytes = gzip(<<"licence":utf8>>)
  let assert Ok(truncated) =
    bit_array.slice(bytes, 0, bit_array.byte_size(bytes) - 1)
  list.each([truncated, corrupt_crc(bytes), <<31, 139, 0>>], fn(bytes) {
    let #(outcome, _, closes) =
      with_inflate_stats(fn() { prepare_tar(bytes, 64) })
    should.equal(outcome, Error(source_archive.InvalidArchive))
    should.equal(closes, 1)
    should.equal(
      source_archive.extract_tar_gz(bytes),
      Error(source_archive.InvalidArchive),
    )
    should.equal(
      source_archive.extract_tar_gz_selected(
        bytes,
        notice.selected_notice_paths,
      ),
      Error(source_archive.InvalidArchive),
    )
    should.equal(
      source_archive.extract_root_file_tar_gz(bytes, "gleam.toml"),
      Error(source_archive.InvalidArchive),
    )
  })
}

pub fn extraction_limits_include_unselected_members_test() {
  should.equal(source_archive.max_decompressed_bytes, 268_435_456)
  with_tar_gz(
    [
      #("gleam.toml", <<"metadata":utf8>>),
      #("LICENSE", <<"licence":utf8>>),
      #(
        "assets/irrelevant.bin",
        bit_array.from_string(string.repeat("x", 32_768)),
      ),
    ],
    fn(bytes) {
      let plain = gunzip(bytes)
      let size = bit_array.byte_size(plain)
      list.each([size - 1, size, size + 1], fn(limit) {
        let expected = case limit < size {
          True -> Error(source_archive.InvalidArchive)
          False -> Ok([#("LICENSE", <<"licence":utf8>>)])
        }
        let expected_full = result.replace(expected, Nil)
        should.equal(
          extract_tar_with_limit(plain, limit) |> result.replace(Nil),
          expected_full,
        )
        should.equal(
          extract_tar_selected_with_limit(
            plain,
            notice.selected_notice_paths,
            limit,
          ),
          expected,
        )
        list.each([bytes, plain], fn(data) {
          should.equal(
            extract_tar_gz_selected_with_limit(
              data,
              notice.selected_notice_paths,
              limit,
            ),
            expected,
          )
          let expected_root = case limit < size {
            True -> Error(source_archive.InvalidArchive)
            False -> Ok(<<"metadata":utf8>>)
          }
          should.equal(
            extract_root_with_limit(data, "gleam.toml", limit),
            expected_root,
          )
          should.equal(
            extract_tar_gz_with_limit(data, limit) |> result.replace(Nil),
            expected_full,
          )
        })
      })
    },
  )
}

pub fn hex_outer_and_inner_tar_limits_test() {
  let assert Ok(outer) = simplifile.read_bits(fixture_dir <> "/hex.tar")
  let outer_size = bit_array.byte_size(outer)
  should.equal(
    extract_tar_with_limit(outer, outer_size - 1),
    Error(source_archive.InvalidArchive),
  )
  should.equal(
    extract_tar_selected_with_limit(
      outer,
      fn(_) { [#("contents.tar.gz", "contents.tar.gz")] },
      outer_size - 1,
    ),
    Error(source_archive.InvalidArchive),
  )
  let assert Ok(files) =
    extract_tar_selected_with_limit(
      outer,
      fn(_) { [#("contents.tar.gz", "contents.tar.gz")] },
      outer_size,
    )
  let assert Ok(contents) = list.key_find(files, "contents.tar.gz")
  let inner_size = bit_array.byte_size(gunzip(contents))
  should.equal(
    extract_tar_gz_with_limit(contents, inner_size - 1),
    Error(source_archive.InvalidArchive),
  )
  should.equal(
    extract_tar_gz_selected_with_limit(
      contents,
      notice.selected_notice_paths,
      inner_size - 1,
    ),
    Error(source_archive.InvalidArchive),
  )
  let assert Ok(_) =
    extract_tar_gz_selected_with_limit(
      contents,
      notice.selected_notice_paths,
      inner_size,
    )
}

pub fn all_archive_paths_share_checked_preparation_test() {
  with_tar_gz([#("gleam.toml", <<"name = \"fixture\"":utf8>>)], fn(bytes) {
    let plain = gunzip(bytes)
    let #(full, count) =
      with_inflation_count(fn() { source_archive.extract_tar_gz(bytes) })
    should.equal(count, 1)
    should.equal(full, source_archive.extract_tar(plain))
    let #(root, count) =
      with_inflation_count(fn() {
        source_archive.extract_root_file_tar_gz(bytes, "gleam.toml")
      })
    should.equal(count, 1)
    should.equal(root, Ok(<<"name = \"fixture\"":utf8>>))
    should.equal(
      source_archive.extract_root_file_tar_gz(plain, "gleam.toml"),
      root,
    )
  })
  let assert Ok(outer) = simplifile.read_bits(fixture_dir <> "/hex.tar")
  let #(full, count) =
    with_inflation_count(fn() { source_archive.extract_hex_contents(outer) })
  should.equal(count, 1)
  let assert Ok(_) = full
  let #(selected, count) =
    with_inflation_count(fn() {
      source_archive.extract_hex_contents_selected(
        outer,
        notice.selected_notice_paths,
      )
    })
  should.equal(count, 1)
  let assert Ok(_) = selected
}

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
