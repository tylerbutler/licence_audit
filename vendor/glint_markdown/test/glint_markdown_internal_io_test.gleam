//// Tests for the filesystem execution layer.
////
//// These run on both Erlang and JS targets — `simplifile` supports both, and
//// the tests stick to ordinary file IO under a scratch directory.

import gleam/bit_array
import gleam/list
import gleam/string
import gleeunit/should
import glint_markdown
import glint_markdown/internal/filesystem
import glint_markdown/internal/io
import glint_markdown/internal/plan.{InjectFile, WriteFile}
import simplifile

// Each test gets its own scratch directory under build/ (gitignored) so the
// repo working tree stays clean even if a teardown is missed.
const scratch_root = "build/_io_test_scratch"

fn fresh_directory(name: String) -> String {
  let directory = scratch_root <> "/" <> name
  case simplifile.delete(directory) {
    Ok(_) | Error(simplifile.Enoent) -> Nil
    Error(reason) -> Error(reason) |> should.equal(Ok(Nil))
  }
  let assert Ok(_) = simplifile.create_directory_all(directory)
  directory
}

fn teardown(directory: String) -> Nil {
  let assert Ok(_) = simplifile.delete(directory)
  Nil
}

pub fn execute_write_file_creates_file_test() -> Nil {
  let directory = fresh_directory("write_creates")
  let path = directory <> "/nested/REF.md"

  let assert Ok(summary) = io.execute([WriteFile(path, "hello")], False, True)

  summary.written |> should.equal(1)
  summary.injected |> should.equal(0)
  summary.unchanged |> should.equal(0)

  let assert Ok(contents) = simplifile.read(path)
  contents |> should.equal("hello")

  teardown(directory)
}

pub fn execute_write_file_unchanged_when_identical_test() -> Nil {
  let directory = fresh_directory("write_unchanged")
  let path = directory <> "/REF.md"
  let assert Ok(_) = simplifile.write(to: path, contents: "same")

  let assert Ok(summary) = io.execute([WriteFile(path, "same")], False, True)

  summary.written |> should.equal(0)
  summary.unchanged |> should.equal(1)

  teardown(directory)
}

pub fn execute_inject_file_replaces_block_test() -> Nil {
  let directory = fresh_directory("inject_replace")
  let path = directory <> "/README.md"
  let original =
    "# title\n<!-- commands -->\nOLD BODY\n<!-- commandsstop -->\nfooter\n"
  let assert Ok(_) = simplifile.write(to: path, contents: original)

  let assert Ok(summary) =
    io.execute([InjectFile(path, "commands", "NEW BODY")], False, True)

  summary.injected |> should.equal(1)

  let assert Ok(updated) = simplifile.read(path)
  updated |> string.contains("NEW BODY") |> should.be_true
  updated |> string.contains("OLD BODY") |> should.be_false

  teardown(directory)
}

pub fn execute_inject_file_returns_error_when_marker_missing_test() -> Nil {
  let directory = fresh_directory("inject_missing")
  let path = directory <> "/README.md"
  let assert Ok(_) =
    simplifile.write(to: path, contents: "# title\nno sentinels here\n")

  let result = io.execute([InjectFile(path, "commands", "BODY")], False, True)

  let assert Error(errors) = result
  errors
  |> list.any(fn(message) { string.contains(message, "missing sentinel") })
  |> should.be_true

  teardown(directory)
}

pub fn execute_check_mode_detects_difference_test() -> Nil {
  let directory = fresh_directory("check_diff")
  let path = directory <> "/REF.md"
  let assert Ok(_) = simplifile.write(to: path, contents: "old")

  let result = io.execute([WriteFile(path, "new")], True, True)

  let assert Error(errors) = result
  errors
  |> list.any(fn(message) { string.contains(message, "would change") })
  |> should.be_true

  // Check mode must not actually write.
  let assert Ok(after) = simplifile.read(path)
  after |> should.equal("old")

  teardown(directory)
}

pub fn execute_check_mode_clean_when_identical_test() -> Nil {
  let directory = fresh_directory("check_clean")
  let path = directory <> "/REF.md"
  let assert Ok(_) = simplifile.write(to: path, contents: "same")

  let assert Ok(summary) = io.execute([WriteFile(path, "same")], True, True)

  summary.unchanged |> should.equal(1)
  summary.written |> should.equal(0)

  teardown(directory)
}

fn expect_failure(
  outcome: Result(io.Summary, List(String)),
  diagnostic: String,
) -> Nil {
  let assert Error(errors) = outcome
  errors
  |> list.any(fn(message) { string.contains(message, diagnostic) })
  |> should.be_true
}

fn expect_bytes(path: String, expected: BitArray) -> Nil {
  let assert Ok(actual) = simplifile.read_bits(path)
  actual |> should.equal(expected)
}

pub fn preflight_rejects_write_inject_aliases_before_any_write_test() -> Nil {
  let directory = fresh_directory("preflight_alias")
  let path = directory <> "/serve.md"
  let untouched = directory <> "/other.md"
  let original = "<!-- commands -->\nold\n<!-- commandsstop -->"
  let assert Ok(_) = simplifile.write(path, original)
  let assert Ok(_) = simplifile.write(untouched, "untouched")
  let assert Ok(absolute) = filesystem.canonical_path(path)
  let aliases = [
    "./" <> path,
    directory <> "/../preflight_alias/serve.md",
    absolute,
  ]
  list.each(aliases, fn(alias) {
    io.execute(
      [
        WriteFile(untouched, "must not be written"),
        WriteFile(path, "replacement"),
        InjectFile(alias, "commands", "new"),
      ],
      False,
      True,
    )
    |> expect_failure("conflicting file actions")
    expect_bytes(path, bit_array.from_string(original))
    expect_bytes(untouched, <<"untouched":utf8>>)
    io.execute(
      [InjectFile(alias, "commands", "new"), WriteFile(path, "replacement")],
      True,
      True,
    )
    |> expect_failure("conflicting file actions")
  })
  teardown(directory)
}

pub fn preflight_rejects_conflicting_duplicate_writes_test() -> Nil {
  let directory = fresh_directory("preflight_duplicate")
  let path = directory <> "/reference.md"
  let assert Ok(_) = simplifile.write(path, "original")
  io.execute(
    [WriteFile(path, "first"), WriteFile("./" <> path, "second")],
    False,
    True,
  )
  |> expect_failure("conflicting file actions")
  expect_bytes(path, <<"original":utf8>>)
  let assert Ok(summary) =
    io.execute(
      [WriteFile(path, "same"), WriteFile("./" <> path, "same")],
      False,
      True,
    )
  summary.written |> should.equal(1)
  summary.unchanged |> should.equal(1)
  teardown(directory)
}

pub fn multiple_injections_to_same_destination_are_allowed_test() -> Nil {
  let directory = fresh_directory("multiple_injections")
  let path = directory <> "/README.md"
  let assert Ok(_) =
    simplifile.write(
      path,
      "<!-- root -->\nold\n<!-- rootstop -->\n<!-- commands -->\nold\n<!-- commandsstop -->",
    )
  let assert Ok(summary) =
    io.execute(
      [
        InjectFile(path, "root", "new root"),
        InjectFile("./" <> path, "commands", "new commands"),
      ],
      False,
      True,
    )
  summary.injected |> should.equal(2)
  let assert Ok(contents) = simplifile.read(path)
  contents |> string.contains("new root") |> should.be_true
  contents |> string.contains("new commands") |> should.be_true
  teardown(directory)
}

pub fn preflight_rejects_symlink_and_hardlink_aliases_test() -> Nil {
  let directory = fresh_directory("preflight_links")
  let path = directory <> "/README.md"
  let symbolic = directory <> "/symbolic.md"
  let hard = directory <> "/hard.md"
  let assert Ok(_) = simplifile.write(path, "original")
  let assert Ok(_) = simplifile.create_symlink("README.md", symbolic)
  let assert Ok(_) = simplifile.create_link(path, hard)
  list.each([symbolic, hard], fn(alias) {
    io.execute(
      [WriteFile(path, "replacement"), InjectFile(alias, "commands", "body")],
      False,
      True,
    )
    |> expect_failure("conflicting file actions")
    io.execute(
      [WriteFile(alias, "first"), WriteFile(path, "second")],
      False,
      True,
    )
    |> expect_failure("conflicting file actions")
    expect_bytes(path, <<"original":utf8>>)
    expect_bytes(alias, <<"original":utf8>>)
  })
  teardown(directory)
}

pub fn preflight_resolves_missing_files_under_symbolic_parents_test() -> Nil {
  let directory = fresh_directory("preflight_parent_link")
  let assert Ok(_) = simplifile.create_directory(directory <> "/real")
  let assert Ok(_) = simplifile.create_directory(directory <> "/real/nested")
  let assert Ok(_) =
    simplifile.create_symlink("real/nested", directory <> "/alias")
  let destination = directory <> "/real/new.md"
  io.execute(
    [
      WriteFile(destination, "first"),
      InjectFile(directory <> "/alias/../new.md", "commands", "body"),
    ],
    False,
    True,
  )
  |> expect_failure("conflicting file actions")
  simplifile.read_bits(destination) |> should.equal(Error(simplifile.Enoent))
  teardown(directory)
}

pub fn full_file_write_and_check_compare_bom_bytes_test() -> Nil {
  let directory = fresh_directory("write_bom")
  let path = directory <> "/reference.md"
  let original = <<0xef, 0xbb, 0xbf, "same":utf8>>
  let assert Ok(_) = simplifile.write_bits(path, original)
  io.execute([WriteFile(path, "same")], True, True)
  |> expect_failure("7 -> 4 bytes")
  expect_bytes(path, original)
  let assert Ok(summary) = io.execute([WriteFile(path, "same")], False, True)
  summary.written |> should.equal(1)
  summary.unchanged |> should.equal(0)
  expect_bytes(path, <<"same":utf8>>)
  // A requested BOM is just as significant as an existing BOM.
  let with_bom = "\u{feff}same"
  io.execute([WriteFile(path, with_bom)], True, True)
  |> expect_failure("4 -> 7 bytes")
  let assert Ok(_) = io.execute([WriteFile(path, with_bom)], False, True)
  expect_bytes(path, original)
  let assert Ok(clean) = io.execute([WriteFile(path, with_bom)], True, True)
  clean.unchanged |> should.equal(1)
  teardown(directory)
}

pub fn injection_preserves_bom_and_skips_unchanged_bytes_test() -> Nil {
  let directory = fresh_directory("inject_bom")
  let path = directory <> "/README.md"
  let original =
    "\u{feff}# title\n<!-- commands -->\nold\n<!-- commandsstop -->\nfooter"
  let assert Ok(_) = simplifile.write(path, original)
  io.execute([InjectFile(path, "commands", "new")], True, True)
  |> expect_failure("would change")
  expect_bytes(path, bit_array.from_string(original))
  let assert Ok(summary) =
    io.execute([InjectFile(path, "commands", "new")], False, True)
  summary.injected |> should.equal(1)
  let expected = glint_markdown.inject(original, "commands", "new")
  expect_bytes(path, bit_array.from_string(expected))
  let assert Ok(before) = simplifile.file_info(path)
  let assert Ok(clean) =
    io.execute([InjectFile(path, "commands", "new")], True, True)
  clean.unchanged |> should.equal(1)
  let assert Ok(skipped) =
    io.execute([InjectFile(path, "commands", "new")], False, True)
  skipped.unchanged |> should.equal(1)
  let assert Ok(after) = simplifile.file_info(path)
  after.inode |> should.equal(before.inode)
  teardown(directory)
}

pub fn injection_preserves_leading_combining_mark_test() -> Nil {
  let directory = fresh_directory("inject_combining")
  let path = directory <> "/README.md"
  let original = "\u{301}<!-- commands -->\nold\n<!-- commandsstop -->"
  let assert Ok(_) = simplifile.write(path, original)
  let assert Ok(_) =
    io.execute([InjectFile(path, "commands", "new")], False, True)
  expect_bytes(
    path,
    bit_array.from_string(glint_markdown.inject(original, "commands", "new")),
  )
  teardown(directory)
}

pub fn injection_rejects_invalid_utf8_without_replacement_test() -> Nil {
  let directory = fresh_directory("inject_invalid")
  let path = directory <> "/README.md"
  let original = <<0xff, "<!-- commands -->":utf8>>
  let assert Ok(_) = simplifile.write_bits(path, original)
  list.each([True, False], fn(check) {
    io.execute([InjectFile(path, "commands", "new")], check, True)
    |> expect_failure("not UTF-8")
    expect_bytes(path, original)
  })
  teardown(directory)
}

pub fn replacement_preserves_permissions_and_uses_new_inode_test() -> Nil {
  let directory = fresh_directory("replace_permissions")
  let path = directory <> "/reference.md"
  let assert Ok(_) = simplifile.write(path, "original")
  let assert Ok(_) = simplifile.set_permissions_octal(path, 0o640)
  let assert Ok(before) = simplifile.file_info(path)
  let assert Ok(_) = io.execute([WriteFile(path, "replacement")], False, True)
  expect_bytes(path, <<"replacement":utf8>>)
  let assert Ok(after) = simplifile.file_info(path)
  simplifile.file_info_permissions_octal(after) |> should.equal(0o640)
  { after.inode != before.inode } |> should.be_true
  let assert Ok(entries) = simplifile.read_directory(directory)
  entries |> should.equal(["reference.md"])
  teardown(directory)
}

pub fn replacement_follows_symlinks_without_replacing_them_test() -> Nil {
  let directory = fresh_directory("replace_symlink")
  let path = directory <> "/README.md"
  let symbolic = directory <> "/symbolic.md"
  let assert Ok(_) = simplifile.write(path, "<!-- commands -->")
  let assert Ok(_) = simplifile.set_permissions_octal(path, 0o640)
  let assert Ok(_) = simplifile.create_symlink("README.md", symbolic)
  let assert Ok(link_before) = simplifile.link_info(symbolic)
  let assert Ok(_) =
    io.execute([InjectFile(symbolic, "commands", "new")], False, True)
  let assert Ok(_) =
    io.execute([WriteFile(symbolic, "replacement")], False, True)
  expect_bytes(path, <<"replacement":utf8>>)
  expect_bytes(symbolic, <<"replacement":utf8>>)
  let assert Ok(link_after) = simplifile.link_info(symbolic)
  simplifile.file_info_type(link_after) |> should.equal(simplifile.Symlink)
  link_after.inode |> should.equal(link_before.inode)
  let assert Ok(information) = simplifile.file_info(path)
  simplifile.file_info_permissions_octal(information) |> should.equal(0o640)
  // Like the old write API, a dangling symlink creates its referent.
  let dangling = directory <> "/dangling.md"
  let assert Ok(_) = simplifile.create_symlink("created.md", dangling)
  let assert Ok(_) = io.execute([WriteFile(dangling, "created")], False, True)
  expect_bytes(directory <> "/created.md", <<"created":utf8>>)
  let assert Ok(is_symbolic) = simplifile.is_symlink(dangling)
  is_symbolic |> should.be_true
  teardown(directory)
}

pub fn replacement_refuses_hardlinks_without_severing_them_test() -> Nil {
  let directory = fresh_directory("replace_hardlink")
  let path = directory <> "/README.md"
  let hard = directory <> "/hard.md"
  let original = "<!-- commands -->"
  let assert Ok(_) = simplifile.write(path, original)
  let assert Ok(_) = simplifile.create_link(path, hard)
  io.execute([WriteFile(path, "replacement")], False, True)
  |> expect_failure("hardlinked file")
  io.execute([InjectFile(hard, "commands", "new")], False, True)
  |> expect_failure("hardlinked file")
  expect_bytes(path, bit_array.from_string(original))
  expect_bytes(hard, bit_array.from_string(original))
  let assert Ok(information) = simplifile.file_info(path)
  information.nlinks |> should.equal(2)
  let assert Ok(unchanged) =
    io.execute([WriteFile(hard, original)], False, True)
  unchanged.unchanged |> should.equal(1)
  teardown(directory)
}

fn fail_after_partial_write(
  path: String,
  _contents: BitArray,
) -> Result(Nil, simplifile.FileError) {
  let assert Ok(_) = simplifile.write_bits(path, <<"partial":utf8>>)
  Error(simplifile.Eio)
}

pub fn failed_staging_preserves_original_and_cleans_temporary_file_test() -> Nil {
  let directory = fresh_directory("failed_staging")
  let path = directory <> "/reference.md"
  let original = <<0xef, 0xbb, 0xbf, "original":utf8>>
  let assert Ok(_) = simplifile.write_bits(path, original)
  let assert Ok(_) = simplifile.set_permissions_octal(path, 0o640)
  let assert Ok(resolved) = filesystem.canonical_path(path)
  let assert Ok(before) = simplifile.file_info(path)
  let assert Error(reason) =
    filesystem.replace_with(
      resolved,
      <<"replacement":utf8>>,
      fail_after_partial_write,
    )
  reason |> string.contains("write temporary file") |> should.be_true
  reason |> string.contains("Input/output error") |> should.be_true
  expect_bytes(path, original)
  let assert Ok(after) = simplifile.file_info(path)
  after.inode |> should.equal(before.inode)
  after.mode |> should.equal(before.mode)
  let assert Ok(entries) = simplifile.read_directory(directory)
  entries |> should.equal(["reference.md"])
  teardown(directory)
}

fn write_then_replace_staged_file_with_directory(
  path: String,
  contents: BitArray,
) -> Result(Nil, simplifile.FileError) {
  let assert Ok(_) = simplifile.write_bits(path, contents)
  // A directory can be chmodded, but cannot be renamed onto the original
  // regular file. This deterministically fails at rename, not permissions.
  let assert Ok(_) = simplifile.delete_file(path)
  simplifile.create_directory(path)
}

pub fn failed_rename_preserves_original_and_cleans_reservation_test() -> Nil {
  let directory = fresh_directory("failed_rename")
  let path = directory <> "/reference.md"
  let assert Ok(_) = simplifile.write(path, "original")
  let assert Ok(resolved) = filesystem.canonical_path(path)
  let assert Ok(before) = simplifile.file_info(path)
  let assert Error(reason) =
    filesystem.replace_with(
      resolved,
      <<"replacement":utf8>>,
      write_then_replace_staged_file_with_directory,
    )
  reason |> string.contains("rename ") |> should.be_true
  expect_bytes(path, <<"original":utf8>>)
  let assert Ok(after) = simplifile.file_info(path)
  after.inode |> should.equal(before.inode)
  let assert Ok(entries) = simplifile.read_directory(directory)
  entries |> should.equal(["reference.md"])
  teardown(directory)
}

pub fn preflight_reports_symlink_cycles_without_writing_earlier_actions_test() -> Nil {
  let directory = fresh_directory("preflight_cycle")
  let path = directory <> "/reference.md"
  let cyclic = directory <> "/cyclic.md"
  let assert Ok(_) = simplifile.write(path, "original")
  let assert Ok(_) = simplifile.create_symlink("cyclic.md", cyclic)
  io.execute(
    [WriteFile(path, "replacement"), WriteFile(cyclic, "unreachable")],
    False,
    True,
  )
  |> expect_failure("too many symbolic links")
  expect_bytes(path, <<"original":utf8>>)
  // Do not rely on simplifile's recursive deletion following a cyclic link.
  let assert Ok(_) = simplifile.delete_file(cyclic)
  teardown(directory)
}

pub fn stale_temporary_names_are_never_clobbered_or_cleaned_test() -> Nil {
  let directory = fresh_directory("stale_reservation")
  let stale = directory <> "/.glint-markdown-0"
  let assert Ok(_) = simplifile.create_directory(stale)
  let assert Ok(_) = simplifile.write(stale <> "/contents", "stale bytes")
  let path = directory <> "/reference.md"
  let assert Ok(_) = io.execute([WriteFile(path, "replacement")], False, True)
  expect_bytes(path, <<"replacement":utf8>>)
  expect_bytes(stale <> "/contents", <<"stale bytes":utf8>>)
  let assert Ok(entries) = simplifile.read_directory(directory)
  entries
  |> list.sort(string.compare)
  |> should.equal([".glint-markdown-0", "reference.md"])
  teardown(directory)
}
