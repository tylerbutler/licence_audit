//// Tests for the filesystem execution layer.
////
//// These run on both Erlang and JS targets — `simplifile` supports both, and
//// the tests stick to ordinary file IO under a scratch directory.

import gleam/list
import gleam/string
import gleeunit/should
import glint_markdown/internal/io
import glint_markdown/internal/plan.{InjectFile, WriteFile}
import simplifile

// Each test gets its own scratch directory under build/ (gitignored) so the
// repo working tree stays clean even if a teardown is missed.
const scratch_root = "build/_io_test_scratch"

fn fresh_dir(name: String) -> String {
  let dir = scratch_root <> "/" <> name
  let _ = simplifile.delete(dir)
  let assert Ok(_) = simplifile.create_directory_all(dir)
  dir
}

fn teardown(dir: String) -> Nil {
  let _ = simplifile.delete(dir)
  Nil
}

pub fn execute_write_file_creates_file_test() {
  let dir = fresh_dir("write_creates")
  let path = dir <> "/nested/REF.md"

  let assert Ok(summary) = io.execute([WriteFile(path, "hello")], False, True)

  summary.written |> should.equal(1)
  summary.injected |> should.equal(0)
  summary.unchanged |> should.equal(0)

  let assert Ok(contents) = simplifile.read(path)
  contents |> should.equal("hello")

  teardown(dir)
}

pub fn execute_write_file_unchanged_when_identical_test() {
  let dir = fresh_dir("write_unchanged")
  let path = dir <> "/REF.md"
  let assert Ok(_) = simplifile.write(to: path, contents: "same")

  let assert Ok(summary) = io.execute([WriteFile(path, "same")], False, True)

  summary.written |> should.equal(0)
  summary.unchanged |> should.equal(1)

  teardown(dir)
}

pub fn execute_inject_file_replaces_block_test() {
  let dir = fresh_dir("inject_replace")
  let path = dir <> "/README.md"
  let original =
    "# title\n<!-- commands -->\nOLD BODY\n<!-- commandsstop -->\nfooter\n"
  let assert Ok(_) = simplifile.write(to: path, contents: original)

  let assert Ok(summary) =
    io.execute([InjectFile(path, "commands", "NEW BODY")], False, True)

  summary.injected |> should.equal(1)

  let assert Ok(updated) = simplifile.read(path)
  updated |> string.contains("NEW BODY") |> should.be_true
  updated |> string.contains("OLD BODY") |> should.be_false

  teardown(dir)
}

pub fn execute_inject_file_returns_error_when_marker_missing_test() {
  let dir = fresh_dir("inject_missing")
  let path = dir <> "/README.md"
  let assert Ok(_) =
    simplifile.write(to: path, contents: "# title\nno sentinels here\n")

  let result = io.execute([InjectFile(path, "commands", "BODY")], False, True)

  let assert Error(errors) = result
  errors
  |> list.any(fn(msg) { string.contains(msg, "missing sentinel") })
  |> should.be_true

  teardown(dir)
}

pub fn execute_check_mode_detects_difference_test() {
  let dir = fresh_dir("check_diff")
  let path = dir <> "/REF.md"
  let assert Ok(_) = simplifile.write(to: path, contents: "old")

  let result = io.execute([WriteFile(path, "new")], True, True)

  let assert Error(errors) = result
  errors
  |> list.any(fn(msg) { string.contains(msg, "would change") })
  |> should.be_true

  // Check mode must not actually write.
  let assert Ok(after) = simplifile.read(path)
  after |> should.equal("old")

  teardown(dir)
}

pub fn execute_check_mode_clean_when_identical_test() {
  let dir = fresh_dir("check_clean")
  let path = dir <> "/REF.md"
  let assert Ok(_) = simplifile.write(to: path, contents: "same")

  let assert Ok(summary) = io.execute([WriteFile(path, "same")], True, True)

  summary.unchanged |> should.equal(1)
  summary.written |> should.equal(0)

  teardown(dir)
}
