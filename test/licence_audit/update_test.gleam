import gleam/option.{None, Some}
import gleam/string
import gleeunit/should
import licence_audit/hex
import licence_audit/picker
import licence_audit/progress
import licence_audit/update
import simplifile

const tmp_dir = "build/tmp/update_test"

const manifest_path = "test/fixtures/transitive_manifest.toml"

fn fresh_path(name: String) -> String {
  let _ = simplifile.create_directory_all(tmp_dir)
  let path = tmp_dir <> "/" <> name <> ".toml"
  let _ = simplifile.delete(path)
  path
}

fn reporter() -> progress.Reporter {
  progress.capturing(progress.Verbose, "update")
}

fn successful_fetcher(name: String) -> Result(hex.PackageMetadata, hex.Error) {
  case name {
    "app_a" -> Ok(hex.licences_only(["MIT"]))
    "lib_b" -> Ok(hex.licences_only(["Apache-2.0", "MIT"]))
    "lib_c" -> Ok(hex.licences_only(["BSD-3-Clause"]))
    _ -> Error(hex.NotFound)
  }
}

fn failing_fetcher(name: String) -> Result(hex.PackageMetadata, hex.Error) {
  case name {
    "lib_b" -> Error(hex.NetworkFailure("connection refused"))
    _ -> successful_fetcher(name)
  }
}

fn cancelling_pick(_title, _labels, _allow, _deny) {
  Error(picker.Cancelled)
}

fn not_interactive_pick(_title, _labels, _allow, _deny) {
  Error(picker.NotInteractive)
}

fn should_not_pick(_title, _labels, _allow, _deny) {
  panic as "picker should not be called"
}

fn selecting_pick(title, labels, allow, deny) {
  should.equal(title, "Allow which licences? (5 total, 2 new)")
  should.equal(labels, [
    "Apache-2.0",
    "BSD-3-Clause",
    "GPL-3.0",
    "MIT",
    "Zlib",
  ])
  should.equal(allow, ["Zlib", "Apache-2.0"])
  should.equal(deny, ["GPL-3.0"])
  Ok(picker.Selection(allow: ["Apache-2.0", "MIT"], deny: ["GPL-3.0"]))
}

fn selected_pick(_title, _labels, _allow, _deny) {
  Ok(picker.Selection(allow: ["MIT"], deny: ["BSD-3-Clause"]))
}

pub fn user_cancel_exits_130_without_writing_file_test() {
  let path = fresh_path("cancel")

  let #(result, _) =
    update.run_with_picker(
      manifest_path,
      ".",
      Some(path),
      True,
      True,
      None,
      successful_fetcher,
      cancelling_pick,
      reporter(),
    )

  should.equal(result.exit_code, 130)
  let assert True = string.contains(result.output, "Update cancelled")
  let assert Error(_) = simplifile.read(from: path)
}

pub fn not_interactive_exits_1_test() {
  let path = fresh_path("not_interactive")

  let #(result, _) =
    update.run_with_picker(
      manifest_path,
      ".",
      Some(path),
      True,
      True,
      None,
      successful_fetcher,
      not_interactive_pick,
      reporter(),
    )

  should.equal(result.exit_code, 1)
  let assert True =
    string.contains(result.output, "requires an interactive terminal")
}

pub fn fetch_failure_during_discovery_exits_2_without_picker_test() {
  let path = fresh_path("fetch_failure")

  let #(result, _) =
    update.run_with_picker(
      manifest_path,
      ".",
      Some(path),
      True,
      True,
      None,
      failing_fetcher,
      should_not_pick,
      reporter(),
    )

  should.equal(result.exit_code, 2)
  let assert True = string.contains(result.output, "failed to fetch metadata")
  let assert Error(_) = simplifile.read(from: path)
}

pub fn manifest_load_failure_exits_2_without_picker_test() {
  let path = fresh_path("manifest_failure")

  let #(result, _) =
    update.run_with_picker(
      "test/fixtures/missing_manifest.toml",
      ".",
      Some(path),
      True,
      True,
      None,
      successful_fetcher,
      should_not_pick,
      reporter(),
    )

  should.equal(result.exit_code, 2)
  let assert True = string.contains(result.output, "Error:")
  let assert Error(_) = simplifile.read(from: path)
}

pub fn successful_write_persists_selection_and_passes_merged_labels_to_picker_test() {
  let path = fresh_path("success")
  let _ =
    simplifile.write(
      to: path,
      contents: "[tools.licence_audit]\nallow = [\"Zlib\", \"Apache-2.0\"]\ndeny = [\"GPL-3.0\"]\n",
    )

  let #(result, _) =
    update.run_with_picker(
      manifest_path,
      ".",
      Some(path),
      False,
      True,
      None,
      successful_fetcher,
      selecting_pick,
      reporter(),
    )
  let assert Ok(contents) = simplifile.read(from: path)

  should.equal(result.exit_code, 0)
  let assert True = string.contains(contents, "[tools.licence_audit]")
  let assert True =
    string.contains(contents, "allow = [\"Apache-2.0\", \"MIT\"]")
  let assert True = string.contains(contents, "deny = [\"GPL-3.0\"]")
  let assert True = string.contains(result.output, "(2 allowed, 1 denied)")
  let _ = simplifile.delete(path)
}

pub fn write_failure_exits_1_test() {
  let _ = simplifile.create_directory_all(tmp_dir)
  let blocker = tmp_dir <> "/blocker.file"
  let _ = simplifile.delete(blocker)
  let _ = simplifile.write("data", to: blocker)
  let target = blocker <> "/gleam.toml"

  let #(result, _) =
    update.run_with_picker(
      manifest_path,
      ".",
      Some(target),
      True,
      True,
      None,
      successful_fetcher,
      selected_pick,
      reporter(),
    )

  should.equal(result.exit_code, 1)
  let assert True = string.contains(result.output, "Failed to write")
  let _ = simplifile.delete(blocker)
}
