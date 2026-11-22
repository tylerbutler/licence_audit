import gleam/list
import gleam/option.{None, Some}
import gleam/string
import gleeunit/should
import licence_audit/config
import licence_audit/notice
import licence_audit/picker
import licence_audit/policy
import licence_audit/progress
import licence_audit/source_archive_test
import licence_audit/update
import simplifile

const tmp_dir = "build/tmp/update_test"

const manifest_path = "test/fixtures/update_manifest.toml"

fn fresh_path(name: String) -> String {
  let _ = simplifile.create_directory_all(tmp_dir)
  let path = tmp_dir <> "/" <> name <> ".toml"
  let _ = simplifile.delete(path)
  path
}

fn reporter() -> progress.Reporter {
  progress.capturing(progress.Verbose, "update")
}

fn successful_fetcher() -> notice.Clients {
  notice.Clients(..notice.default_clients(), fetch_hex_tarball: fn(name, _) {
    Ok(
      source_archive_test.metadata_archive(case name {
        "app_a" -> ["MIT"]
        "lib_b" -> ["Apache-2.0", "MIT"]
        "lib_c" -> ["BSD-3-Clause"]
        _ -> panic as "unexpected package"
      }),
    )
  })
}

fn failing_fetcher() -> notice.Clients {
  notice.Clients(..successful_fetcher(), fetch_hex_tarball: fn(name, version) {
    case name {
      "lib_b" -> Error(notice.FetchNetworkFailure)
      _ -> successful_fetcher().fetch_hex_tarball(name, version)
    }
  })
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
      None,
      successful_fetcher(),
      cancelling_pick,
      reporter(),
    )

  should.equal(result.exit_code, 130)
  let assert True = string.contains(result.output, "Update cancelled")
  let assert Error(_) = simplifile.read(from: path)
}

pub fn not_interactive_exits_2_test() {
  let path = fresh_path("not_interactive")

  let #(result, _) =
    update.run_with_picker(
      manifest_path,
      ".",
      Some(path),
      True,
      None,
      successful_fetcher(),
      not_interactive_pick,
      reporter(),
    )

  should.equal(result.exit_code, 2)
  let assert True =
    string.contains(result.output, "requires an interactive terminal")
  let assert Error(_) = simplifile.read(path)
}

pub fn fetch_failure_during_discovery_exits_2_without_picker_test() {
  let path = fresh_path("fetch_failure")

  let #(result, rep) =
    update.run_with_picker(
      manifest_path,
      ".",
      Some(path),
      True,
      None,
      failing_fetcher(),
      should_not_pick,
      reporter(),
    )

  should.equal(result.exit_code, 2)
  let assert True = string.contains(result.output, "failed to fetch metadata")
  let assert Error(_) = simplifile.read(from: path)
  assert list.any(progress.events(rep), fn(event) {
    case event {
      progress.Event(progress.Failure, message) ->
        string.contains(message, "lib_b@")
        && string.contains(message, "network failure")
      _ -> False
    }
  })
}

pub fn manifest_load_failure_exits_2_without_picker_test() {
  let path = fresh_path("manifest_failure")

  let #(result, _) =
    update.run_with_picker(
      "test/fixtures/missing_manifest.toml",
      ".",
      Some(path),
      True,
      None,
      successful_fetcher(),
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

  let #(result, updated_reporter) =
    update.run_with_picker(
      manifest_path,
      ".",
      Some(path),
      True,
      None,
      successful_fetcher(),
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
  assert !list.any(progress.events(updated_reporter), fn(event) {
    event.kind == progress.Warning
  })
  let _ = simplifile.delete(path)
}

pub fn empty_allow_selection_is_saved_with_check_warning_test() {
  list.each([[], ["GPL-3.0-only"]], fn(deny) {
    let path = fresh_path("empty_allow")
    let #(result, updated_reporter) =
      update.run_with_picker(
        manifest_path,
        ".",
        Some(path),
        True,
        None,
        successful_fetcher(),
        fn(_, _, _, _) { Ok(picker.Selection(allow: [], deny: deny)) },
        reporter(),
      )
    should.equal(result.exit_code, 0)
    assert string.contains(result.output, "Wrote " <> path)
    let assert Ok(contents) = simplifile.read(path)
    let assert Ok(saved_policy) = config.parse(contents)
    should.equal(saved_policy.allow, [])
    should.equal(saved_policy.deny, deny)
    assert list.any(progress.events(updated_reporter), fn(event) {
      event.kind == progress.Warning
      && string.contains(event.message, "empty allow list")
      && string.contains(event.message, "check --checks=all")
    })
    let assert Ok(_) = simplifile.delete(path)
  })
}

pub fn invalid_target_parent_fails_before_writing_test() {
  let _ = simplifile.create_directory_all(tmp_dir)
  let blocker = tmp_dir <> "/blocker.file"
  let _ = simplifile.delete(blocker)
  let assert Ok(_) = simplifile.write("data", to: blocker)
  list.each(["/gleam.toml", "/missing/gleam.toml"], fn(suffix) {
    let #(result, _) =
      update.run_with_picker(
        manifest_path,
        ".",
        Some(blocker <> suffix),
        True,
        None,
        notice.Clients(..successful_fetcher(), fetch_hex_tarball: fn(_, _) {
          panic as "invalid target must stop before fetching"
        }),
        should_not_pick,
        reporter(),
      )
    should.equal(result.exit_code, 2)
    assert string.contains(result.output, "Could not read")
    should.equal(simplifile.read(blocker), Ok("data"))
  })
  let assert Ok(_) = simplifile.delete(blocker)
}

pub fn malformed_toml_exits_2_before_picker_without_changing_file_test() {
  let path = fresh_path("toml_edit_failure")
  let original = "name = [\n"
  let assert Ok(_) = simplifile.write(to: path, contents: original)
  let #(result, _) =
    update.run_with_picker(
      manifest_path,
      ".",
      Some(path),
      True,
      None,
      successful_fetcher(),
      should_not_pick,
      reporter(),
    )

  should.equal(result.exit_code, 2)
  assert string.contains(result.output, "Invalid TOML")
  should.equal(simplifile.read(path), Ok(original))
  let assert Ok(_) = simplifile.delete(path)
}

pub fn file_write_failure_exits_2_test() {
  let parent = fresh_path("missing_parent")
  list.each(["/gleam.toml", "/missing/gleam.toml"], fn(suffix) {
    let path = parent <> suffix
    let #(result, _) =
      update.run_with_picker(
        manifest_path,
        ".",
        Some(path),
        True,
        None,
        successful_fetcher(),
        selected_pick,
        reporter(),
      )

    should.equal(result.exit_code, 2)
    assert string.contains(result.output, "Failed to write " <> path)
    let assert Error(_) = simplifile.read(path)
  })
}

pub fn update_preserves_unreadable_text_before_picker_test() {
  let path = fresh_path("unreadable")
  let original = <<255, 254>>
  let assert Ok(_) = simplifile.write_bits(to: path, bits: original)
  let #(result, _) =
    update.run_with_picker(
      manifest_path,
      ".",
      Some(path),
      True,
      None,
      successful_fetcher(),
      should_not_pick,
      reporter(),
    )
  should.equal(result.exit_code, 2)
  should.equal(simplifile.read_bits(path), Ok(original))
  let assert Ok(_) = simplifile.delete(path)
}

@external(erlang, "notice_test_ffi", "with_unreadable_file")
fn with_unreadable_file(path: String, check: fn() -> a) -> option.Option(a)

pub fn update_preserves_writable_file_without_read_permission_test() {
  let path = fresh_path("write_only")
  let original = "name = \"keep_me\"\nversion = \"1.0.0\"\n"
  let assert Ok(_) = simplifile.write(to: path, contents: original)
  let _ =
    with_unreadable_file(path, fn() {
      let #(result, _) =
        update.run_with_picker(
          manifest_path,
          ".",
          Some(path),
          True,
          None,
          successful_fetcher(),
          should_not_pick,
          reporter(),
        )
      should.equal(result.exit_code, 2)
    })
  should.equal(simplifile.read(path), Ok(original))
  let assert Ok(_) = simplifile.delete(path)
}

pub fn update_preserves_file_when_read_fails_after_selection_test() {
  let path = fresh_path("read_after_picker")
  let original = <<255, 254>>
  let assert Ok(_) =
    simplifile.write(
      to: path,
      contents: "name = \"keep_me\"\n[tools.licence_audit]\n",
    )
  let #(result, _) =
    update.run_with_picker(
      manifest_path,
      ".",
      Some(path),
      True,
      None,
      successful_fetcher(),
      fn(_title, _labels, _allow, _deny) {
        let assert Ok(_) = simplifile.write_bits(to: path, bits: original)
        Ok(picker.Selection(["MIT"], []))
      },
      reporter(),
    )
  should.equal(result.exit_code, 2)
  assert string.contains(result.output, "Failed to read")
  should.equal(simplifile.read_bits(path), Ok(original))
  let assert Ok(_) = simplifile.delete(path)
}

pub fn update_creates_missing_default_and_explicit_config_test() {
  list.each([None, Some(tmp_dir <> "/gleam.toml")], fn(config_path) {
    let path = fresh_path("gleam")
    let #(result, _) =
      update.run_with_picker(
        manifest_path,
        tmp_dir,
        config_path,
        True,
        None,
        successful_fetcher(),
        selected_pick,
        reporter(),
      )
    should.equal(result.exit_code, 0)
    let assert Ok(contents) = simplifile.read(path)
    let assert Ok(policy) = config.parse(contents)
    should.equal(policy.allow, ["MIT"])
    let assert Ok(_) = simplifile.delete(path)
  })
}

pub fn cancellation_preserves_existing_policy_test() {
  let path = fresh_path("cancel_existing")
  let original = "# Keep selection\n[tools.licence_audit]\nallow = [\"MIT\"]\n"
  let assert Ok(_) = simplifile.write(path, original)
  let #(result, _) =
    update.run_with_picker(
      manifest_path,
      ".",
      Some(path),
      True,
      None,
      successful_fetcher(),
      cancelling_pick,
      reporter(),
    )
  should.equal(result.exit_code, 130)
  should.equal(simplifile.read(path), Ok(original))
  should.equal(temporary_files(path), [])
  let assert Ok(_) = simplifile.delete(path)
}

pub fn update_creates_policy_section_in_default_and_explicit_targets_test() {
  list.each([None, Some(tmp_dir <> "/gleam.toml")], fn(config_path) {
    let path = tmp_dir <> "/gleam.toml"
    let _ = simplifile.create_directory_all(tmp_dir)
    let original =
      "# Project settings\nname = \"keep_me\" # project name\n[tools.other]\nenabled = true\n"
    let assert Ok(_) = simplifile.write(path, original)
    set_private_mode(path)
    let original_metadata = metadata(path)
    let #(result, _) =
      update.run_with_picker(
        manifest_path,
        tmp_dir,
        config_path,
        True,
        None,
        successful_fetcher(),
        fn(_title, _labels, allow, deny) {
          should.equal(allow, [])
          should.equal(deny, [])
          selected_pick("", [], allow, deny)
        },
        reporter(),
      )
    should.equal(result.exit_code, 0)
    let assert Ok(contents) = simplifile.read(path)
    assert string.contains(contents, original)
    let assert Ok(policy) = config.parse(contents)
    should.equal(policy.allow, ["MIT"])
    should.equal(policy.deny, ["BSD-3-Clause"])
    should.equal(metadata(path), original_metadata)
    should.equal(temporary_files(path), [])
    let assert Ok(_) = simplifile.delete(path)
  })
}

pub fn update_rejects_invalid_existing_policy_in_default_and_explicit_targets_test() {
  list.each([None, Some(tmp_dir <> "/gleam.toml")], fn(config_path) {
    list.each(
      [
        "name = [\n",
        "[tools.licence_audit]\nallow = true\n",
        "[tools.licence_audit]\nallow = [\"not a licence\"]\n",
        "[tools.licence_audit]\nvuln_severity = \"urgent\"\n",
        "[tools.licence_audit]\nexceptions = \"ignore\"\n",
        "[[tools.licence_audit.exceptions]]\nreason = \"Missing finding\"\n",
        "[tools.licence_audit.exceptions]\n",
        "[tools.licence_audit]\nunknown = true\n",
        "[tools]\nlicence_audit = false\n",
      ],
      fn(original) {
        let path = tmp_dir <> "/gleam.toml"
        let _ = simplifile.create_directory_all(tmp_dir)
        let assert Ok(_) = simplifile.write(path, original)
        set_private_mode(path)
        let original_metadata = metadata(path)
        let #(result, _) =
          update.run_with_picker(
            manifest_path,
            tmp_dir,
            config_path,
            True,
            None,
            notice.Clients(
              ..notice.default_clients(),
              fetch_hex_tarball: fn(_, _) {
                panic as "invalid policy must stop before fetching"
              },
            ),
            should_not_pick,
            reporter(),
          )
        should.equal(result.exit_code, 2)
        should.equal(simplifile.read(path), Ok(original))
        should.equal(metadata(path), original_metadata)
        should.equal(temporary_files(path), [])
        let assert Ok(_) = simplifile.delete(path)
      },
    )
  })
}

pub fn update_revalidates_policy_changed_during_selection_test() {
  let path = fresh_path("changed_policy")
  let assert Ok(_) =
    simplifile.write(path, "[tools.licence_audit]\nallow = [\"MIT\"]\n")
  let invalid = "[tools.licence_audit]\nexceptions = false\n"
  let #(result, _) =
    update.run_with_picker(
      manifest_path,
      ".",
      Some(path),
      True,
      None,
      successful_fetcher(),
      fn(_, _, _, _) {
        let assert Ok(_) = simplifile.write(path, invalid)
        Ok(picker.Selection(["MIT"], []))
      },
      reporter(),
    )
  should.equal(result.exit_code, 2)
  should.equal(simplifile.read(path), Ok(invalid))
  should.equal(temporary_files(path), [])
  let assert Ok(_) = simplifile.delete(path)
}

pub fn update_rejects_valid_concurrent_policy_edits_test() -> Nil {
  list.each(
    [
      "[tools.licence_audit]\nallow = [\"MIT\"]\ndeny = [\"MIT\"]\n",
      "[tools.licence_audit]\nallow = [\"ISC\"]\ndeny = []\n",
    ],
    fn(newer) {
      let path = fresh_path("concurrent_policy")
      let assert Ok(_) =
        simplifile.write(path, "[tools.licence_audit]\nallow = [\"MIT\"]\n")
      let #(result, _) =
        update.run_with_picker(
          manifest_path,
          ".",
          Some(path),
          True,
          None,
          successful_fetcher(),
          fn(_, labels, allow, deny) {
            let assert Ok(_) = simplifile.write(path, newer)
            picker.new_state("Policy", labels, allow, deny)
            |> picker.state_selection
            |> Ok
          },
          reporter(),
        )
      should.equal(result.exit_code, 2)
      assert string.contains(result.output, "changed")
      assert string.contains(result.output, "rerun")
      should.equal(simplifile.read(path), Ok(newer))
      should.equal(temporary_files(path), [])
      let assert Ok(_) = simplifile.delete(path)
    },
  )
}

pub fn update_preserves_concurrent_unrelated_edits_test() -> Nil {
  let path = fresh_path("concurrent_unrelated")
  let assert Ok(_) =
    simplifile.write(path, "[tools.licence_audit]\nallow = [\"MIT\"]\n")
  let newer =
    "# Added during selection\nname = \"new_name\"\n[tools.licence_audit]\nallow = [\"MIT\"]\nvuln_block_unknown = true\n"
  let #(result, _) =
    update.run_with_picker(
      manifest_path,
      ".",
      Some(path),
      True,
      None,
      successful_fetcher(),
      fn(_, _, _, _) {
        let assert Ok(_) = simplifile.write(path, newer)
        Ok(picker.Selection(["MIT", "ISC"], ["GPL-3.0-only"]))
      },
      reporter(),
    )
  should.equal(result.exit_code, 0)
  let assert Ok(contents) = simplifile.read(path)
  assert string.contains(
    contents,
    "# Added during selection\nname = \"new_name\"",
  )
  let assert Ok(saved) = config.parse(contents)
  should.equal(saved.allow, ["MIT", "ISC"])
  should.equal(saved.deny, ["GPL-3.0-only"])
  should.equal(saved.vuln_block_unknown, True)
  simplifile.delete(path) |> should.be_ok
}

pub fn update_merges_labels_with_policy_matching_tokens_test() -> Nil {
  let path = fresh_path("normalized_labels")
  let assert Ok(_) =
    simplifile.write(
      path,
      "[tools.licence_audit]\nallow = [\"mit\", \"ISC\", \"LicenseRef-Custom\", \"DocumentRef-A:LicenseRef-X\"]\ndeny = [\"mIt\", \"LicenseRef-custom\", \"DocumentRef-a:LicenseRef-X\"]\n",
    )
  let #(result, _) =
    update.run_with_picker(
      manifest_path,
      ".",
      Some(path),
      True,
      None,
      successful_fetcher(),
      fn(title, labels, allow, deny) {
        should.equal(title, "Allow which licences? (8 total, 2 new)")
        should.equal(labels, [
          "Apache-2.0", "BSD-3-Clause", "DocumentRef-A:LicenseRef-X",
          "DocumentRef-a:LicenseRef-X", "ISC", "LicenseRef-Custom",
          "LicenseRef-custom", "mit",
        ])
        picker.new_state("Policy", labels, allow, deny)
        |> picker.state_selection
        |> Ok
      },
      reporter(),
    )
  should.equal(result.exit_code, 0)
  let assert Ok(contents) = simplifile.read(path)
  let assert Ok(saved) = config.parse(contents)
  should.equal(saved.allow, [
    "mit", "ISC", "LicenseRef-Custom", "DocumentRef-A:LicenseRef-X",
  ])
  should.equal(saved.deny, [
    "mIt", "LicenseRef-custom", "DocumentRef-a:LicenseRef-X",
  ])
  simplifile.delete(path) |> should.be_ok
}

pub fn unchanged_update_preserves_overlapping_rules_and_unrelated_verdicts_test() -> Nil {
  let path = fresh_path("overlapping_rules")
  let original = "[tools.licence_audit]\nallow = [\"MIT\"]\ndeny = [\"mit\"]\n"
  let assert Ok(_) = simplifile.write(path, original)
  let #(result, _) =
    update.run_with_picker(
      manifest_path,
      ".",
      Some(path),
      True,
      None,
      successful_fetcher(),
      fn(_, labels, allow, deny) {
        picker.new_state("Policy", labels, allow, deny)
        |> picker.state_selection
        |> Ok
      },
      reporter(),
    )
  should.equal(result.exit_code, 0)
  let assert Ok(contents) = simplifile.read(path)
  let assert Ok(saved) = config.parse(contents)
  should.equal(saved.allow, ["MIT"])
  should.equal(saved.deny, ["mit"])
  let assert Ok(audit_policy) = policy.from_config(saved, check_mode: True)
  should.equal(policy.audit(audit_policy, ["MIT"]), policy.DeniedLicence("MIT"))
  should.equal(
    policy.audit(audit_policy, ["ISC"]),
    policy.UnallowedLicence("ISC"),
  )
  simplifile.delete(path) |> should.be_ok
}

pub fn update_preserves_reviewed_exceptions_and_comments_test() {
  let path = fresh_path("exceptions")
  let unrelated = "# Project settings\nname = \"keep_me\" # project name\n"
  let exceptions =
    "
# Review decisions must survive allow-list updates.
[[tools.licence_audit.exceptions]]
purl = \"pkg:hex/lib_b@2.0.0\"
finding = \"unallowed-licence\"
licence = \"Apache-2.0\"
reason = \"Reviewed for this release\" # reviewer note
expires = \"2099-12-31\"

[[tools.licence_audit.exceptions]]
purl = \"pkg:hex/lib_c@3.0.0\"
finding = \"advisory\"
advisory = \"CVE-2026-12345\"
reason = \"Reviewed affected code\"
"
  let assert Ok(_) =
    simplifile.write(
      to: path,
      contents: unrelated
        <> "[tools.licence_audit]\nallow = [\"MIT\"]\n"
        <> exceptions,
    )
  set_private_mode(path)
  let original_metadata = metadata(path)
  let #(result, _) =
    update.run_with_picker(
      manifest_path,
      ".",
      Some(path),
      True,
      None,
      successful_fetcher(),
      selected_pick,
      reporter(),
    )
  should.equal(result.exit_code, 0)
  let assert Ok(contents) = simplifile.read(path)
  assert string.contains(contents, unrelated)
  should.equal(metadata(path), original_metadata)
  should.equal(temporary_files(path), [])
  list.each(string.split(exceptions, "\n"), fn(line) {
    assert string.contains(contents, line)
  })
  let assert Ok(parsed) = config.parse(contents)
  let assert Ok(original) =
    config.parse("[tools.licence_audit]\n" <> exceptions)
  should.equal(parsed.exceptions, original.exceptions)
  let assert Ok(_) = simplifile.delete(path)
}

pub fn update_handles_commented_arrays_implicit_parents_and_inline_tables_test() {
  let cases = [
    #(
      "array_comments",
      "[tools.licence_audit]\nallow = [\n  \"MIT\", # needed by foo\n  \"Zlib\",\n]\n",
      "# needed by foo",
    ),
    #(
      "implicit_parent",
      "[[tools.licence_audit.exceptions]]\npurl = \"pkg:hex/lib_b@2.0.0\"\nfinding = \"unallowed-licence\"\nlicence = \"Apache-2.0\"\nreason = \"Reviewed\" # keep review\n",
      "# keep review",
    ),
    #(
      "inline_table",
      "[tools]\nlicence_audit = { allow = [\"MIT\"] } # keep policy\n",
      "# keep policy",
    ),
  ]
  list.each(cases, fn(test_case) {
    let #(name, original, comment) = test_case
    let path = fresh_path(name)
    let assert Ok(_) = simplifile.write(to: path, contents: original)
    let assert Ok(original_policy) = config.parse(original)
    let #(result, _) =
      update.run_with_picker(
        manifest_path,
        ".",
        Some(path),
        True,
        None,
        successful_fetcher(),
        selected_pick,
        reporter(),
      )
    should.equal(result.exit_code, 0)
    let assert Ok(contents) = simplifile.read(path)
    let assert Ok(policy) = config.parse(contents)
    should.equal(policy.allow, ["MIT"])
    should.equal(policy.deny, ["BSD-3-Clause"])
    should.equal(policy.exceptions, original_policy.exceptions)
    assert string.contains(contents, comment)
    let assert Ok(_) = simplifile.delete(path)
  })
}

@external(erlang, "update_test_ffi", "partial_write")
fn partial_write(path: String, interrupt: Bool) -> Result(Nil, Nil)

@external(erlang, "update_test_ffi", "replace_and_recreate_temporary")
fn replace_and_recreate_temporary(path: String) -> Result(Nil, Nil)

@external(erlang, "update_test_ffi", "failed_replacement")
fn failed_replacement(path: String) -> Result(Nil, Nil)

@external(erlang, "update_test_ffi", "set_private_mode")
fn set_private_mode(path: String) -> Nil

@external(erlang, "update_test_ffi", "metadata")
fn metadata(path: String) -> #(Int, Int, Int)

@external(erlang, "update_test_ffi", "temporary_files")
fn temporary_files(path: String) -> List(String)

@external(erlang, "update_test_ffi", "make_link")
fn make_link(target: String, link: String) -> Result(Nil, Nil)

@external(erlang, "update_test_ffi", "is_symlink")
fn is_symlink(path: String) -> Bool

pub fn update_preserves_symlink_and_replaces_its_target_test() {
  let target = fresh_path("link_target")
  let link = fresh_path("linked_policy")
  let assert Ok(_) =
    simplifile.write(
      to: target,
      contents: "# Keep this comment\n[tools.licence_audit]\n",
    )
  let assert Ok(_) = make_link("link_target.toml", link)
  assert is_symlink(link)
  should.equal(simplifile.read(link), simplifile.read(target))
  let #(result, _) =
    update.run_with_picker(
      manifest_path,
      ".",
      Some(link),
      True,
      None,
      successful_fetcher(),
      selected_pick,
      reporter(),
    )
  should.equal(result.exit_code, 0)
  let assert Ok(contents) = simplifile.read(target)
  assert string.contains(contents, "# Keep this comment")
  assert string.contains(contents, "allow = [\"MIT\"]")
  should.equal(simplifile.read(link), Ok(contents))
  assert is_symlink(link)
  let assert Ok(_) = simplifile.delete(target)
  should.equal(simplifile.read(link), Error(simplifile.Enoent))
  let assert Ok(_) = simplifile.delete(link)
}

pub fn update_preserves_original_after_partial_write_failure_or_interruption_test() {
  let path = fresh_path("partial_write")
  let original = "# Keep this file\nname = \"keep_me\"\n"
  let assert Ok(_) = simplifile.write(to: path, contents: original)
  set_private_mode(path)
  let original_metadata = metadata(path)
  list.each([False, True], fn(interrupt) {
    should.equal(partial_write(path, interrupt), Ok(Nil))
    should.equal(simplifile.read(path), Ok(original))
    should.equal(metadata(path), original_metadata)
    should.equal(temporary_files(path), [])
  })
  let assert Ok(_) = simplifile.delete(path)
}

pub fn update_leaves_recreated_temporary_path_after_successful_replacement_test() -> Nil {
  let path = fresh_path("recreated_temporary")
  let assert Ok(_) = simplifile.write(path, "original")
  should.equal(replace_and_recreate_temporary(path), Ok(Nil))
  should.equal(simplifile.read(path), Ok("complete replacement"))
  let assert [temporary] = temporary_files(path)
  should.equal(
    simplifile.read(temporary),
    Ok("another writer's temporary file"),
  )
  simplifile.delete(temporary) |> should.be_ok
  simplifile.delete(path) |> should.be_ok
}

pub fn update_cleans_temporary_after_failed_replacement_test() -> Nil {
  let path = fresh_path("failed_replacement")
  let assert Ok(_) = simplifile.write(path, "original")
  set_private_mode(path)
  let original_metadata = metadata(path)
  should.equal(failed_replacement(path), Ok(Nil))
  should.equal(simplifile.read(path), Ok("original"))
  should.equal(metadata(path), original_metadata)
  should.equal(temporary_files(path), [])
  simplifile.delete(path) |> should.be_ok
}

pub fn update_rejects_invalid_exceptions_before_picker_or_write_test() {
  let path = fresh_path("invalid_exceptions")
  let original =
    "[tools.licence_audit]\nallow = [\"MIT\"]\nexceptions = \"ignore\"\n"
  let assert Ok(_) = simplifile.write(to: path, contents: original)
  let #(result, _) =
    update.run_with_picker(
      manifest_path,
      ".",
      Some(path),
      True,
      None,
      successful_fetcher(),
      should_not_pick,
      reporter(),
    )
  should.equal(result.exit_code, 2)
  assert string.contains(result.output, "exceptions must be an array of tables")
  should.equal(simplifile.read(path), Ok(original))
  let assert Ok(_) = simplifile.delete(path)
}
