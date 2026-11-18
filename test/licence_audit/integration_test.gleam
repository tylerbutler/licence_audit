import gleam/dynamic/decode
import gleam/http/response
import gleam/json
import gleam/list
import gleam/option.{None, Some}
import gleam/result
import gleam/string
import gleeunit/should
import licence_audit
import licence_audit/error as licence_audit_error
import licence_audit/gleam_toml
import licence_audit/hex
import licence_audit/manifest
import licence_audit/notice
import licence_audit/osv
import licence_audit/path_test
import licence_audit/picker
import licence_audit/progress
import licence_audit/repository
import licence_audit/sbom
import licence_audit/source_archive
import licence_audit/source_archive_test
import licence_audit/spdx
import licence_audit/test_policy
import licence_audit/toml
import licence_audit/update
import simplifile

@external(erlang, "integration_test_ffi", "record_detail_fetch")
fn record_detail_fetch(id: String) -> Int

@external(erlang, "integration_test_ffi", "reset_detail_fetch")
fn reset_detail_fetch(id: String) -> Nil

fn fake_fetcher(name: String) -> Result(hex.PackageMetadata, hex.Error) {
  case name {
    "gleam_stdlib" -> Ok(hex.licences_only(["MIT"]))
    "argv" -> Ok(hex.licences_only(["Apache-2.0"]))
    _ -> Error(hex.NotFound)
  }
}

fn test_clients(
  fetcher: fn(String) -> Result(hex.PackageMetadata, hex.Error),
) -> licence_audit.Clients {
  licence_audit.Clients(
    ..licence_audit.default_clients(),
    fetcher:,
    publication_fetcher: fn(_, _) { Ok(hex.Unpublished) },
    notice_clients: source_archive_test.metadata_clients(fetcher),
  )
}

pub fn help_and_version_do_not_call_clients_test() {
  let clients =
    licence_audit.Clients(
      fetcher: fn(_) { panic as "root must not fetch Hex metadata" },
      publication_fetcher: fn(_, _) {
        panic as "root must not verify publications"
      },
      osv_batch_fetcher: fn(_) { panic as "root must not query OSV" },
      osv_detail_fetcher: fn(_) { panic as "root must not fetch advisories" },
      notice_clients: source_archive_test.metadata_clients(fn(_) {
        panic as "help must not fetch locked sources"
      }),
    )
  use args <- list.each([
    ["--help"],
    ["-h"],
    ["--version"],
    ["report", "--help"],
    ["--help", "--manifest=missing-manifest.toml"],
    ["--version", "--config=missing-config.toml"],
  ])
  let #(result, events) =
    licence_audit.run_configured(args, clients, progress.disabled())
  should.equal(result.exit_code, 0)
  should.equal(events, [])
  assert !string.contains(result.output, "Starting licence audit")
}

pub fn default_and_named_report_preserve_output_errors_and_cache_bypass_test() {
  let args = [
    "--manifest=test/fixtures/manifest.toml",
    test_policy.flag([], ["MIT"]),
    "--cache-dir=build/default-report-unused-cache",
  ]
  use #(fetcher, expected_exit) <- list.each([
    #(fake_fetcher, 0),
    #(failing_fetcher, 2),
  ])
  let clients = test_clients(fetcher)
  let root = licence_audit.run_configured(args, clients, progress.disabled())
  let named =
    licence_audit.run_configured(
      ["report", ..args],
      clients,
      progress.disabled(),
    )
  should.equal(root, named)
  should.equal(root.0.exit_code, expected_exit)
  assert string.contains(root.0.output, "gleam_stdlib")
  assert string.contains(root.0.output, "MIT")
  let assert Error(_) =
    simplifile.read_directory("build/default-report-unused-cache")
}

pub fn removed_policy_flags_stop_before_loading_any_configuration_test() {
  let alternate = test_policy.flag(["Apache-2.0"], [])
  let invalid = "build/removed-policy-flags-invalid.toml"
  let assert Ok(_) = simplifile.write(invalid, "invalid = [")
  list.each([[], ["report"], ["check"]], fn(command) {
    use config <- list.each([
      [],
      [alternate],
      [alternate, "--ignore-config"],
      ["--config=missing.toml"],
      ["--config=missing.toml", "--ignore-config"],
      ["--config=" <> invalid],
      ["--config=" <> invalid, "--ignore-config"],
    ])
    use name <- list.each(["allow", "deny"])
    use flags <- list.each([
      ["--" <> name],
      ["--" <> name <> "="],
      ["--" <> name <> "=MIT"],
      ["--" <> name, "MIT"],
      ["--" <> name, ""],
    ])
    let #(result, events) =
      licence_audit.run_configured(
        list.append(list.append(command, config), flags),
        test_clients(fn(_) { panic as "invalid flags must not fetch metadata" }),
        progress.capturing(progress.Normal, "report"),
      )
    should.equal(result.exit_code, 2)
    assert string.contains(result.output, "invalid flag")
    assert string.contains(result.output, name)
    should.equal(events, [])
  })
  let assert Ok(_) = simplifile.delete(invalid)
}

pub fn vulnerability_flag_prerequisites_stop_before_fetching_test() {
  let clients =
    licence_audit.Clients(
      ..licence_audit.default_clients(),
      fetcher: fn(_) { panic as "invalid flags must stop before Hex fetch" },
      osv_batch_fetcher: fn(_) {
        panic as "invalid flags must stop before OSV batch fetch"
      },
      osv_detail_fetcher: fn(_) {
        panic as "invalid flags must stop before OSV detail fetch"
      },
    )
  use flags <- list.each([
    ["--vuln-severity=critical"],
    ["--vuln-block-unknown"],
    ["--vuln-block-unknown=false"],
    ["--vuln-severity=high", "--vuln-block-unknown"],
  ])
  let #(result, events) =
    licence_audit.run_configured(
      ["check", "--manifest=missing-manifest.toml", ..flags],
      clients,
      progress.disabled(),
    )
  should.equal(result.exit_code, 2)
  assert string.contains(
    result.output,
    "require --checks=vulns or --checks=all",
  )
  should.equal(events, [])
}

pub fn configured_vulnerability_defaults_without_scan_remain_valid_test() {
  let path = "build/vulnerability-prerequisite-config.toml"
  let assert Ok(_) =
    simplifile.write(
      path,
      "[tools.licence_audit]\nallow = [\"MIT\", \"Apache-2.0\"]\nvuln_severity = \"critical\"\nvuln_block_unknown = true\n",
    )
  let clients =
    licence_audit.Clients(
      ..test_clients(fake_fetcher),
      osv_batch_fetcher: fn(_) { panic as "config must not enable an OSV scan" },
      osv_detail_fetcher: fn(_) { panic as "config must not fetch advisories" },
    )
  let #(result, _) =
    licence_audit.run_configured(
      [
        "check",
        "--manifest=test/fixtures/manifest.toml",
        "--config=" <> path,
      ],
      clients,
      progress.disabled(),
    )
  let assert Ok(_) = simplifile.delete(path)
  should.equal(result.exit_code, 0)
}

fn failing_fetcher(name: String) -> Result(hex.PackageMetadata, hex.Error) {
  case name {
    "argv" -> Error(hex.NotFound)
    _ -> fake_fetcher(name)
  }
}

fn selection_project(name: String, configuration: String) -> String {
  let root = "build/check-selection-" <> name
  let assert Ok(_) = simplifile.create_directory_all(root)
  let assert Ok(contents) = simplifile.read("test/fixtures/manifest.toml")
  let assert Ok(_) = simplifile.write(root <> "/manifest.toml", contents)
  let assert Ok(_) =
    simplifile.write(
      root <> "/gleam.toml",
      "name = \"fixture\"\n" <> configuration,
    )
  root
}

pub fn selected_checks_do_not_depend_on_present_licence_policy_test() {
  use policy <- list.each(["", "allow = [\"MIT\"]\ndeny = [\"MIT\"]\n"])
  use selection <- list.each(["licences", "vulns", "all"])
  let root =
    selection_project("policy-boundary", case policy {
      "" -> ""
      _ -> "[tools.licence_audit]\n" <> policy
    })
  let clients =
    licence_audit.Clients(
      ..test_clients(fn(name) {
        assert selection != "vulns"
        fake_fetcher(name)
      }),
      fetcher: fn(_) { panic as "selected gates must not fetch API licences" },
      osv_batch_fetcher: fn(purls) {
        assert selection != "licences"
        one_vuln_batch(purls)
      },
      osv_detail_fetcher: one_vuln_detail,
    )
  let result =
    licence_audit.run_configured(
      [
        "check",
        "--checks=" <> selection,
        "--manifest=" <> root <> "/manifest.toml",
      ],
      clients,
      progress.disabled(),
    ).0
  case selection, policy {
    "licences", "" | "all", "" -> {
      should.equal(result.exit_code, 2)
      assert string.contains(result.output, "requires a non-empty allow list")
      assert string.contains(result.output, "--checks=licences")
      assert string.contains(result.output, "--checks=all")
    }
    _, _ -> {
      should.equal(result.exit_code, 1)
      should.equal(
        string.contains(result.output, "denied: MIT"),
        selection != "vulns",
      )
      should.equal(
        string.contains(result.output, "CVE-2024-0001"),
        selection != "licences",
      )
      should.equal(
        string.contains(result.output, "Package"),
        selection != "vulns",
      )
    }
  }
  let assert Ok(_) = simplifile.delete(root)
}

pub fn vulnerability_only_config_and_cli_thresholds_work_without_allow_test() {
  let clients =
    licence_audit.Clients(
      ..test_clients(fn(_) {
        panic as "vulnerability-only must not fetch licences"
      }),
      osv_batch_fetcher: one_vuln_batch,
      osv_detail_fetcher: one_vuln_detail,
    )
  use settings <- list.each([
    #("", [], 1),
    #("vuln_severity = \"critical\"\n", [], 0),
    #("", ["--vuln-severity=critical"], 0),
    #("vuln_severity = \"critical\"\n", ["--vuln-severity=high"], 1),
  ])
  let root = selection_project("thresholds", "")
  let config_path = root <> "/selected.toml"
  let assert Ok(_) =
    simplifile.write(config_path, case settings.0 {
      "" -> "name = \"no_policy\"\n"
      _ -> "[tools.licence_audit]\n" <> settings.0
    })
  let result =
    licence_audit.run_configured(
      list.append(
        [
          "check",
          "--checks=vulns",
          "--manifest=" <> root <> "/manifest.toml",
          "--config=" <> config_path,
        ],
        settings.1,
      ),
      clients,
      progress.disabled(),
    ).0
  should.equal(result.exit_code, settings.2)
  assert string.contains(result.output, "CVE-2024-0001")
  let assert Ok(_) = simplifile.delete(root)
}

pub fn selected_vulnerability_gates_resolve_unknown_blocking_precedence_test() {
  use selection <- list.each(["vulns", "all"])
  use #(setting, configured_exit) <- list.each([
    #("", 0),
    #("vuln_block_unknown = true\n", 1),
    #("vuln_block_unknown = false\n", 0),
  ])
  use #(flags, expected_exit) <- list.each([
    #([], configured_exit),
    #(["--vuln-block-unknown=true"], 1),
    #(["--vuln-block-unknown=false"], 0),
  ])
  let licence_policy = case selection {
    "vulns" -> "allow = [\"MIT\"]\ndeny = [\"MIT\"]\n"
    _ -> "allow = [\"MIT\", \"Apache-2.0\"]\n"
  }
  let root =
    selection_project(
      "unknown-precedence",
      "[tools.licence_audit]\n" <> licence_policy <> setting,
    )
  let result =
    licence_audit.run_configured(
      list.append(
        [
          "check",
          "--checks=" <> selection,
          "--manifest=" <> root <> "/manifest.toml",
        ],
        flags,
      ),
      licence_audit.Clients(
        ..test_clients(fn(name) {
          assert selection == "all"
          fake_fetcher(name)
        }),
        fetcher: fn(_) { panic as "gates must not fetch API licences" },
        osv_batch_fetcher: one_vuln_batch,
        osv_detail_fetcher: unknown_vuln_detail,
      ),
      progress.disabled(),
    ).0
  should.equal(result.exit_code, expected_exit)
  let marker = case expected_exit {
    1 -> "✗"
    _ -> "·"
  }
  assert string.contains(result.output, marker <> "  [UNKNOWN ]  CVE-2024-0001")
  should.equal(string.contains(result.output, "Package"), selection == "all")
  assert !string.contains(result.output, "denied: MIT")
  let assert Ok(_) = simplifile.delete(root)
}

pub fn unknown_override_preserves_selected_severity_threshold_test() {
  use selection <- list.each(["vulns", "all"])
  use #(flags, expected_exit, threshold) <- list.each([
    #([], 0, "critical"),
    #(["--vuln-severity=high"], 1, "high"),
  ])
  let root =
    selection_project(
      "severity-precedence",
      "[tools.licence_audit]\nallow = [\"MIT\", \"Apache-2.0\"]\nvuln_severity = \"critical\"\nvuln_block_unknown = true\n",
    )
  let result =
    licence_audit.run_configured(
      [
        "check",
        "--checks=" <> selection,
        "--manifest=" <> root <> "/manifest.toml",
        "--vuln-block-unknown=false",
        ..flags
      ],
      licence_audit.Clients(
        ..test_clients(fn(name) {
          assert selection == "all"
          fake_fetcher(name)
        }),
        osv_batch_fetcher: one_vuln_batch,
        osv_detail_fetcher: one_vuln_detail,
      ),
      progress.disabled(),
    ).0
  should.equal(result.exit_code, expected_exit)
  assert string.contains(result.output, "threshold: " <> threshold)
  assert !string.contains(result.output, "unknown: block")
  let assert Ok(_) = simplifile.delete(root)
}

pub fn vulnerability_only_validates_explicit_configuration_before_clients_test() {
  use input <- list.each([
    "invalid = [",
    "[tools.licence_audit]\nvuln_severity = \"invalid\"\n",
    "[tools.licence_audit]\nvuln_block_unknown = \"true\"\n",
    "[tools.licence_audit]\nunknown_setting = true\n",
    "[[tools.licence_audit.exceptions]]\npurl = \"invalid\"\n",
  ])
  let root = selection_project("invalid-config", "")
  let config_path = root <> "/invalid.toml"
  let assert Ok(_) = simplifile.write(config_path, input)
  let result =
    licence_audit.run_configured(
      [
        "check",
        "--checks=vulns",
        "--manifest=" <> root <> "/manifest.toml",
        "--config=" <> config_path,
        "--vuln-severity=high",
      ],
      licence_audit.Clients(
        ..test_clients(fn(_) { panic as "invalid config must stop Hex" }),
        osv_batch_fetcher: fn(_) { panic as "invalid config must stop OSV" },
        osv_detail_fetcher: unused_vuln_detail,
      ),
      progress.disabled(),
    ).0
  should.equal(result.exit_code, 2)
  assert string.contains(result.output, "Error:")
  let assert Ok(_) = simplifile.delete(root)
}

pub fn selected_vulnerability_gates_keep_incomplete_exit_priority_test() {
  use selection <- list.each(["vulns", "all"])
  use batch_failed <- list.each([False, True])
  let root =
    selection_project(
      "incomplete",
      "[tools.licence_audit]\nallow = [\"MIT\"]\ndeny = [\"MIT\"]\n",
    )
  let #(result, events) =
    licence_audit.run_configured(
      [
        "check",
        "--checks=" <> selection,
        "--manifest=" <> root <> "/manifest.toml",
      ],
      licence_audit.Clients(
        ..test_clients(fn(name) {
          assert selection == "all"
          fake_fetcher(name)
        }),
        fetcher: fn(_) { panic as "selected gates must not fetch API licences" },
        osv_batch_fetcher: fn(purls) {
          case batch_failed {
            True -> failing_osv_batch(purls)
            False -> one_vuln_batch(purls)
          }
        },
        osv_detail_fetcher: unused_vuln_detail,
      ),
      progress.capturing(progress.Normal, "check"),
    )
  should.equal(result.exit_code, 2)
  should.equal(
    string.contains(result.output, "denied: MIT"),
    selection == "all",
  )
  assert !string.contains(result.output, "Dependency licence audit failed")
  assert list.any(events, fn(event) { event.kind == progress.Error })
  let assert Ok(_) = simplifile.delete(root)
}

fn notice_metadata_fetcher(
  name: String,
) -> Result(hex.PackageMetadata, hex.Error) {
  case name {
    "gleam_stdlib" -> Ok(hex.licences_only(["Apache-2.0"]))
    "argv" -> Ok(hex.licences_only(["Apache-2.0"]))
    _ -> Ok(hex.licences_only([]))
  }
}

fn fixture_hex_tarball(
  _name: String,
  _version: String,
) -> Result(BitArray, notice.FetchError) {
  case simplifile.read_bits("test/fixtures/notices/archive_fixture/hex.tar") {
    Ok(bits) -> Ok(bits)
    Error(_) -> Error(notice.FetchNetworkFailure)
  }
}

fn unused_git_archive(
  _repo: repository.Repository,
  _commit: String,
) -> Result(BitArray, notice.FetchError) {
  Error(notice.FetchNetworkFailure)
}

fn notice_clients(
  fetch_hex_tarball: fn(String, String) -> Result(BitArray, notice.FetchError),
) -> notice.Clients {
  notice.Clients(
    fetch_hex_tarball:,
    fetch_git_archive: unused_git_archive,
    resolve_commit: fn(_repo, _tag) { Ok(None) },
    fetch_repo_archive: fn(_repo, _commit) { Error(notice.FetchNetworkFailure) },
    fetch_spdx_index: fn(_kind) { Error(notice.FetchNetworkFailure) },
    fetch_spdx: fn(_requirement) { Error(notice.FetchNetworkFailure) },
  )
}

fn notice_only_hex_tarball(
  _name: String,
  _version: String,
) -> Result(BitArray, notice.FetchError) {
  Ok(source_archive_test.notice_archive(["Apache-2.0"]))
}

/// Full client bundle whose Hex source ships only a NOTICE file, no repository
/// tag resolves, and every SPDX record returns synthesized canonical text.
fn spdx_fallback_clients() -> notice.Clients {
  notice.Clients(
    fetch_hex_tarball: notice_only_hex_tarball,
    fetch_git_archive: unused_git_archive,
    resolve_commit: fn(_repo, _tag) { Ok(None) },
    fetch_repo_archive: fn(_repo, _commit) { Error(notice.FetchNetworkFailure) },
    fetch_spdx_index: fn(kind) {
      case kind {
        spdx.LicenceIndex -> Ok(["Apache-2.0"])
        spdx.ExceptionIndex -> Ok([])
      }
    },
    fetch_spdx: fn(_requirement) {
      Ok(Some("SYNTHESIZED APACHE-2.0 CANONICAL TEXT"))
    },
  )
}

fn manifest_args(extra: List(String)) -> List(String) {
  let flags = case list.any(extra, string.starts_with(_, "--config=")) {
    True -> []
    False -> ["--ignore-config"]
  }
  let command = case list.contains(extra, "check") {
    True -> extra
    False -> ["report", ..extra]
  }
  list.append(command, ["--manifest=test/fixtures/manifest.toml", ..flags])
}

pub fn default_report_succeeds_without_policy_test() {
  let licence_audit.RunResult(exit_code, output) =
    licence_audit.run_configured(
      manifest_args([]),
      test_clients(fake_fetcher),
      progress.disabled(),
    ).0

  should.equal(exit_code, 0)
  assert string.contains(output, "Package")
  assert string.contains(output, "gleam_stdlib")
  assert string.contains(output, "MIT")
  assert string.contains(output, "argv")
  assert string.contains(output, "Apache-2.0")
  assert !string.contains(output, "Status")
}

pub fn licence_commands_require_checksum_but_standalone_vulns_does_not_test() {
  let path = "build/tmp/manifest-without-checksum.toml"
  let assert Ok(_) = simplifile.create_directory_all("build/tmp")
  let assert Ok(_) =
    simplifile.write(
      to: path,
      contents: "packages = [{ name = \"gleam_stdlib\", version = \"1.0.0\", source = \"hex\" }]\n",
    )

  [
    ["--ignore-config"],
    ["report", "--ignore-config"],
    ["check", test_policy.flag(["MIT"], [])],
    ["check", test_policy.flag(["MIT"], []), "--checks=all"],
    ["update"],
  ]
  |> list.each(fn(args) {
    let audit =
      licence_audit.run_configured(
        list.append(args, ["--manifest=" <> path]),
        test_clients(fake_fetcher),
        progress.disabled(),
      ).0
    should.equal(audit.exit_code, 2)
    assert string.contains(audit.output, "gleam_stdlib")
    assert string.contains(audit.output, "outer_checksum")
  })

  let sbom =
    licence_audit.run_configured(
      ["sbom", "--manifest=" <> path],
      test_clients(fake_fetcher),
      progress.disabled(),
    ).0
  should.equal(sbom.exit_code, 2)
  assert string.contains(
    sbom.output,
    "Invalid manifest package gleam_stdlib field outer_checksum: expected String",
  )

  [[], ["CVE-2024-0001"]]
  |> list.each(fn(ids) {
    [["vulns"], ["check", "--checks=vulns"]]
    |> list.each(fn(args) {
      let result =
        licence_audit.run_configured(
          list.append(args, ["--manifest=" <> path]),
          licence_audit.Clients(
            ..test_clients(fake_fetcher),
            osv_batch_fetcher: fn(purls) {
              should.equal(purls, ["pkg:hex/gleam_stdlib@1.0.0"])
              Ok(
                list.map(purls, fn(purl) {
                  osv.BatchEntry(purl: purl, vuln_ids: ids)
                }),
              )
            },
            osv_detail_fetcher: vulnerability_with_severity(osv.Low),
          ),
          progress.disabled(),
        ).0
      should.equal(result.exit_code, 0)
      case ids {
        [] -> {
          assert string.contains(
            result.output,
            "No known vulnerabilities reported by OSV.dev.",
          )
        }
        _ -> {
          assert string.contains(result.output, "CVE-2024-0001")
        }
      }
    })
  })
  let assert Ok(_) = simplifile.delete(path)
}

pub fn vulnerability_commands_reject_invalid_required_manifest_fields_test() {
  let path = "build/tmp/vulns-invalid-fields.toml"
  let assert Ok(_) = simplifile.create_directory_all("build/tmp")
  let clients =
    licence_audit.Clients(
      ..test_clients(fn(_) { panic as "invalid manifest must stop Hex fetch" }),
      osv_batch_fetcher: fn(_) {
        panic as "invalid manifest must stop OSV batch fetch"
      },
      osv_detail_fetcher: fn(_) {
        panic as "invalid manifest must stop OSV detail fetch"
      },
    )
  ["name", "version", "source"]
  |> list.each(fn(field) {
    ["", field <> " = 42,"]
    |> list.each(fn(invalid_field) {
      let valid_fields =
        [#("name", "gleam_stdlib"), #("version", "1.0.0"), #("source", "hex")]
        |> list.filter(fn(pair) { pair.0 != field })
        |> list.map(fn(pair) { pair.0 <> " = \"" <> pair.1 <> "\"" })
        |> string.join(", ")
      let assert Ok(_) =
        simplifile.write(
          to: path,
          contents: "packages = [{ " <> invalid_field <> valid_fields <> " }]",
        )
      [["vulns"], ["check", test_policy.flag(["MIT"], []), "--checks=all"]]
      |> list.each(fn(args) {
        let result =
          licence_audit.run_configured(
            list.append(args, ["--manifest=" <> path]),
            clients,
            progress.disabled(),
          ).0
        should.equal(result.exit_code, 2)
        assert string.contains(
          result.output,
          "field " <> field <> ": expected String",
        )
      })
    })
  })
  let assert Ok(_) = simplifile.delete(path)
}

pub fn notices_subcommand_prints_release_notice_text_test() {
  let assert Ok(bits) =
    simplifile.read_bits("test/fixtures/notices/archive_fixture/hex.tar")
  let assert Ok(fixture_checksum) = source_archive.sha256_hex(bits)
  let manifest_path = "build/tmp/notices-manifest.toml"
  let _ = simplifile.create_directory_all("build/tmp")
  let assert Ok(_) = simplifile.write(to: manifest_path, contents: "packages = [
  { name = \"gleam_stdlib\", version = \"1.0.0\", source = \"hex\", outer_checksum = \"" <> fixture_checksum <> "\" },
]

[requirements]
gleam_stdlib = { version = \">= 1.0.0\" }
")

  let result =
    licence_audit.run_configured(
      [
        "notices",
        "--manifest=" <> path_test.absolute_native_path(manifest_path),
      ],
      licence_audit.Clients(
        ..test_clients(notice_metadata_fetcher),
        notice_clients: notice_clients(fixture_hex_tarball),
      ),
      progress.disabled(),
    ).0

  should.equal(result.exit_code, 0)
  assert string.contains(result.output, "Third-party licences")
  assert string.contains(result.output, "gleam_stdlib 1.0.0")
  assert string.contains(result.output, "Declared licences: Apache-2.0")
  assert string.contains(result.output, "Fixture licence text")
}

fn missing_notices_manifest() -> String {
  let path = "build/tmp/notices-missing-manifest.toml"
  let assert Ok(_) = simplifile.create_directory_all("build/tmp")
  let bits = source_archive_test.notice_archive([])
  let assert Ok(checksum) = source_archive.sha256_hex(bits)
  let assert Ok(_) = simplifile.write(to: path, contents: "packages = [
  { name = \"first\", version = \"1.0.0\", source = \"hex\", outer_checksum = \"" <> checksum <> "\" },
  { name = \"second\", version = \"1.0.0\", source = \"hex\", outer_checksum = \"" <> checksum <> "\" },
]
[requirements]
first = \"1.0.0\"
second = \"1.0.0\"
")
  path
}

pub fn notices_aggregates_all_missing_packages_test() {
  let result =
    licence_audit.run_configured(
      ["notices", "--manifest=" <> missing_notices_manifest()],
      licence_audit.Clients(
        ..test_clients(fn(_name) { Ok(hex.licences_only([])) }),
        notice_clients: notice_clients(fn(_, _) {
          Ok(source_archive_test.notice_archive([]))
        }),
      ),
      progress.disabled(),
    ).0
  should.equal(result.exit_code, 2)
  assert string.contains(
    result.output,
    "Missing licence text for packages: first, second",
  )
  assert !string.contains(result.output, "Third-party licences")
}

pub fn notices_propagates_source_error_and_stops_resolution_test() {
  let result =
    licence_audit.run_configured(
      ["notices", "--manifest=" <> missing_notices_manifest()],
      licence_audit.Clients(
        ..test_clients(fn(_name) { Ok(hex.licences_only([])) }),
        notice_clients: notice_clients(fn(name, _version) {
          case name {
            "first" -> Error(notice.FetchNetworkFailure)
            _ -> panic as "source reads must stop at the first hard error"
          }
        }),
      ),
      progress.disabled(),
    ).0
  should.equal(result.exit_code, 2)
  assert string.contains(
    result.output,
    "Failed to fetch source archive for first: network failure",
  )
  assert !string.contains(result.output, "Missing licence text")
}

pub fn exceptions_do_not_change_sbom_or_notice_evidence_test() {
  let root = "build/tmp/exception-evidence"
  let assert Ok(_) = simplifile.create_directory_all(root)
  let assert Ok(bits) =
    simplifile.read_bits("test/fixtures/notices/archive_fixture/hex.tar")
  let assert Ok(checksum) = source_archive.sha256_hex(bits)
  let manifest_path = root <> "/manifest.toml"
  let assert Ok(_) =
    simplifile.write(
      to: manifest_path,
      contents: "packages = [{ name = \"gleam_stdlib\", version = \"1.0.0\", source = \"hex\", outer_checksum = \""
        <> checksum
        <> "\" }]\n[requirements]\ngleam_stdlib = \"1.0.0\"\n",
    )
  let project =
    "name = \"fixture\"\nversion = \"1.0.0\"\nlicences = [\"MIT\"]\n[dependencies]\ngleam_stdlib = \"1.0.0\"\n"
  let assert Ok(_) =
    simplifile.write(to: root <> "/gleam.toml", contents: project)
  let notice_args = ["notices", "--manifest=" <> manifest_path]
  let sbom_args = [
    "sbom",
    "--manifest=" <> manifest_path,
    "--reproducible",
  ]
  let original_notices =
    licence_audit.run_configured(
      notice_args,
      licence_audit.Clients(
        ..test_clients(notice_metadata_fetcher),
        notice_clients: notice_clients(fixture_hex_tarball),
      ),
      progress.disabled(),
    ).0
  let original_sbom =
    licence_audit.run_configured(
      sbom_args,
      licence_audit.Clients(
        ..test_clients(notice_metadata_fetcher),
        notice_clients: notice_clients(fixture_hex_tarball),
      ),
      progress.disabled(),
    ).0
  let assert Ok(_) =
    simplifile.write(to: root <> "/gleam.toml", contents: project <> "
[tools.licence_audit]
allow = [\"MIT\"]
[[tools.licence_audit.exceptions]]
purl = \"pkg:hex/gleam_stdlib@1.0.0\"
finding = \"unallowed-licence\"
licence = \"Apache-2.0\"
reason = \"Reviewed licence\"
[[tools.licence_audit.exceptions]]
purl = \"pkg:hex/gleam_stdlib@1.0.0\"
finding = \"advisory\"
advisory = \"CVE-2024-0001\"
reason = \"Reviewed advisory\"
")
  let notices =
    licence_audit.run_configured(
      notice_args,
      licence_audit.Clients(
        ..test_clients(notice_metadata_fetcher),
        notice_clients: notice_clients(fixture_hex_tarball),
      ),
      progress.disabled(),
    ).0
  let sbom =
    licence_audit.run_configured(
      sbom_args,
      licence_audit.Clients(
        ..test_clients(notice_metadata_fetcher),
        notice_clients: notice_clients(fixture_hex_tarball),
      ),
      progress.disabled(),
    ).0
  should.equal(original_notices.exit_code, 0)
  should.equal(original_sbom.exit_code, 0)
  should.equal(notices, original_notices)
  should.equal(sbom, original_sbom)
  assert string.contains(notices.output, "Fixture licence text")
}

pub fn notices_falls_back_to_spdx_when_source_lacks_licence_test() {
  let bits = source_archive_test.notice_archive(["Apache-2.0"])
  let assert Ok(fixture_checksum) = source_archive.sha256_hex(bits)
  let manifest_path = "build/tmp/notices-spdx-fallback-manifest.toml"
  let _ = simplifile.create_directory_all("build/tmp")
  let assert Ok(_) = simplifile.write(to: manifest_path, contents: "packages = [
  { name = \"gleam_stdlib\", version = \"1.0.0\", source = \"hex\", outer_checksum = \"" <> fixture_checksum <> "\" },
]

[requirements]
gleam_stdlib = { version = \">= 1.0.0\" }
")

  let result =
    licence_audit.run_configured(
      ["notices", "--manifest=" <> manifest_path],
      licence_audit.Clients(
        ..test_clients(notice_metadata_fetcher),
        notice_clients: spdx_fallback_clients(),
      ),
      progress.disabled(),
    ).0

  should.equal(result.exit_code, 0)
  // The source NOTICE is preserved and canonical SPDX text is synthesized.
  assert string.contains(result.output, "SPDX-License-List/Apache-2.0.txt")
  assert string.contains(result.output, "SYNTHESIZED APACHE-2.0 CANONICAL TEXT")
  assert string.contains(result.output, "NOTICE.txt")
}

fn notices_progress_manifest_path() -> String {
  let manifest_path = "build/tmp/notices-progress-manifest.toml"
  let assert Ok(bits) =
    simplifile.read_bits("test/fixtures/notices/archive_fixture/hex.tar")
  let assert Ok(fixture_checksum) = source_archive.sha256_hex(bits)
  let _ = simplifile.create_directory_all("build/tmp")
  let assert Ok(_) = simplifile.write(to: manifest_path, contents: "packages = [
  { name = \"gleam_stdlib\", version = \"1.0.0\", source = \"hex\", outer_checksum = \"" <> fixture_checksum <> "\" },
]

[requirements]
gleam_stdlib = { version = \">= 1.0.0\" }
")
  manifest_path
}

pub fn notices_verbose_progress_includes_package_details_test() {
  let manifest_path = notices_progress_manifest_path()
  let #(licence_audit.RunResult(exit_code, _output), events) =
    licence_audit.run_configured(
      ["notices", "--manifest=" <> manifest_path, "--verbose"],
      licence_audit.Clients(
        ..test_clients(notice_metadata_fetcher),
        notice_clients: notice_clients(fixture_hex_tarball),
      ),
      progress.capturing(progress.Verbose, "notices"),
    )

  should.equal(exit_code, 0)
  assert list.contains(
    events,
    progress.Event(progress.Detail, "Fetching gleam_stdlib@1.0.0 from Hex"),
  )
  assert list.any(events, fn(event) {
    case event {
      progress.Event(progress.Detail, message) ->
        string.contains(message, "licence file(s) for gleam_stdlib")
      _ -> False
    }
  })
}

pub fn notices_normal_progress_omits_package_details_test() {
  let manifest_path = notices_progress_manifest_path()
  let #(licence_audit.RunResult(exit_code, _output), events) =
    licence_audit.run_configured(
      ["notices", "--manifest=" <> manifest_path],
      licence_audit.Clients(
        ..test_clients(notice_metadata_fetcher),
        notice_clients: notice_clients(fixture_hex_tarball),
      ),
      progress.capturing(progress.Normal, "notices"),
    )

  should.equal(exit_code, 0)
  assert !list.any(events, fn(event) {
    case event {
      progress.Event(progress.Detail, _) -> True
      _ -> False
    }
  })
}

pub fn notices_subcommand_writes_output_file_test() {
  let assert Ok(bits) =
    simplifile.read_bits("test/fixtures/notices/archive_fixture/hex.tar")
  let assert Ok(fixture_checksum) = source_archive.sha256_hex(bits)
  let manifest_path = "build/tmp/notices-output-manifest.toml"
  let output_path = "build/tmp/THIRD_PARTY_LICENSES.txt"
  let _ = simplifile.create_directory_all("build/tmp")
  let _ = simplifile.delete(output_path)
  let assert Ok(_) = simplifile.write(to: manifest_path, contents: "packages = [
  { name = \"gleam_stdlib\", version = \"1.0.0\", source = \"hex\", outer_checksum = \"" <> fixture_checksum <> "\" },
]

[requirements]
gleam_stdlib = { version = \">= 1.0.0\" }
")

  let result =
    licence_audit.run_configured(
      [
        "notices",
        "--manifest=" <> manifest_path,
        "--output=" <> output_path,
      ],
      licence_audit.Clients(
        ..test_clients(notice_metadata_fetcher),
        notice_clients: notice_clients(fixture_hex_tarball),
      ),
      progress.disabled(),
    ).0
  let assert Ok(contents) = simplifile.read(from: output_path)

  should.equal(result.exit_code, 0)
  should.equal(result.output, "")
  assert string.contains(contents, "Fixture licence text")
}

pub fn notices_manifest_path_uses_manifest_project_for_scope_test() {
  let assert Ok(bits) =
    simplifile.read_bits("test/fixtures/notices/archive_fixture/hex.tar")
  let assert Ok(fixture_checksum) = source_archive.sha256_hex(bits)
  let project_root = "build/tmp/notices-scope-project"
  let manifest_path = project_root <> "/manifest.toml"
  let assert Ok(Nil) = simplifile.create_directory_all(project_root)
  let assert Ok(Nil) =
    simplifile.write(
      to: project_root <> "/gleam.toml",
      contents: "[dependencies]
prod_dep = \">= 1.0.0\"

[dev-dependencies]
dev_dep = \">= 1.0.0\"
",
    )
  let assert Ok(Nil) =
    simplifile.write(to: manifest_path, contents: "packages = [
  { name = \"prod_dep\", version = \"1.0.0\", source = \"hex\", outer_checksum = \"" <> fixture_checksum <> "\" },
  { name = \"dev_dep\", version = \"1.0.0\", source = \"hex\", outer_checksum = \"" <> fixture_checksum <> "\" },
]

[requirements]
prod_dep = { version = \">= 1.0.0\" }
dev_dep = { version = \">= 1.0.0\" }
")

  let result =
    licence_audit.run_configured(
      ["notices", "--manifest=" <> manifest_path],
      licence_audit.Clients(
        ..test_clients(notice_metadata_fetcher),
        notice_clients: notice_clients(fixture_hex_tarball),
      ),
      progress.disabled(),
    ).0

  should.equal(result.exit_code, 0)
  assert string.contains(result.output, "prod_dep 1.0.0")
  assert !string.contains(result.output, "dev_dep 1.0.0")
}

pub fn notices_path_dependencies_resolve_relative_to_manifest_project_test() {
  let project_root = "build/tmp/notices-path-project"
  let local_dep = project_root <> "/deps/local_dep"
  let manifest_path = project_root <> "/manifest.toml"
  let assert Ok(Nil) = simplifile.create_directory_all(local_dep)
  let assert Ok(Nil) =
    simplifile.write(
      to: local_dep <> "/LICENSE",
      contents: "Path licence text\n",
    )
  let assert Ok(Nil) =
    simplifile.write(
      to: project_root <> "/gleam.toml",
      contents: "[dependencies]
local_dep = { path = \"deps/local_dep\" }
",
    )
  let assert Ok(Nil) =
    simplifile.write(
      to: manifest_path,
      contents: "packages = [
  { name = \"local_dep\", version = \"0.1.0\", source = \"local\", path = \"deps/local_dep\" },
]

[requirements]
local_dep = { path = \"deps/local_dep\" }
",
    )

  let result =
    licence_audit.run_configured(
      [
        "notices",
        "--manifest=" <> path_test.absolute_native_path(manifest_path),
      ],
      licence_audit.Clients(
        ..test_clients(notice_metadata_fetcher),
        notice_clients: notice_clients(fixture_hex_tarball),
      ),
      progress.disabled(),
    ).0

  should.equal(result.exit_code, 0)
  assert string.contains(result.output, "local_dep 0.1.0")
  assert string.contains(result.output, "Path licence text")
}

pub fn run_with_source_clients_disables_disk_cache_for_audits_test() {
  let cache_path = "build/tmp/run-with-notice-clients-cache"
  let _ = simplifile.create_directory_all("build/tmp")
  let _ = simplifile.delete(cache_path)

  let result =
    licence_audit.run_configured(
      manifest_args(["--cache-dir=" <> cache_path]),
      licence_audit.Clients(
        ..test_clients(fake_fetcher),
        notice_clients: source_archive_test.metadata_clients(fake_fetcher),
      ),
      progress.disabled(),
    ).0

  should.equal(result.exit_code, 0)
  let assert Error(_) = simplifile.read_bits(cache_path)
}

pub fn embedded_cache_bypass_does_not_create_flag_conflicts_test() {
  let root =
    selection_project(
      "embedded-cache",
      "version = \"1.0.0\"\n[tools.licence_audit]\nallow = [\"MIT\"]\n",
    )
  let assert Ok(_) =
    simplifile.write(root <> "/manifest.toml", "packages = []\n")
  let cache_path = root <> "/unused-cache"
  let clients =
    test_clients(fn(_) { panic as "empty manifests need no clients" })
  use command <- list.each([
    [],
    ["report"],
    ["check"],
    ["update"],
    ["sbom"],
    ["notices"],
  ])
  use flags <- list.each([[], ["--no-cache=false"]])
  let result =
    licence_audit.run_configured(
      list.append(
        [
          "--manifest=" <> root <> "/manifest.toml",
          "--cache-dir=" <> cache_path,
          ..command
        ],
        flags,
      ),
      clients,
      progress.disabled(),
    ).0
  case command {
    ["update"] -> {
      should.equal(result.exit_code, 2)
      assert string.contains(result.output, "requires an interactive terminal")
    }
    _ -> should.equal(result.exit_code, 0)
  }
  let assert Error(_) = simplifile.read_directory(cache_path)
}

pub fn explicit_conflicts_stop_both_injected_runners_before_io_test() {
  use runner <- list.each([
    licence_audit.run_configured,
    licence_audit.run_cli_configured,
  ])
  use pair <- list.each([
    #(
      ["--config=missing.toml", "--ignore-config"],
      [[], ["report"], ["check"], ["notices"], ["vulns"]],
      "--config and --ignore-config",
    ),
    #(
      ["--no-cache", "--cache-dir=unused-cache"],
      [[], ["report"], ["check"], ["update"], ["sbom"], ["notices"]],
      "--no-cache and --cache-dir",
    ),
  ])
  use command <- list.each(pair.1)
  let #(result, events) =
    runner(
      list.append(command, ["--manifest=missing-manifest.toml", ..pair.0]),
      test_clients(fn(_) { panic as "invalid usage must not fetch" }),
      progress.capturing(progress.Normal, "report"),
    )
  should.equal(result.exit_code, 2)
  should.equal(
    result.output,
    "Error: " <> pair.2 <> " cannot be used together\n",
  )
  should.equal(events, [])
}

pub fn normal_progress_reports_audit_phases_without_package_details_test() {
  let #(licence_audit.RunResult(exit_code, _), events) =
    licence_audit.run_configured(
      manifest_args([]),
      test_clients(fake_fetcher),
      progress.capturing(progress.Normal, "report"),
    )

  should.equal(exit_code, 0)
  should.equal(events, [
    progress.Event(progress.Phase, "Starting licence audit"),
    progress.Event(progress.PackageCount, "Checking Hex package metadata"),
    progress.Event(progress.Success, "Licence audit completed"),
  ])
}

pub fn quiet_progress_reports_no_events_test() {
  let #(licence_audit.RunResult(exit_code, output), events) =
    licence_audit.run_configured(
      manifest_args(["--quiet"]),
      test_clients(fake_fetcher),
      progress.capturing(progress.Quiet, "report"),
    )

  should.equal(exit_code, 0)
  assert string.contains(output, "Package")
  should.equal(events, [])
}

pub fn verbose_progress_includes_package_details_test() {
  let #(licence_audit.RunResult(exit_code, output), events) =
    licence_audit.run_configured(
      manifest_args(["--verbose"]),
      test_clients(fake_fetcher),
      progress.capturing(progress.Verbose, "report"),
    )

  should.equal(exit_code, 0)
  assert string.contains(output, "Package")
  assert !list.any(events, fn(event) {
    event
    == progress.Event(
      progress.Detail,
      "Fetched package metadata for gleam_stdlib",
    )
  })
  assert !string.contains(output, "Fetched package metadata for gleam_stdlib")
  assert !string.contains(output, "Licence audit completed")
}

pub fn all_allowed_dependencies_pass_in_check_mode_test() {
  let licence_audit.RunResult(exit_code, output) =
    licence_audit.run_configured(
      manifest_args(["check", test_policy.flag(["MIT", "Apache-2.0"], [])]),
      test_clients(fake_fetcher),
      progress.disabled(),
    ).0

  should.equal(exit_code, 0)
  assert string.contains(output, "Status")
  assert string.contains(output, "gleam_stdlib")
  assert string.contains(output, "allowed")
  assert !string.contains(output, "Dependency licence audit failed")
}

pub fn missing_policy_in_check_mode_exits_two_test() {
  let licence_audit.RunResult(exit_code, output) =
    licence_audit.run_configured(
      manifest_args(["check"]),
      test_clients(fake_fetcher),
      progress.disabled(),
    ).0

  should.equal(exit_code, 2)
  assert string.contains(
    output,
    "The `check` subcommand requires a non-empty allow list",
  )
}

pub fn check_without_allow_rejects_before_loading_manifest_or_calling_clients_test() {
  let clients =
    licence_audit.Clients(
      ..licence_audit.default_clients(),
      fetcher: fn(_) { panic as "Hex must not be called without allow" },
      osv_batch_fetcher: fn(_) {
        panic as "OSV must not be called without allow"
      },
      osv_detail_fetcher: fn(_) {
        panic as "OSV details must not be called without allow"
      },
    )
  [
    [],
    ["--checks=all"],
    ["--checks=all", "--vuln-severity=low"],
    ["--checks=all", "--vuln-block-unknown"],
  ]
  |> list.each(fn(flags) {
    let result =
      licence_audit.run_configured(
        list.append(
          [
            "check",
            "--ignore-config",
            "--manifest=test/fixtures/missing_manifest.toml",
          ],
          flags,
        ),
        clients,
        progress.disabled(),
      ).0
    should.equal(result.exit_code, 2)
    assert string.contains(result.output, "requires a non-empty allow list")
    assert string.contains(result.output, "select a policy file with --config")
    assert !string.contains(result.output, "--allow/--deny")
  })
  let empty_identifier =
    licence_audit.run_configured(
      manifest_args(["check", test_policy.flag([""], [])]),
      clients,
      progress.disabled(),
    ).0
  should.equal(empty_identifier.exit_code, 2)
  assert string.contains(
    empty_identifier.output,
    "Allow and deny entries must be valid SPDX expressions",
  )
}

pub fn check_requires_allow_in_selected_config_test() {
  let assert Ok(_) = simplifile.create_directory_all("build/tmp")
  let path = "build/tmp/check_allow_requirement.toml"
  [
    "allow = []",
    "deny = [\"GPL-3.0-only\"]",
    "vuln_severity = \"low\"",
    "vuln_block_unknown = true",
  ]
  |> list.each(fn(fields) {
    let assert Ok(_) =
      simplifile.write("[tools.licence_audit]\n" <> fields <> "\n", to: path)
    let arguments = [
      "check",
      "--config=" <> path,
      "--manifest=test/fixtures/manifest.toml",
    ]
    let result =
      licence_audit.run_configured(
        arguments,
        test_clients(fn(_) { panic as "Hex must not be called without allow" }),
        progress.disabled(),
      ).0
    should.equal(result.exit_code, 2)
    assert string.contains(result.output, "requires a non-empty allow list")
    let assert Ok(_) =
      simplifile.write(
        "[tools.licence_audit]\nallow = [\"MIT\", \"Apache-2.0\"]\n"
          <> string.replace(fields, "allow = []", ""),
        to: path,
      )
    let with_allow =
      licence_audit.run_configured(
        arguments,
        test_clients(fake_fetcher),
        progress.disabled(),
      ).0
    should.equal(with_allow.exit_code, 0)
  })
  let assert Ok(_) = simplifile.delete(path)
}

pub fn denied_dependency_fails_in_check_mode_with_report_test() {
  let licence_audit.RunResult(exit_code, output) =
    licence_audit.run_configured(
      manifest_args([
        "check",
        test_policy.flag(["MIT", "Apache-2.0"], ["MIT"]),
      ]),
      test_clients(fake_fetcher),
      progress.disabled(),
    ).0

  should.equal(exit_code, 1)
  assert string.contains(output, "gleam_stdlib")
  assert string.contains(output, "denied: MIT")
  assert string.contains(output, "Dependency licence audit failed")
}

pub fn policy_failure_does_not_emit_error_progress_event_test() {
  let #(licence_audit.RunResult(exit_code, _), events) =
    licence_audit.run_configured(
      manifest_args(["check", test_policy.flag(["MIT", "Apache-2.0"], ["MIT"])]),
      test_clients(fake_fetcher),
      progress.capturing(progress.Normal, "report"),
    )

  should.equal(exit_code, 1)
  assert !list.any(events, fn(event) { event.kind == progress.Error })
}

pub fn fetch_failure_in_check_mode_emits_error_progress_event_test() {
  let #(licence_audit.RunResult(exit_code, _), events) =
    licence_audit.run_configured(
      manifest_args(["check", test_policy.flag(["MIT", "Apache-2.0"], [])]),
      test_clients(failing_fetcher),
      progress.capturing(progress.Normal, "report"),
    )

  should.equal(exit_code, 2)
  assert list.contains(
    events,
    progress.Event(
      progress.Error,
      "Licence audit failed: package metadata could not be fetched",
    ),
  )
}

pub fn network_failure_reports_reason_and_continues_audit_test() {
  let #(licence_audit.RunResult(exit_code, output), events) =
    licence_audit.run_configured(
      manifest_args(["check", test_policy.flag(["MIT", "Apache-2.0"], [])]),
      licence_audit.Clients(
        ..test_clients(fake_fetcher),
        notice_clients: notice_clients(fn(name, version) {
          case name {
            "gleam_stdlib" -> Error(notice.FetchTimeout)
            _ ->
              test_clients(fake_fetcher).notice_clients.fetch_hex_tarball(
                name,
                version,
              )
          }
        }),
      ),
      progress.capturing(progress.Normal, "report"),
    )

  should.equal(exit_code, 2)
  assert string.contains(output, "timed out after 30s")
  assert string.contains(output, "Apache-2.0")
  assert list.contains(
    events,
    progress.Event(
      progress.Failure,
      "Failed to fetch package metadata for gleam_stdlib@1.0.0: Failed to fetch source archive for gleam_stdlib: timed out after 30s",
    ),
  )
}

pub fn path_and_git_packages_are_skipped_and_counted_test() {
  let licence_audit.RunResult(exit_code, output) =
    licence_audit.run_configured(
      manifest_args([]),
      test_clients(fake_fetcher),
      progress.disabled(),
    ).0

  should.equal(exit_code, 0)
  // Non-Hex packages now appear in the tree (so their place in the dependency
  // graph is visible) but are still tallied in the skipped summary.
  assert string.contains(output, "local_dep")
  assert string.contains(output, "git_dep")
  assert string.contains(output, "non-hex (local)")
  assert string.contains(output, "non-hex (git)")
  // The skipped summary names the omitted non-Hex packages (issue #3).
  assert string.contains(
    output,
    "Skipped non-Hex packages: 2 (git_dep, local_dep)",
  )
}

pub fn prod_scope_skipped_summary_matches_displayed_non_hex_rows_test() {
  let licence_audit.RunResult(exit_code, output) =
    licence_audit.run_configured(
      manifest_args(["--scope=prod"]),
      test_clients(fake_fetcher),
      progress.disabled(),
    ).0

  should.equal(exit_code, 0)
  assert string.contains(output, "gleam_stdlib")
  assert !string.contains(output, "local_dep")
  assert !string.contains(output, "git_dep")
  assert string.contains(output, "Skipped non-Hex packages: 0")
  assert !string.contains(output, "Skipped non-Hex packages: 2")
}

pub fn hex_fetch_failure_in_report_mode_exits_two_test() {
  list.each([[], [test_policy.flag([], ["MIT"])], ["--quiet"]], fn(flags) {
    let #(result, events) =
      licence_audit.run_configured(
        manifest_args(flags),
        test_clients(failing_fetcher),
        progress.capturing(progress.Normal, "report"),
      )

    should.equal(result.exit_code, 2)
    assert string.contains(result.output, "gleam_stdlib")
    assert string.contains(result.output, "MIT")
    assert string.contains(result.output, "argv")
    assert string.contains(result.output, "network failure")
    assert list.contains(
      events,
      progress.Event(
        progress.Error,
        "Licence audit failed: package metadata could not be fetched",
      ),
    )
    assert !list.contains(
      events,
      progress.Event(progress.Success, "Licence audit completed"),
    )
  })
}

pub fn report_metadata_errors_exit_two_test() {
  list.each(
    [
      #(notice.FetchNetworkFailure, "network failure"),
      #(notice.FetchTimeout, "timed out after 30s"),
      #(notice.FetchUnexpectedResponse(500), "unexpected HTTP response 500"),
    ],
    fn(test_case) {
      let #(fetch_error, message) = test_case
      let result =
        licence_audit.run_configured(
          manifest_args([]),
          licence_audit.Clients(
            ..test_clients(fake_fetcher),
            notice_clients: notice_clients(fn(_, _) { Error(fetch_error) }),
          ),
          progress.disabled(),
        ).0
      should.equal(result.exit_code, 2)
      assert string.contains(result.output, message)
    },
  )
}

pub fn report_policy_findings_still_exit_zero_test() {
  let result =
    licence_audit.run_configured(
      manifest_args([test_policy.flag([], ["MIT"])]),
      test_clients(fake_fetcher),
      progress.disabled(),
    ).0
  should.equal(result.exit_code, 0)
  assert string.contains(result.output, "denied: MIT")
}

pub fn hex_fetch_failure_in_check_mode_exits_two_test() {
  let licence_audit.RunResult(exit_code, output) =
    licence_audit.run_configured(
      manifest_args(["check", test_policy.flag(["MIT", "Apache-2.0"], [])]),
      test_clients(failing_fetcher),
      progress.disabled(),
    ).0

  should.equal(exit_code, 2)
  assert string.contains(output, "gleam_stdlib")
  assert string.contains(output, "argv")
  assert string.contains(output, "network failure")
}

fn transitive_fetcher(name: String) -> Result(hex.PackageMetadata, hex.Error) {
  case name {
    "app_a" -> Ok(hex.licences_only(["MIT"]))
    "lib_b" -> Ok(hex.licences_only(["MIT"]))
    "lib_c" -> Ok(hex.licences_only(["GPL-3.0"]))
    _ -> Error(hex.NotFound)
  }
}

fn transitive_manifest_args(extra: List(String)) -> List(String) {
  let flags = case list.any(extra, string.starts_with(_, "--config=")) {
    True -> []
    False -> ["--ignore-config"]
  }
  let command = case list.contains(extra, "check") {
    True -> extra
    False -> ["report", ..extra]
  }
  list.append(command, [
    "--manifest=test/fixtures/transitive_manifest.toml",
    ..flags
  ])
}

pub fn report_shows_dependency_tree_without_kind_column_test() {
  let licence_audit.RunResult(exit_code, output) =
    licence_audit.run_configured(
      transitive_manifest_args([]),
      test_clients(transitive_fetcher),
      progress.disabled(),
    ).0

  should.equal(exit_code, 0)
  assert !string.contains(output, "Kind")
  // app_a is the direct dep, lib_b and lib_c are transitive.
  assert string.contains(output, "app_a")
  assert string.contains(output, "lib_b")
  assert string.contains(output, "lib_c")
}

pub fn denied_transitive_fails_check_and_prints_via_chain_test() {
  let licence_audit.RunResult(exit_code, output) =
    licence_audit.run_configured(
      transitive_manifest_args([
        "check",
        test_policy.flag(["MIT"], ["GPL-3.0"]),
      ]),
      test_clients(transitive_fetcher),
      progress.disabled(),
    ).0

  should.equal(exit_code, 1)
  assert string.contains(output, "lib_c")
  assert string.contains(output, "denied: GPL-3.0")
  // The tree layout indents transitive deps under the dep that brought them
  // in: app_a → lib_b → lib_c.
  assert string.contains(output, "└─ ✓ lib_b")
  assert string.contains(output, "   └─ ✗ lib_c")
  assert string.contains(output, "Dependency licence audit failed")
}

pub fn direct_dep_denial_does_not_emit_via_line_test() {
  let licence_audit.RunResult(exit_code, output) =
    licence_audit.run_configured(
      transitive_manifest_args([
        "check",
        test_policy.flag(["GPL-3.0"], ["MIT"]),
      ]),
      test_clients(transitive_fetcher),
      progress.disabled(),
    ).0

  should.equal(exit_code, 1)
  assert string.contains(output, "app_a")
  assert string.contains(output, "denied: MIT")
  // A direct dep alone never produces a `via:` chain — the only via line in
  // this output, if any, belongs to the transitive lib_b → app_a chain.
  assert !string.contains(output, "via: app_a\n")
}

pub fn check_failure_only_reports_failing_trees_test() {
  // gleam_stdlib (MIT) is denied; argv (Apache-2.0) is allowed and lives in
  // its own root-level tree. On policy failure the report should omit the
  // passing tree and only show the offending one.
  let licence_audit.RunResult(exit_code, output) =
    licence_audit.run_configured(
      manifest_args([
        "check",
        test_policy.flag(["MIT", "Apache-2.0"], ["MIT"]),
      ]),
      test_clients(fake_fetcher),
      progress.disabled(),
    ).0

  should.equal(exit_code, 1)
  assert string.contains(output, "gleam_stdlib")
  assert string.contains(output, "denied: MIT")
  assert !string.contains(output, "argv")
}

pub fn check_mixed_failures_keeps_fetch_trees_and_filters_successes_test() {
  list.each(["fetch_root", "fetch_leaf"], fn(failed_package) {
    list.each(
      [#([], progress.Normal), #(["--quiet"], progress.Quiet)],
      fn(mode) {
        let #(extra, verbosity) = mode
        let #(result, events) =
          licence_audit.run_configured(
            list.append(
              [
                "--manifest=test/fixtures/mixed_failure_manifest.toml",
                "check",
                test_policy.flag(["MIT"], ["GPL-3.0"]),
              ],
              extra,
            ),
            test_clients(fn(name) {
              case name == failed_package, name {
                True, _ -> Error(hex.NotFound)
                False, "denied" -> Ok(hex.licences_only(["GPL-3.0"]))
                False, _ -> Ok(hex.licences_only(["MIT"]))
              }
            }),
            progress.capturing(verbosity, "report"),
          )

        should.equal(result.exit_code, 2)
        assert string.contains(result.output, "denied: GPL-3.0")
        assert string.contains(result.output, "fetch_root")
        assert string.contains(result.output, "fetch_leaf")
        assert string.contains(result.output, "network failure")
        assert !string.contains(result.output, "allowed_root")
        assert !string.contains(result.output, "allowed_leaf")
        assert !string.contains(
          result.output,
          "Dependency licence audit failed",
        )
        assert list.contains(
          events,
          progress.Event(
            progress.Error,
            "Licence audit failed: package metadata could not be fetched",
          ),
        )
      },
    )
  })
}

fn failing_osv_batch(
  _purls: List(String),
) -> Result(List(osv.BatchEntry), osv.Error) {
  Error(osv.NetworkFailure("connection refused"))
}

fn unused_vuln_detail(_id: String) -> Result(osv.Vulnerability, osv.Error) {
  Error(osv.NotFound)
}

pub fn check_vulns_osv_batch_failure_exits_two_test() {
  let #(result, events) =
    licence_audit.run_configured(
      manifest_args([
        "check",
        test_policy.flag(["MIT", "Apache-2.0"], []),
        "--checks=all",
      ]),
      licence_audit.Clients(
        ..test_clients(fake_fetcher),
        osv_batch_fetcher: failing_osv_batch,
        osv_detail_fetcher: unused_vuln_detail,
      ),
      progress.capturing(progress.Quiet, "check"),
    )

  should.equal(result.exit_code, 2)
  assert !string.contains(
    result.output,
    "Vulnerability check failed: OSV request failed: connection refused",
  )
  assert string.contains(result.output, "gleam_stdlib")
  should.equal(events, [
    progress.Event(
      progress.Error,
      "Vulnerability check failed: OSV request failed: connection refused",
    ),
  ])
}

fn unknown_vuln_detail(id: String) -> Result(osv.Vulnerability, osv.Error) {
  Ok(
    osv.Vulnerability(
      aliases: [],
      id: id,
      summary: "severity unavailable",
      severity: osv.UnknownSeverity,
      scores: [],
      affected: [],
    ),
  )
}

fn vulnerability_with_severity(
  severity: osv.Severity,
) -> fn(String) -> Result(osv.Vulnerability, osv.Error) {
  fn(id) {
    Ok(
      osv.Vulnerability(
        aliases: [],
        id: id,
        summary: "known severity",
        severity: severity,
        scores: [],
        affected: [],
      ),
    )
  }
}

fn zero_vuln_detail(id: String) -> Result(osv.Vulnerability, osv.Error) {
  let assert Ok(body) = simplifile.read("test/fixtures/osv_vuln_none.json")
  osv.decode_vuln_body(body, id)
}

pub fn zero_cvss_never_blocks_low_threshold_with_unknown_blocking_test() -> Nil {
  list.each([[], ["--vuln-block-unknown"]], fn(flags) {
    let result =
      licence_audit.run_configured(
        manifest_args(list.append(
          [
            "check",
            test_policy.flag(["MIT", "Apache-2.0"], []),
            "--checks=all",
            "--vuln-severity=low",
          ],
          flags,
        )),
        licence_audit.Clients(
          ..test_clients(fake_fetcher),
          osv_batch_fetcher: one_vuln_batch,
          osv_detail_fetcher: zero_vuln_detail,
        ),
        progress.disabled(),
      ).0
    should.equal(result.exit_code, 0)
    assert string.contains(result.output, "[NONE    ]  CVE-2024-0001")
    assert string.contains(
      result.output,
      "0 advisory/advisories at or above low",
    )
    assert !string.contains(result.output, "[LOW")
    assert !string.contains(result.output, "[UNKNOWN")
  })
}

pub fn zero_cvss_is_reported_as_none_in_vulns_and_sbom_test() -> Nil {
  list.each([["vulns"], ["sbom", "--vulns"]], fn(args) {
    let result =
      licence_audit.run_configured(
        list.append(args, ["--manifest=test/fixtures/manifest_github_git.toml"]),
        licence_audit.Clients(
          ..test_clients(fake_fetcher),
          osv_batch_fetcher: one_vuln_batch,
          osv_detail_fetcher: zero_vuln_detail,
        ),
        progress.disabled(),
      ).0
    should.equal(result.exit_code, 0)
    assert string.contains(result.output, "CVE-2024-0001")
    case args {
      ["sbom", ..] -> {
        assert string.contains(result.output, "\"severity\": \"none\"")
        assert string.contains(result.output, "\"method\": \"CVSSv31\"")
        assert string.contains(result.output, "C:N/I:N/A:N")
      }
      _ -> {
        assert string.contains(result.output, "[NONE    ]")
        assert string.contains(result.output, "No impact")
      }
    }
  })
}

pub fn none_is_not_a_vulnerability_gate_threshold_test() -> Nil {
  let result =
    licence_audit.run_configured(
      manifest_args([
        "check",
        test_policy.flag(["MIT", "Apache-2.0"], []),
        "--checks=all",
        "--vuln-severity=none",
      ]),
      test_clients(fn(_) { panic as "invalid threshold must not fetch" }),
      progress.disabled(),
    ).0
  should.equal(result.exit_code, 2)
  assert string.contains(result.output, "low")
  let config_path = "build/none-threshold-config.toml"
  let assert Ok(_) =
    simplifile.write(
      config_path,
      "[tools.licence_audit]\nallow = [\"MIT\", \"Apache-2.0\"]\nvuln_severity = \"none\"\n",
    )
  let configured =
    licence_audit.run_configured(
      [
        "check",
        "--checks=all",
        "--manifest=test/fixtures/manifest.toml",
        "--config=" <> config_path,
      ],
      test_clients(fn(_) { panic as "invalid threshold must not fetch" }),
      progress.disabled(),
    ).0
  let assert Ok(_) = simplifile.delete(config_path)
  should.equal(configured.exit_code, 2)
  assert string.contains(configured.output, "vuln_severity")
}

fn github_only_vuln_batch(
  purls: List(String),
) -> Result(List(osv.BatchEntry), osv.Error) {
  osv.query_batch(purls, fn(request) {
    let assert Ok(commits) =
      json.parse(
        request.body,
        decode.field(
          "queries",
          decode.list(decode.optional_field(
            "commit",
            "",
            decode.string,
            decode.success,
          )),
          decode.success,
        ),
      )
    let results =
      json.array(commits, fn(commit) {
        let ids = case commit {
          "" -> []
          _ -> ["CVE-GITHUB-0001"]
        }
        json.object([
          #(
            "vulns",
            json.array(ids, fn(id) { json.object([#("id", json.string(id))]) }),
          ),
        ])
      })
    Ok(response.Response(
      status: 200,
      headers: [],
      body: json.to_string(json.object([#("results", results)])),
    ))
  })
}

pub fn vulnerability_commands_preserve_mixed_source_identities_test() {
  ["", ", outer_checksum = \"AAAA\"", ", outer_checksum = 42"]
  |> list.each(fn(checksum) {
    let manifest_path = mixed_vuln_manifest(checksum)
    [#(["vulns"], 0), #(["check", "--checks=vulns"], 1)]
    |> list.each(fn(command) {
      let #(args, expected_exit) = command
      let result =
        licence_audit.run_configured(
          list.append(args, [
            "--manifest=" <> manifest_path,
          ]),
          licence_audit.Clients(
            ..test_clients(fake_fetcher),
            osv_batch_fetcher: fn(purls) {
              should.equal(purls, [
                "pkg:hex/gleam_stdlib@1.0.0",
                "pkg:github/tylerbutler/gluegun@fa4c8ee919138fc8ffddd2642165a89654e61999",
              ])
              github_only_vuln_batch(purls)
            },
            osv_detail_fetcher: vulnerability_with_severity(osv.High),
          ),
          progress.disabled(),
        ).0

      should.equal(result.exit_code, expected_exit)
      assert string.contains(result.output, "CVE-GITHUB-0001")
      assert string.contains(result.output, "gluegun")
      assert string.contains(
        result.output,
        "Skipped 1 unsupported source(s): local_dep",
      )
    })
  })
}

fn mixed_vuln_manifest(checksum: String) -> String {
  let root = "build/tmp/mixed-vuln-provenance"
  let assert Ok(_) = simplifile.create_directory_all(root)
  let assert Ok(_) =
    simplifile.write(to: root <> "/manifest.toml", contents: "packages = [
  { name = \"gleam_stdlib\", version = \"1.0.0\", source = \"hex\"" <> checksum <> " },
  { name = \"gluegun\", version = \"0.1.0\", source = \"git\", repo = \"https://github.com/tylerbutler/gluegun\", commit = \"fa4c8ee919138fc8ffddd2642165a89654e61999\", requirements = [\"gleam_stdlib\"] },
  { name = \"local_dep\", version = \"0.1.0\", source = \"local\", path = \"../local_dep\" },
]
[requirements]
gleam_stdlib = \"1.0.0\"
gluegun = { git = \"https://github.com/tylerbutler/gluegun\" }
local_dep = { path = \"../local_dep\" }
")
  root <> "/manifest.toml"
}

pub fn check_vulns_locked_checksum_preserves_prod_git_scope_test() {
  [#("gleam_stdlib", 0), #("gluegun", 1)]
  |> list.each(fn(test_case) {
    let #(production, expected_exit) = test_case
    let manifest_path =
      mixed_vuln_manifest(
        ", outer_checksum = \"4C4C81A8F753EE1917FCC9C611745DBB1F8730F2A8B7A1BBDBC9A6B1C69F7A66\"",
      )
    let assert Ok(_) =
      simplifile.write(
        to: "build/tmp/mixed-vuln-provenance/gleam.toml",
        contents: "[dependencies]\n" <> production <> " = \"1.0.0\"\n",
      )
    let result =
      licence_audit.run_configured(
        [
          "--manifest=" <> manifest_path,
          "check",
          test_policy.flag(["MIT"], []),
          "--checks=all",
          "--scope=prod",
        ],
        licence_audit.Clients(
          ..test_clients(fake_fetcher),
          osv_batch_fetcher: fn(purls) {
            let expected = case production {
              "gleam_stdlib" -> ["pkg:hex/gleam_stdlib@1.0.0"]
              _ -> [
                "pkg:hex/gleam_stdlib@1.0.0",
                "pkg:github/tylerbutler/gluegun@fa4c8ee919138fc8ffddd2642165a89654e61999",
              ]
            }
            should.equal(purls, expected)
            github_only_vuln_batch(purls)
          },
          osv_detail_fetcher: vulnerability_with_severity(osv.High),
        ),
        progress.disabled(),
      ).0
    should.equal(result.exit_code, expected_exit)
    should.equal(
      string.contains(result.output, "CVE-GITHUB-0001"),
      expected_exit == 1,
    )
    assert !string.contains(result.output, "local_dep")
  })
}

pub fn github_commit_queries_reach_vulns_and_sbom_test() {
  [["vulns"], ["sbom", "--vulns"]]
  |> list.each(fn(args) {
    let result =
      licence_audit.run_configured(
        list.append(args, ["--manifest=test/fixtures/manifest_github_git.toml"]),
        licence_audit.Clients(
          ..test_clients(fake_fetcher),
          osv_batch_fetcher: github_only_vuln_batch,
          osv_detail_fetcher: vulnerability_with_severity(osv.High),
        ),
        progress.disabled(),
      ).0
    should.equal(result.exit_code, 0)
    assert string.contains(result.output, "CVE-GITHUB-0001")
    case args {
      ["sbom", ..] -> {
        let assert Ok(affected) =
          json.parse(
            result.output,
            decode.at(
              ["vulnerabilities"],
              decode.list(decode.field(
                "affects",
                decode.list(decode.field("ref", decode.string, decode.success)),
                decode.success,
              )),
            ),
          )
        should.equal(affected, [
          [
            "pkg:github/tylerbutler/gluegun@fa4c8ee919138fc8ffddd2642165a89654e61999",
          ],
        ])
      }
      _ -> {
        assert string.contains(result.output, "gluegun 0.1.0")
      }
    }
  })
}

pub fn check_vulns_reports_unsupported_sources_test() {
  let path =
    mixed_vuln_manifest(
      ", outer_checksum = \"4C4C81A8F753EE1917FCC9C611745DBB1F8730F2A8B7A1BBDBC9A6B1C69F7A66\"",
    )
  let result =
    licence_audit.run_configured(
      [
        "--manifest=" <> path,
        "check",
        test_policy.flag(["MIT"], []),
        "--checks=all",
      ],
      licence_audit.Clients(
        ..test_clients(fake_fetcher),
        osv_batch_fetcher: fn(purls) {
          Ok(list.map(purls, fn(purl) { osv.BatchEntry(purl, []) }))
        },
        osv_detail_fetcher: vulnerability_with_severity(osv.High),
      ),
      progress.disabled(),
    ).0

  should.equal(result.exit_code, 0)
  assert string.contains(
    result.output,
    "Skipped 1 unsupported source(s): local_dep",
  )
}

fn locked_licence_project(name: String, archive: BitArray) -> String {
  let root = "build/locked-licence-" <> name
  let assert Ok(_) = simplifile.create_directory_all(root)
  let assert Ok(checksum) = source_archive.sha256_hex(archive)
  let assert Ok(_) =
    simplifile.write(
      root <> "/manifest.toml",
      "packages = [{ name = \"hex_dep\", version = \"1.0.0\", source = \"hex\", outer_checksum = \""
        <> checksum
        <> "\" }]\n[requirements]\nhex_dep = \"1.0.0\"\n",
    )
  let assert Ok(_) =
    simplifile.write(
      root <> "/gleam.toml",
      "name = \"fixture\"\nversion = \"1.0.0\"\n[tools.licence_audit]\nallow = [\"MIT\"]\n",
    )
  root
}

pub fn report_check_and_update_use_locked_licences_not_api_licences_test() {
  let assert Ok(archive) =
    simplifile.read_bits("test/fixtures/sbom_metadata/hex.tar")
  let root = locked_licence_project("disagreement", archive)
  let clients =
    licence_audit.Clients(
      ..test_clients(fn(_) { Ok(hex.licences_only(["MIT"])) }),
      notice_clients: notice_clients(fn(name, version) {
        should.equal(#(name, version), #("hex_dep", "1.0.0"))
        Ok(archive)
      }),
    )
  list.each(
    [
      #([], 0),
      #(["report"], 0),
      #(["check"], 1),
      #(["check", test_policy.flag(["Apache-2.0"], [])], 0),
    ],
    fn(command) {
      let result =
        licence_audit.run_configured(
          list.append(command.0, ["--manifest=" <> root <> "/manifest.toml"]),
          clients,
          progress.disabled(),
        ).0
      should.equal(result.exit_code, command.1)
      assert string.contains(result.output, "Apache-2.0")
      assert !string.contains(result.output, "MIT")
    },
  )
  let root_update =
    licence_audit.run_configured(
      ["update", "--manifest=" <> root <> "/manifest.toml"],
      clients,
      progress.disabled(),
    ).0
  should.equal(root_update.exit_code, 2)
  assert string.contains(root_update.output, "requires an interactive terminal")
  let #(updated, _) =
    update.run_with_picker(
      root <> "/manifest.toml",
      root,
      None,
      True,
      None,
      clients.notice_clients,
      fn(_, labels, allow, deny) {
        should.equal(labels, ["Apache-2.0", "MIT"])
        should.equal(allow, ["MIT"])
        should.equal(deny, [])
        Ok(picker.Selection(["Apache-2.0"], []))
      },
      progress.disabled(),
    )
  should.equal(updated.exit_code, 0)
  let assert Ok(saved) = simplifile.read(root <> "/gleam.toml")
  assert string.contains(saved, "allow = [\"Apache-2.0\"]")
  let assert Ok(_) = simplifile.delete(root)
}

pub fn licence_commands_reject_bad_locked_evidence_without_api_fallback_test() {
  let archive = source_archive_test.metadata_archive(["Apache-2.0"])
  let root = locked_licence_project("bad-evidence", archive)
  let assert Ok(original_policy) = simplifile.read(root <> "/gleam.toml")
  let assert Ok(original_manifest) = simplifile.read(root <> "/manifest.toml")
  let assert Ok(checksum) = source_archive.sha256_hex(archive)
  let cases = [
    #(original_manifest, Error(notice.FetchNetworkFailure), "network failure"),
    #(
      string.replace(original_manifest, checksum, string.repeat("0", 64)),
      Ok(archive),
      "Checksum mismatch",
    ),
    #(
      string.replace(original_manifest, checksum, "invalid"),
      Ok(archive),
      "outer_checksum",
    ),
    #(
      string.replace(
        original_manifest,
        ", outer_checksum = \"" <> checksum <> "\"",
        "",
      ),
      Ok(archive),
      "outer_checksum",
    ),
  ]
  list.each(cases, fn(test_case) {
    let assert Ok(_) = simplifile.write(root <> "/manifest.toml", test_case.0)
    list.each([[], ["report"], ["check"], ["update"]], fn(command) {
      let result =
        licence_audit.run_configured(
          list.append(command, ["--manifest=" <> root <> "/manifest.toml"]),
          licence_audit.Clients(
            ..test_clients(fn(_) {
              panic as "API licences must not be a fallback"
            }),
            notice_clients: notice_clients(fn(_, _) { test_case.1 }),
          ),
          progress.disabled(),
        ).0
      should.equal(result.exit_code, 2)
      case command, test_case.2 {
        ["update"], "network failure" | ["update"], "Checksum mismatch" -> {
          assert string.contains(result.output, "failed to fetch metadata")
        }
        _, _ -> {
          assert string.contains(result.output, test_case.2)
        }
      }
      should.equal(simplifile.read(root <> "/gleam.toml"), Ok(original_policy))
    })
  })
  let assert Ok(_) = simplifile.delete(root)
}

pub fn licence_commands_reject_missing_and_invalid_archive_metadata_test() {
  list.each(
    [
      #([#("README", <<"No metadata":utf8>>)], "no metadata.config"),
      #([#("metadata.config", <<"invalid":utf8>>)], "invalid metadata.config"),
      #(
        [
          #("metadata.config", <<
            "{<<\"description\">>, <<\"Missing licences\">>}.\n":utf8,
          >>),
        ],
        "invalid metadata.config",
      ),
      #(
        [#("metadata.config", <<"{<<\"licenses\">>, [42]}.\n":utf8>>)],
        "invalid metadata.config",
      ),
    ],
    fn(test_case) {
      let archive =
        source_archive_test.with_tar(test_case.0, fn(archive) { archive })
      let root = locked_licence_project("metadata-error", archive)
      let assert Ok(original_policy) = simplifile.read(root <> "/gleam.toml")
      list.each([["report"], ["check"], ["update"]], fn(command) {
        let result =
          licence_audit.run_configured(
            list.append(command, ["--manifest=" <> root <> "/manifest.toml"]),
            licence_audit.Clients(
              ..test_clients(fn(_) {
                panic as "invalid archive must not fall back to API licences"
              }),
              notice_clients: notice_clients(fn(_, _) { Ok(archive) }),
            ),
            progress.disabled(),
          ).0
        should.equal(result.exit_code, 2)
        case command {
          ["update"] -> {
            assert string.contains(result.output, "failed to fetch metadata")
          }
          _ -> {
            assert string.contains(result.output, test_case.1)
          }
        }
        should.equal(
          simplifile.read(root <> "/gleam.toml"),
          Ok(original_policy),
        )
      })
      let assert Ok(_) = simplifile.delete(root)
    },
  )
}

pub fn check_vulns_unknown_severity_is_non_blocking_by_default_test() {
  let result =
    licence_audit.run_configured(
      manifest_args([
        "check",
        test_policy.flag(["MIT", "Apache-2.0"], []),
        "--checks=all",
      ]),
      licence_audit.Clients(
        ..test_clients(fake_fetcher),
        osv_batch_fetcher: one_vuln_batch,
        osv_detail_fetcher: unknown_vuln_detail,
      ),
      progress.disabled(),
    ).0

  should.equal(result.exit_code, 0)
  assert string.contains(result.output, "·  [UNKNOWN ]  CVE-2024-0001")
  assert string.contains(
    result.output,
    "0 advisory/advisories at or above high",
  )
}

pub fn check_vulns_unknown_severity_blocks_when_enabled_test() {
  let result =
    licence_audit.run_configured(
      manifest_args([
        "check",
        test_policy.flag(["MIT", "Apache-2.0"], []),
        "--checks=all",
        "--vuln-block-unknown",
      ]),
      licence_audit.Clients(
        ..test_clients(fake_fetcher),
        osv_batch_fetcher: one_vuln_batch,
        osv_detail_fetcher: unknown_vuln_detail,
      ),
      progress.disabled(),
    ).0

  should.equal(result.exit_code, 1)
  assert string.contains(result.output, "✗  [UNKNOWN ]  CVE-2024-0001")
  assert string.contains(result.output, "blocking advisory/advisories")
  assert string.contains(result.output, "or unknown severity")
  assert string.contains(result.output, "unknown-severity blocking rule")
}

pub fn check_vulns_detail_failure_exits_two_by_default_test() {
  // A failed advisory detail lookup can't be evaluated for severity, so it
  // must fail the gate outright rather than falling back to a non-blocking
  // unknown-severity placeholder — even with the default threshold/config.
  let result =
    licence_audit.run_configured(
      manifest_args([
        "check",
        test_policy.flag(["MIT", "Apache-2.0"], []),
        "--checks=all",
      ]),
      licence_audit.Clients(
        ..test_clients(fake_fetcher),
        osv_batch_fetcher: one_vuln_batch,
        osv_detail_fetcher: unused_vuln_detail,
      ),
      progress.disabled(),
    ).0

  should.equal(result.exit_code, 2)
  assert string.contains(result.output, "gleam_stdlib")
  assert !string.contains(result.output, "Vulnerability check incomplete")
  assert !string.contains(result.output, "OSV resource not found")
}

pub fn check_vulns_detail_failure_reports_one_specific_error_event_test() {
  // Regression test: the detail-failure gate path must exit 2 without
  // setting the pre-existing `vuln_query_failed` flag, since that flag makes
  // `finalize_audit` attach a second, generic "OSV request failed" message —
  // a false duplicate for a lookup failure that has nothing to do with the
  // OSV batch request. Exactly one deferred error event should be recorded,
  // and it must be the specific advisory-detail failure.
  let #(licence_audit.RunResult(exit_code, _), events) =
    licence_audit.run_configured(
      manifest_args([
        "check",
        test_policy.flag(["MIT", "Apache-2.0"], []),
        "--checks=all",
      ]),
      licence_audit.Clients(
        ..test_clients(fake_fetcher),
        osv_batch_fetcher: one_vuln_batch,
        osv_detail_fetcher: unused_vuln_detail,
      ),
      progress.capturing(progress.Normal, "report"),
    )

  should.equal(exit_code, 2)
  let error_events =
    list.filter(events, fn(event) {
      case event {
        progress.Event(progress.Error, _) -> True
        _ -> False
      }
    })
  should.equal(error_events, [
    progress.Event(
      progress.Error,
      "Vulnerability check incomplete: failed to fetch OSV advisory details for 1 advisory/advisories. The gate cannot confirm these are safe, so the check fails:\n  CVE-2024-0001: OSV resource not found",
    ),
  ])
  assert !list.contains(
    events,
    progress.Event(
      progress.Error,
      "Vulnerability check failed: OSV request failed",
    ),
  )
}

pub fn check_vulns_detail_failure_exits_two_with_block_unknown_test() {
  // Same as above with --vuln-block-unknown set: the failure must still
  // surface as an incomplete check (exit 2), not as a blocked-but-successful
  // gate evaluation (exit 1).
  let result =
    licence_audit.run_configured(
      manifest_args([
        "check",
        test_policy.flag(["MIT", "Apache-2.0"], []),
        "--checks=all",
        "--vuln-block-unknown",
      ]),
      licence_audit.Clients(
        ..test_clients(fake_fetcher),
        osv_batch_fetcher: one_vuln_batch,
        osv_detail_fetcher: unused_vuln_detail,
      ),
      progress.disabled(),
    ).0

  should.equal(result.exit_code, 2)
  assert string.contains(result.output, "gleam_stdlib")
  assert !string.contains(result.output, "Vulnerability check incomplete")
  assert !string.contains(result.output, "OSV resource not found")
}

pub fn check_vulns_alternate_config_controls_unknown_gate_test() {
  let config_path = "build/tmp/vuln-block-unknown.toml"
  let assert Ok(Nil) = simplifile.create_directory_all("build/tmp")
  let assert Ok(Nil) =
    simplifile.write(
      to: config_path,
      contents: "[tools.licence_audit]
allow = [\"MIT\", \"Apache-2.0\"]
vuln_block_unknown = true
",
    )
  let configured =
    licence_audit.run_configured(
      [
        "--manifest=test/fixtures/manifest.toml",
        "--config=" <> config_path,
        "check",
        "--checks=all",
      ],
      licence_audit.Clients(
        ..test_clients(fake_fetcher),
        osv_batch_fetcher: one_vuln_batch,
        osv_detail_fetcher: unknown_vuln_detail,
      ),
      progress.disabled(),
    ).0
  let ignored =
    licence_audit.run_configured(
      [
        "--manifest=test/fixtures/manifest.toml",
        "check",
        test_policy.flag(["MIT", "Apache-2.0"], []),
        "--checks=all",
      ],
      licence_audit.Clients(
        ..test_clients(fake_fetcher),
        osv_batch_fetcher: one_vuln_batch,
        osv_detail_fetcher: unknown_vuln_detail,
      ),
      progress.disabled(),
    ).0

  should.equal(configured.exit_code, 1)
  should.equal(ignored.exit_code, 0)
  assert string.contains(configured.output, "✗  [UNKNOWN ]  CVE-2024-0001")
  assert string.contains(ignored.output, "·  [UNKNOWN ]  CVE-2024-0001")
}

pub fn check_vulns_known_severity_thresholds_are_unchanged_test() {
  [
    #(osv.Low, "low", 1),
    #(osv.Low, "medium", 0),
    #(osv.Low, "high", 0),
    #(osv.Low, "critical", 0),
    #(osv.Medium, "low", 1),
    #(osv.Medium, "medium", 1),
    #(osv.Medium, "high", 0),
    #(osv.Medium, "critical", 0),
    #(osv.High, "low", 1),
    #(osv.High, "medium", 1),
    #(osv.High, "high", 1),
    #(osv.High, "critical", 0),
    #(osv.Critical, "low", 1),
    #(osv.Critical, "medium", 1),
    #(osv.Critical, "high", 1),
    #(osv.Critical, "critical", 1),
  ]
  |> list.each(fn(test_case) {
    let #(severity, threshold, expected_exit) = test_case
    let result =
      licence_audit.run_configured(
        manifest_args([
          "check",
          test_policy.flag(["MIT", "Apache-2.0"], []),
          "--checks=all",
          "--vuln-severity=" <> threshold,
        ]),
        licence_audit.Clients(
          ..test_clients(fake_fetcher),
          osv_batch_fetcher: one_vuln_batch,
          osv_detail_fetcher: vulnerability_with_severity(severity),
        ),
        progress.disabled(),
      ).0

    should.equal(result.exit_code, expected_exit)
  })
}

pub fn vulns_unknown_severity_remains_descriptive_test() {
  let result =
    licence_audit.run_configured(
      ["vulns", "--manifest=test/fixtures/manifest_github_git.toml"],
      licence_audit.Clients(
        ..test_clients(fake_fetcher),
        osv_batch_fetcher: one_vuln_batch,
        osv_detail_fetcher: unknown_vuln_detail,
      ),
      progress.disabled(),
    ).0

  should.equal(result.exit_code, 0)
  assert string.contains(result.output, "[UNKNOWN ]")
  assert string.contains(result.output, "CVE-2024-0001")
}

fn sbom_fetcher(name: String) -> Result(hex.PackageMetadata, hex.Error) {
  case name {
    "gleam_stdlib" -> Ok(hex.licences_only(["Apache-2.0"]))
    _ -> Error(hex.NotFound)
  }
}

pub fn sbom_subcommand_prints_cyclonedx_to_stdout_test() {
  let result =
    licence_audit.run_configured(
      ["sbom", "--manifest=test/fixtures/manifest_github_git.toml"],
      test_clients(sbom_fetcher),
      progress.disabled(),
    ).0
  should.equal(result.exit_code, 0)
  let assert True =
    string.contains(result.output, "\"bomFormat\": \"CycloneDX\"")
  let assert True = string.contains(result.output, "\n  \"metadata\": {")
  let assert True = string.contains(result.output, "\n    \"tools\": [")
  let assert True =
    string.contains(result.output, "\"purl\": \"pkg:hex/gleam_stdlib@1.0.0\"")
  let assert True =
    string.contains(
      result.output,
      "\"purl\": \"pkg:github/tylerbutler/gluegun@fa4c8ee919138fc8ffddd2642165a89654e61999\"",
    )
  let assert True = string.contains(result.output, "\"id\": \"Apache-2.0\"")
}

pub fn sbom_license_text_is_opt_in_and_fetches_shared_id_once_test() {
  reset_detail_fetch("sbom-license-text")
  let clients =
    licence_audit.Clients(
      ..test_clients(sbom_fetcher),
      fetcher: fn(name) {
        sbom_fetcher(name)
        |> result.map(fn(metadata) {
          hex.PackageMetadata(..metadata, licences: [
            "apache-2.0",
            "MIT OR Apache-2.0",
            "LicenseRef-Local",
          ])
        })
      },
      notice_clients: notice.Clients(
        ..notice_clients(fixture_hex_tarball),
        fetch_spdx: fn(requirement) {
          should.equal(requirement, spdx.LicenseRequirement("Apache-2.0"))
          let _ = record_detail_fetch("sbom-license-text")
          Ok(Some("Canonical SPDX text\n"))
        },
      ),
    )
  let args = ["sbom", "--manifest=test/fixtures/manifest_github_git.toml"]
  let plain = licence_audit.run_configured(args, clients, progress.disabled()).0
  should.equal(plain.exit_code, 0)
  assert !string.contains(plain.output, "\"text\":")
  should.equal(record_detail_fetch("sbom-license-text"), 1)
  use spelling <- list.each(["--licence-text", "--license-text"])
  use value <- list.each([#("", True), #("=true", True), #("=false", False)])
  let #(suffix, enabled) = value
  reset_detail_fetch("sbom-license-text")
  let enriched =
    licence_audit.run_configured(
      list.append(args, [spelling <> suffix]),
      clients,
      progress.disabled(),
    ).0
  should.equal(enriched.exit_code, 0)
  should.equal(record_detail_fetch("sbom-license-text"), case enabled {
    True -> 2
    False -> 1
  })
  should.equal(
    string.contains(enriched.output, "\"contentType\": \"text/plain\""),
    enabled,
  )
  should.equal(
    string.contains(enriched.output, "Canonical SPDX text\\n"),
    enabled,
  )
}

pub fn sbom_license_text_fetch_failures_leave_output_untouched_test() {
  let output = "build/tmp/sbom-license-text-existing.json"
  let assert Ok(Nil) = simplifile.create_directory_all("build/tmp")
  list.each(
    [
      Error(notice.FetchNetworkFailure),
      Ok(None),
      Ok(Some(" \r\n\t")),
    ],
    fn(response) {
      use spelling <- list.each(["--licence-text", "--license-text"])
      let assert Ok(Nil) = simplifile.write(output, "previous output")
      let result =
        licence_audit.run_configured(
          [
            "sbom",
            "--manifest=test/fixtures/manifest_github_git.toml",
            spelling,
            "--output=" <> output,
          ],
          licence_audit.Clients(
            ..test_clients(sbom_fetcher),
            notice_clients: notice.Clients(
              ..notice_clients(fixture_hex_tarball),
              fetch_spdx: fn(_requirement) { response },
            ),
          ),
          progress.disabled(),
        ).0
      should.equal(result.exit_code, 2)
      assert string.contains(result.output, "SPDX")
      assert string.contains(result.output, "Apache-2.0")
      should.equal(simplifile.read(output), Ok("previous output"))
    },
  )
  let assert Ok(Nil) = simplifile.delete(output)
}

pub fn sbom_optional_enrichment_failures_still_exit_zero_test() {
  let #(result, events) =
    licence_audit.run_configured(
      [
        "sbom",
        "--vulns",
        "--manifest=test/fixtures/manifest_github_git.toml",
      ],
      licence_audit.Clients(
        ..test_clients(fn(_) { Error(hex.NetworkFailure("offline")) }),
        osv_batch_fetcher: one_vuln_batch,
        osv_detail_fetcher: fn(_) {
          Error(osv.NetworkFailure("connection refused"))
        },
      ),
      progress.capturing(progress.Normal, "sbom"),
    )

  should.equal(result.exit_code, 0)
  let assert Ok(format) =
    json.parse(result.output, decode.at(["bomFormat"], decode.string))
  should.equal(format, "CycloneDX")
  assert string.contains(
    result.output,
    "\"purl\": \"pkg:hex/gleam_stdlib@1.0.0\"",
  )
  assert string.contains(result.output, "\"id\": \"CVE-2024-0001\"")
  assert string.contains(result.output, "(details unavailable)")
  assert list.any(events, fn(event) {
    event.kind == progress.Warning
    && string.contains(event.message, "No Hex metadata for gleam_stdlib")
  })
  assert list.any(events, fn(event) {
    event.kind == progress.Warning
    && string.contains(event.message, "Failed to fetch OSV details")
  })
}

pub fn sbom_subcommand_output_file_is_formatted_json_test() {
  let path = "build/tmp/sbom-output-file.json"
  let _ = simplifile.create_directory_all("build/tmp")
  let _ = simplifile.delete(path)
  let result =
    licence_audit.run_configured(
      [
        "sbom",
        "--manifest=test/fixtures/manifest_github_git.toml",
        "--output=" <> path,
      ],
      test_clients(sbom_fetcher),
      progress.disabled(),
    ).0
  let assert Ok(contents) = simplifile.read(from: path)
  let assert Ok(bom_format) =
    json.parse(contents, decode.at(["bomFormat"], decode.string))

  should.equal(result.exit_code, 0)
  should.equal(result.output, "")
  should.equal(bom_format, "CycloneDX")
  let assert True = string.contains(contents, "\"bomFormat\": \"CycloneDX\"")
  let assert True = string.contains(contents, "\n  \"metadata\": {")
  let assert True = string.contains(contents, "\n    \"tools\": [")
}

pub fn sbom_subcommand_errors_on_missing_local_metadata_test() {
  let root = "build/tmp/sbom-local-absent-metadata"
  prepare_local_sbom_project(
    root,
    "name = \"local_dep\"\nversion = \"1.0.0\"\n",
    "",
  )
  let assert Ok(_) = simplifile.delete(root <> "/local_dep/gleam.toml")
  let result =
    licence_audit.run_configured(
      ["sbom", "--manifest=" <> root <> "/manifest.toml"],
      test_clients(sbom_fetcher),
      progress.disabled(),
    ).0
  should.equal(result.exit_code, 2)
  let assert True = string.contains(result.output, "local_dep")
  let assert True = string.contains(result.output, "gleam.toml")
  let assert True = string.contains(result.output, "No such file or directory")
  let assert Ok(_) = simplifile.delete(root)
}

fn local_sbom_clients() -> licence_audit.Clients {
  licence_audit.Clients(
    ..test_clients(fn(_) { panic as "offline must not fetch Hex metadata" }),
    publication_fetcher: fn(_, _) {
      panic as "offline must not verify publications over the network"
    },
    osv_batch_fetcher: fn(_) { panic as "offline must not query OSV" },
    osv_detail_fetcher: fn(_) { panic as "offline must not fetch OSV details" },
    notice_clients: notice.Clients(
      ..notice.default_clients(),
      fetch_hex_tarball: fn(_, _) {
        panic as "offline must not fetch Hex archives"
      },
      fetch_git_archive: fn(_, _) {
        panic as "offline must not fetch Git archives"
      },
      fetch_spdx: fn(_) { panic as "offline must not fetch SPDX text" },
    ),
  )
}

fn run_local_sbom(
  root: String,
  flags: List(String),
) -> licence_audit.RunResult {
  licence_audit.run_cli_configured(
    [
      "sbom",
      "--manifest=" <> root <> "/manifest.toml",
      "--cache-dir=" <> root <> "/.cache",
      ..flags
    ],
    local_sbom_clients(),
    progress.disabled(),
  ).0
}

fn warm_local_sbom(root: String) -> Nil {
  let result =
    licence_audit.run_cli_configured(
      [
        "sbom",
        "--reproducible",
        "--manifest=" <> root <> "/manifest.toml",
        "--cache-dir=" <> root <> "/.cache",
      ],
      test_clients(sbom_fetcher),
      progress.disabled(),
    ).0
  should.equal(result.exit_code, 0)
}

fn prepare_local_sbom_workspace() -> String {
  let root = "build/tmp/sbom-local-workspace"
  list.each(
    ["app", "local_parent", "nested/local_child", "local_dev"],
    fn(directory) {
      let assert Ok(_) =
        simplifile.create_directory_all(root <> "/" <> directory)
      let assert Ok(contents) =
        simplifile.read(
          "test/fixtures/sbom_local/" <> directory <> "/gleam.toml.txt",
        )
      let assert Ok(_) =
        simplifile.write(root <> "/" <> directory <> "/gleam.toml", contents)
    },
  )
  let assert Ok(_) =
    simplifile.copy_file(
      "test/fixtures/sbom_local/app/manifest.toml",
      root <> "/app/manifest.toml",
    )
  let assert Ok(locked) = simplifile.read(root <> "/app/manifest.toml")
  let assert Ok(checksum) =
    source_archive.sha256_hex(
      source_archive_test.metadata_archive(["Apache-2.0"]),
    )
  let assert Ok(_) =
    simplifile.write(
      root <> "/app/manifest.toml",
      string.replace(
        locked,
        "0C5506589DF4C63DF5D6FFBB834562D6865C6C2AEE0019D7B37886BD6D128141",
        checksum,
      ),
    )
  root <> "/app"
}

pub fn sbom_local_workspace_offline_graph_scopes_and_metadata_test() {
  let root = prepare_local_sbom_workspace()
  warm_local_sbom(root)
  let assert Ok(parent) =
    sbom.component_ref(manifest.SbomEntry(
      "local_parent",
      "2.0.0",
      [],
      manifest.PathProvenance("../local_parent"),
    ))
  let assert Ok(child) =
    sbom.component_ref(manifest.SbomEntry(
      "local_child",
      "1.2.3",
      [],
      manifest.PathProvenance("../nested/local_child"),
    ))
  let assert Ok(dev) =
    sbom.component_ref(manifest.SbomEntry(
      "local_dev",
      "0.1.0",
      [],
      manifest.PathProvenance("../local_dev"),
    ))
  list.each([["--offline"], ["--offline", "--reproducible"]], fn(flags) {
    let output = run_local_sbom(root, flags)
    should.equal(output.exit_code, 0)
    let assert Ok(components) =
      json.parse(
        output.output,
        decode.at(
          ["components"],
          decode.list({
            use name <- decode.field("name", decode.string)
            use scope <- decode.field("scope", decode.string)
            decode.success(#(name, scope))
          }),
        ),
      )
    should.equal(components, [
      #("local_child", "required"),
      #("local_dev", "optional"),
      #("local_parent", "required"),
      #("gleam_stdlib", "required"),
    ])
    let assert Ok(edges) =
      json.parse(
        output.output,
        decode.at(
          ["dependencies"],
          decode.list({
            use ref <- decode.field("ref", decode.string)
            use children <- decode.field(
              "dependsOn",
              decode.list(decode.string),
            )
            decode.success(#(ref, children))
          }),
        ),
      )
    should.equal(edges, [
      #("root", list.sort([dev, parent], string.compare)),
      #(child, [
        "pkg:hex/gleam_stdlib@1.0.0",
      ]),
      #(dev, ["pkg:hex/gleam_stdlib@1.0.0"]),
      #(parent, [
        child,
        "pkg:hex/gleam_stdlib@1.0.0",
      ]),
      #("pkg:hex/gleam_stdlib@1.0.0", []),
    ])
    assert string.contains(
      output.output,
      "\"description\": \"Local parent package\"",
    )
    assert string.contains(output.output, "\"id\": \"MIT\"")
    assert string.contains(output.output, "\"id\": \"Apache-2.0\"")
    assert string.contains(
      output.output,
      "https://github.com/example/workspace",
    )
    assert !string.contains(output.output, "pkg:hex/local_")
    assert !string.contains(output.output, "unlocked_member_test_tool")
  })
}

fn prepare_local_sbom_project(
  root: String,
  metadata: String,
  requirements: String,
) -> Nil {
  let assert Ok(_) = simplifile.create_directory_all(root <> "/local_dep")
  let assert Ok(_) =
    simplifile.write(
      root <> "/gleam.toml",
      "name = \"app\"\nversion = \"1.0.0\"\n[dependencies]\nlocal_dep = { path = \"local_dep\" }\n",
    )
  let assert Ok(_) =
    simplifile.write(
      root <> "/manifest.toml",
      "packages = [{ name = \"local_dep\", version = \"1.0.0\", source = \"local\", path = \"./local_dep/\", requirements = ["
        <> requirements
        <> "] }]\n[requirements]\nlocal_dep = { path = \"local_dep\" }\n",
    )
  let assert Ok(_) = simplifile.write(root <> "/local_dep/gleam.toml", metadata)
  Nil
}

pub fn sbom_local_invalid_metadata_fails_before_network_or_output_test() {
  let root = "build/tmp/sbom-local-invalid"
  let output = root <> "/existing.json"
  list.each(
    [
      #("name = [", "", "invalid TOML"),
      #("version = \"1.0.0\"\n", "", "required name"),
      #("name = \"local_dep\"\n", "", "required version"),
      #("name = \"wrong\"\nversion = \"1.0.0\"\n", "", "name/version"),
      #("name = \"local_dep\"\nversion = \"2.0.0\"\n", "", "name/version"),
      #("name = \"local_dep\"\nversion = \"\"\n", "", "name/version"),
      #(
        "name = \"local_dep\"\nversion = \"1.0.0\"\nlicences = [1]\n",
        "",
        "invalid description",
      ),
      #(
        "name = \"local_dep\"\nversion = \"1.0.0\"\nlinks = [{ title = \"Docs\" }]\n",
        "",
        "invalid description",
      ),
      #(
        "name = \"local_dep\"\nversion = \"1.0.0\"\nrepository = { type = \"github\", user = \"a b\", repo = \"c\" }\n",
        "",
        "invalid description",
      ),
      #(
        "name = \"local_dep\"\nversion = \"1.0.0\"\nrepository = { type = \"github\" }\n",
        "",
        "invalid description",
      ),
      #(
        "name = \"local_dep\"\nversion = \"1.0.0\"\nlinks = [{ title = \"Docs\", href = \"not a URL\" }]\n",
        "",
        "invalid description",
      ),
      #(
        "name = \"local_dep\"\nversion = \"1.0.0\"\n[dependencies]\nmissing = \"*\"\n",
        "",
        "production dependencies",
      ),
      #(
        "name = \"local_dep\"\nversion = \"1.0.0\"\n[dependencies]\nmissing = \"*\"\n",
        "\"missing\"",
        "is not locked",
      ),
      #(
        "name = \"local_dep\"\nversion = \"1.0.0\"\n[dependencies]\nlocal_dep = { path = \".\" }\n",
        "\"local_dep\"",
        "dependency cycle",
      ),
    ],
    fn(example) {
      prepare_local_sbom_project(root, example.0, example.1)
      let assert Ok(_) = simplifile.write(output, "previous output")
      list.each(
        [[], ["--offline"], ["--reproducible"], ["--reproducible", "--offline"]],
        fn(flags) {
          let result = run_local_sbom(root, ["--output=" <> output, ..flags])
          should.equal(result.exit_code, 2)
          assert string.contains(result.output, "local_dep")
          assert string.contains(result.output, example.2)
          should.equal(simplifile.read(output), Ok("previous output"))
        },
      )
    },
  )
  let assert Ok(_) = simplifile.delete(root)
}

pub fn sbom_local_paths_cycles_and_locked_targets_are_validated_test() {
  let root = prepare_local_sbom_workspace()
  let assert Ok(locked) = manifest.load_sbom(root <> "/manifest.toml")
  list.each(["", "\u{0000}", "../absent"], fn(directory) {
    let altered =
      manifest.SbomManifest(
        ..locked,
        entries: list.map(locked.entries, fn(entry) {
          case entry.name {
            "local_parent" ->
              manifest.SbomEntry(
                ..entry,
                provenance: manifest.PathProvenance(directory),
              )
            _ -> entry
          }
        }),
      )
    let assert Error(error) = sbom.resolve_local(altered, root)
    assert string.contains(licence_audit_error.message(error), "local_parent")
  })
  let altered =
    manifest.SbomManifest(
      ..locked,
      entries: list.map(locked.entries, fn(entry) {
        case entry.name {
          "local_child" ->
            manifest.SbomEntry(
              ..entry,
              provenance: manifest.PathProvenance("../local_dev"),
            )
          _ -> entry
        }
      }),
    )
  let assert Error(error) = sbom.resolve_local(altered, root)
  assert string.contains(
    licence_audit_error.message(error),
    "does not match the lockfile",
  )
  let cyclic =
    manifest.SbomManifest(
      ..locked,
      entries: list.map(locked.entries, fn(entry) {
        case entry.name {
          "gleam_stdlib" ->
            manifest.SbomEntry(..entry, requirements: ["local_parent"])
          _ -> entry
        }
      }),
    )
  let assert Error(error) = sbom.resolve_local(cyclic, root)
  assert string.contains(licence_audit_error.message(error), "dependency cycle")
}

pub fn sbom_local_reproducibility_survives_relocation_and_uses_current_metadata_test() {
  let first_root = "build/tmp/sbom-local-first"
  let second_root = "build/tmp/sbom-local-second"
  let metadata =
    "name = \"local_dep\"\nversion = \"1.0.0\"\nlicences = [\"MIT\"]\n"
  prepare_local_sbom_project(first_root, metadata, "")
  prepare_local_sbom_project(second_root, metadata, "")
  warm_local_sbom(first_root)
  warm_local_sbom(second_root)
  let flags = ["--offline", "--reproducible"]
  let first = run_local_sbom(first_root, flags)
  should.equal(first.exit_code, 0)
  should.equal(run_local_sbom(first_root, flags), first)
  should.equal(run_local_sbom(second_root, flags), first)
  let assert Ok(absolute) = simplifile.resolve(second_root <> "/local_dep")
  let assert Ok(manifest_text) =
    simplifile.read(second_root <> "/manifest.toml")
  let assert Ok(_) =
    simplifile.write(
      second_root <> "/manifest.toml",
      string.replace(manifest_text, "./local_dep/", absolute),
    )
  should.equal(run_local_sbom(second_root, flags), first)
  let assert Ok(_) =
    simplifile.write(first_root <> "/local_dep/source.txt", "source change")
  should.equal(run_local_sbom(first_root, flags), first)
  let assert Ok(_) =
    simplifile.write(
      first_root <> "/local_dep/gleam.toml",
      metadata <> "description = \"changed\"\n",
    )
  let changed = run_local_sbom(first_root, flags)
  should.equal(changed.exit_code, 0)
  assert changed.output != first.output
  assert string.contains(changed.output, "\"description\": \"changed\"")
  let assert Ok(_) = simplifile.delete(first_root)
  let assert Ok(_) = simplifile.delete(second_root)
}

pub fn sbom_local_metadata_survives_enrichment_and_osv_skips_unpublished_locals_test() {
  let root = "build/tmp/sbom-local-enrichment"
  prepare_local_sbom_project(
    root,
    "name = \"local_dep\"\nversion = \"1.0.0\"\nlicences = [\"MIT\"]\n[dependencies]\nhex_dep = \"1.0.0\"\n",
    "\"hex_dep\"",
  )
  let assert Ok(archive) =
    simplifile.read_bits("test/fixtures/sbom_metadata/hex.tar")
  let assert Ok(checksum) = source_archive.sha256_hex(archive)
  let assert Ok(locked) = simplifile.read(root <> "/manifest.toml")
  let assert Ok(_) =
    simplifile.write(
      root <> "/manifest.toml",
      string.replace(
        locked,
        "packages = [",
        "packages = [{ name = \"hex_dep\", version = \"1.0.0\", source = \"hex\", requirements = [], outer_checksum = \""
          <> checksum
          <> "\" }, ",
      ),
    )
  let clients =
    licence_audit.Clients(
      ..test_clients(mutable_registry_metadata),
      notice_clients: notice.Clients(
        ..reproducible_sbom_clients(),
        fetch_spdx: fn(requirement) {
          should.equal(requirement, spdx.LicenseRequirement("MIT"))
          Ok(Some("canonical MIT text"))
        },
      ),
      osv_batch_fetcher: fn(purls) {
        should.equal(purls, ["pkg:hex/hex_dep@1.0.0"])
        Ok([osv.BatchEntry("pkg:hex/hex_dep@1.0.0", [])])
      },
      osv_detail_fetcher: fn(_) { panic as "no advisory details expected" },
    )
  list.each(
    [[], ["--reproducible"], ["--vulns"], ["--license-text"]],
    fn(flags) {
      let result =
        licence_audit.run_configured(
          ["sbom", "--manifest=" <> root <> "/manifest.toml", ..flags],
          clients,
          progress.disabled(),
        ).0
      should.equal(result.exit_code, 0)
      assert string.contains(result.output, "\"id\": \"MIT\"")
      assert !string.contains(result.output, "pkg:hex/local_dep")
      case flags {
        ["--reproducible"] -> {
          assert string.contains(
            result.output,
            "Metadata from the locked Hex archive",
          )
        }
        ["--license-text"] -> {
          assert string.contains(result.output, "canonical MIT text")
        }
        _ -> Nil
      }
    },
  )
  let assert Ok(_) = simplifile.delete(root)
}

pub fn sbom_local_missing_metadata_and_root_path_mismatch_are_errors_test() {
  let root = "build/tmp/sbom-local-missing"
  prepare_local_sbom_project(
    root,
    "name = \"local_dep\"\nversion = \"1.0.0\"\n",
    "",
  )
  let assert Ok(_) = simplifile.delete(root <> "/local_dep/gleam.toml")
  let result = run_local_sbom(root, ["--offline", "--reproducible"])
  should.equal(result.exit_code, 2)
  assert string.contains(result.output, "local_dep/gleam.toml")
  let assert Ok(_) =
    simplifile.create_directory_all(root <> "/local_dep/gleam.toml")
  let result = run_local_sbom(root, ["--offline"])
  should.equal(result.exit_code, 2)
  assert string.contains(result.output, "local_dep/gleam.toml")
  let assert Ok(_) = simplifile.delete(root <> "/local_dep/gleam.toml")
  let assert Ok(_) =
    simplifile.write(
      root <> "/gleam.toml",
      "name = \"app\"\nversion = \"1.0.0\"\n[dependencies]\nlocal_dep = { path = \"different\" }\n",
    )
  let result = run_local_sbom(root, [])
  should.equal(result.exit_code, 2)
  assert string.contains(result.output, "path does not match the lockfile")
  let assert Ok(_) = simplifile.delete(root)
}

pub fn sbom_local_stale_root_edges_fail_before_network_or_output_test() {
  let root = "build/tmp/sbom-local-root-edges"
  let output = root <> "/existing.json"
  use file <- list.each(["gleam.toml", "manifest.toml"])
  prepare_local_sbom_project(
    root,
    "name = \"local_dep\"\nversion = \"1.0.0\"\n",
    "",
  )
  let assert Ok(contents) = simplifile.read(root <> "/" <> file)
  let assert Ok(_) =
    simplifile.write(
      root <> "/" <> file,
      string.replace(contents, "local_dep = { path = \"local_dep\" }\n", ""),
    )
  let assert Ok(_) = simplifile.write(output, "previous output")
  list.each(
    [
      [],
      ["--offline"],
      ["--reproducible"],
      ["--reproducible", "--offline"],
    ],
    fn(flags) {
      let result = run_local_sbom(root, ["--output=" <> output, ..flags])
      should.equal(result.exit_code, 2)
      assert string.contains(result.output, "local_dep")
      assert string.contains(result.output, "direct dependency does not match")
      should.equal(simplifile.read(output), Ok("previous output"))
    },
  )
  let assert Ok(_) = simplifile.delete(root)
}

pub fn sbom_subcommand_errors_on_non_github_git_test() {
  let result =
    licence_audit.run_configured(
      ["sbom", "--manifest=test/fixtures/manifest_non_github_git.toml"],
      test_clients(sbom_fetcher),
      progress.disabled(),
    ).0
  should.equal(result.exit_code, 2)
  let assert True = string.contains(result.output, "gitlab.com")
}

pub fn sbom_subcommand_offline_omits_licenses_test() {
  let result =
    licence_audit.run_configured(
      [
        "sbom",
        "--manifest=test/fixtures/manifest_github_git.toml",
        "--offline",
      ],
      test_clients(sbom_fetcher),
      progress.disabled(),
    ).0
  should.equal(result.exit_code, 0)
  // Offline mode skips the Hex fetch, so dependency components have no
  // licences. The root component still declares its own licence from the
  // local gleam.toml, so allow that single block but no more.
  let license_blocks = list.length(string.split(result.output, "\"licenses\":"))
  let assert True = license_blocks <= 2
}

@external(erlang, "sbom_version_ffi", "with_cwd")
fn with_cwd(dir: String, body: fn() -> a) -> a

fn prepare_sbom_metadata_project(root: String) -> Nil {
  let _ = simplifile.delete(root)
  let assert Ok(Nil) = simplifile.create_directory_all(root)
  let assert Ok(Nil) =
    simplifile.write(
      to: root <> "/manifest.toml",
      contents: "packages = []\n\n[requirements]\n",
    )
  Nil
}

fn run_sbom_metadata_project(root: String) -> licence_audit.RunResult {
  with_cwd(root, fn() {
    licence_audit.run_configured(
      ["sbom", "--manifest=manifest.toml", "--offline"],
      test_clients(sbom_fetcher),
      progress.disabled(),
    ).0
  })
}

pub fn sbom_missing_root_metadata_errors_with_path_test() {
  let root = "build/tmp/sbom-missing-root-metadata"
  prepare_sbom_metadata_project(root)

  let result = run_sbom_metadata_project(root)

  should.equal(result.exit_code, 2)
  assert string.contains(result.output, "Could not read SBOM root metadata")
  assert string.contains(result.output, "./gleam.toml")
  assert !string.contains(result.output, "\"name\": \"project\"")
}

pub fn sbom_unreadable_root_metadata_errors_with_path_test() {
  let root = "build/tmp/sbom-unreadable-root-metadata"
  prepare_sbom_metadata_project(root)
  let assert Ok(Nil) = simplifile.create_directory_all(root <> "/gleam.toml")

  let result = run_sbom_metadata_project(root)

  should.equal(result.exit_code, 2)
  assert string.contains(result.output, "Could not read SBOM root metadata")
  assert string.contains(result.output, "./gleam.toml")
}

pub fn sbom_malformed_root_metadata_errors_with_path_test() {
  let root = "build/tmp/sbom-malformed-root-metadata"
  prepare_sbom_metadata_project(root)
  let assert Ok(Nil) =
    simplifile.write(to: root <> "/gleam.toml", contents: "name = [")

  let result = run_sbom_metadata_project(root)

  should.equal(result.exit_code, 2)
  assert string.contains(result.output, "Could not parse SBOM root metadata")
  assert string.contains(result.output, "./gleam.toml")
}

pub fn sbom_valid_root_metadata_is_emitted_test() {
  let root = "build/tmp/sbom-valid-root-metadata"
  prepare_sbom_metadata_project(root)
  let assert Ok(Nil) =
    simplifile.write(
      to: root <> "/gleam.toml",
      contents: "name = \"valid_project\"\nversion = \"1.2.3\"\n",
    )

  let result = run_sbom_metadata_project(root)
  let assert Ok(name) =
    json.parse(
      result.output,
      decode.at(["metadata", "component", "name"], decode.string),
    )
  let assert Ok(version) =
    json.parse(
      result.output,
      decode.at(["metadata", "component", "version"], decode.string),
    )

  should.equal(result.exit_code, 0)
  should.equal(name, "valid_project")
  should.equal(version, "1.2.3")
}

/// Runs the `sbom` command with the current working directory pointed at a
/// project whose own `gleam.toml` version differs from licence_audit's build
/// version. Regression test for
/// https://github.com/tylerbutler/licence_audit/issues/79: the CycloneDX
/// `metadata.tools[].version` must always be licence_audit's own build
/// version, never leaked from whatever project is being audited.
pub fn sbom_tool_version_is_build_version_not_target_project_version_test() {
  let assert Ok(this_project_gleam_toml) = simplifile.read(from: "gleam.toml")
  let assert Ok(this_project_doc) = toml.parse(this_project_gleam_toml)
  let assert Ok(this_project_version) =
    toml.get_string(this_project_doc, ["version"])

  let project_dir = "build/tmp/sbom-tool-version-project"
  let assert Ok(Nil) = simplifile.create_directory_all(project_dir)
  let assert Ok(Nil) =
    simplifile.write(
      to: project_dir <> "/gleam.toml",
      contents: "name = \"other_project\"\nversion = \"9.9.9\"\n",
    )
  let assert Ok(Nil) =
    simplifile.write(
      to: project_dir <> "/manifest.toml",
      contents: "packages = []\n\n[requirements]\n",
    )

  // `with_cwd` restores the original working directory via an Erlang
  // `after` block even if an assertion inside the closure panics, so a
  // failure here can never corrupt the cwd for later tests.
  let result =
    with_cwd(project_dir, fn() {
      licence_audit.run_configured(
        ["sbom", "--manifest=manifest.toml", "--offline"],
        test_clients(sbom_fetcher),
        progress.disabled(),
      ).0
    })

  should.equal(result.exit_code, 0)

  let assert Ok(component_version) =
    json.parse(
      result.output,
      decode.at(["metadata", "component", "version"], decode.string),
    )
  let assert Ok(tool_versions) =
    json.parse(
      result.output,
      decode.at(
        ["metadata", "tools"],
        decode.list(decode.at(["version"], decode.string)),
      ),
    )
  let assert Ok(tool_version) = list.first(tool_versions)

  // The audited project's own version is reported for the root component...
  should.equal(component_version, "9.9.9")
  // ...but licence_audit's own tool version must come from this build, never
  // from whatever gleam.toml happens to sit in the current working
  // directory.
  should.equal(tool_version, this_project_version)
  let assert True = tool_version != "9.9.9"
}

pub fn sbom_manifest_path_uses_manifest_project_metadata_test() {
  let project_root = "build/tmp/project-root-sbom"
  let manifest_path = project_root <> "/manifest.toml"
  let local_package = project_root <> "/build/packages/git_dep"
  let assert Ok(Nil) = simplifile.create_directory_all(local_package)
  let assert Ok(Nil) =
    simplifile.write(
      to: project_root <> "/gleam.toml",
      contents: "name = \"other_project\"
version = \"1.2.3\"

[dependencies]
git_dep = { git = \"https://github.com/example/git_dep\" }
",
    )
  let assert Ok(Nil) =
    simplifile.write(
      to: local_package <> "/gleam.toml",
      contents: "name = \"git_dep\"
description = \"Metadata from the manifest project\"
licences = [\"MIT\"]
",
    )
  let assert Ok(Nil) =
    simplifile.write(
      to: manifest_path,
      contents: "packages = [
  { name = \"git_dep\", version = \"1.0.0\", source = \"git\", repo = \"https://github.com/example/git_dep\", commit = \"abc\" },
]

[requirements]
git_dep = { git = \"https://github.com/example/git_dep\" }
",
    )

  let result =
    licence_audit.run_configured(
      [
        "sbom",
        "--manifest=" <> path_test.absolute_native_path(manifest_path),
        "--offline",
      ],
      test_clients(sbom_fetcher),
      progress.disabled(),
    ).0
  let assert Ok(root_name) =
    json.parse(
      result.output,
      decode.at(["metadata", "component", "name"], decode.string),
    )

  should.equal(result.exit_code, 0)
  should.equal(root_name, "other_project")
  assert string.contains(
    result.output,
    "\"description\": \"Metadata from the manifest project\"",
  )
  assert string.contains(result.output, "\"id\": \"MIT\"")
}

pub fn sbom_subcommand_with_vulns_embeds_vulnerabilities_test() {
  let licence_audit.RunResult(exit_code, output) =
    licence_audit.run_configured(
      [
        "sbom",
        "--vulns",
        "--manifest=test/fixtures/manifest_github_git.toml",
      ],
      licence_audit.Clients(
        ..test_clients(sbom_fetcher),
        osv_batch_fetcher: one_vuln_batch,
        osv_detail_fetcher: one_vuln_detail,
      ),
      progress.disabled(),
    ).0

  should.equal(exit_code, 0)
  // stdout is pretty-printed, so keys are followed by ": ".
  assert string.contains(output, "\"vulnerabilities\": [")
  assert string.contains(output, "\"id\": \"CVE-2024-0001\"")
  assert string.contains(
    output,
    "\"url\": \"https://osv.dev/vulnerability/CVE-2024-0001\"",
  )
  assert string.contains(output, "\"method\": \"CVSSv31\"")
  // The advisory affects the Hex component's bom-ref (purl).
  assert string.contains(output, "pkg:hex/gleam_stdlib@1.0.0")
}

pub fn sbom_subcommand_vulns_conflicts_with_offline_test() {
  let result =
    licence_audit.run_configured(
      [
        "sbom",
        "--vulns",
        "--offline",
        "--manifest=test/fixtures/manifest_github_git.toml",
      ],
      test_clients(sbom_fetcher),
      progress.disabled(),
    ).0

  should.equal(result.exit_code, 2)
  assert string.contains(result.output, "--offline")
}

fn reproducible_sbom_clients() -> notice.Clients {
  notice.Clients(
    fetch_hex_tarball: fn(name, version) {
      should.equal(name, "hex_dep")
      should.equal(version, "1.0.0")
      simplifile.read_bits("test/fixtures/sbom_metadata/hex.tar")
      |> result.replace_error(notice.FetchNetworkFailure)
    },
    fetch_git_archive: fn(_repo, commit) {
      should.equal(commit, "abcdef")
      simplifile.read_bits("test/fixtures/sbom_metadata/git.tar.gz")
      |> result.replace_error(notice.FetchNetworkFailure)
    },
    resolve_commit: fn(_repo, _tag) { Ok(None) },
    fetch_repo_archive: fn(_repo, _commit) { Error(notice.FetchNetworkFailure) },
    fetch_spdx_index: fn(_kind) { Error(notice.FetchNetworkFailure) },
    fetch_spdx: fn(_requirement) { Error(notice.FetchNetworkFailure) },
  )
}

pub fn sbom_licence_text_spellings_produce_identical_reproducible_output_test() {
  let root = "build/sbom-licence-text-alias"
  let assert Ok(Nil) = simplifile.create_directory_all(root)
  let assert Ok(archive) =
    simplifile.read_bits("test/fixtures/sbom_metadata/hex.tar")
  let assert Ok(checksum) = source_archive.sha256_hex(archive)
  let assert Ok(Nil) =
    simplifile.write(
      to: root <> "/gleam.toml",
      contents: "name = \"fixture\"\nversion = \"1.0.0\"\n",
    )
  let assert Ok(Nil) =
    simplifile.write(
      to: root <> "/manifest.toml",
      contents: "packages = [{ name = \"hex_dep\", version = \"1.0.0\", source = \"hex\", outer_checksum = \""
        <> checksum
        <> "\" }]\n[requirements]\nhex_dep = \"1.0.0\"\n",
    )
  let args = [
    "sbom",
    "--reproducible",
    "--manifest=" <> root <> "/manifest.toml",
  ]
  let clients =
    licence_audit.Clients(
      ..test_clients(fn(_) { panic as "must use locked metadata" }),
      notice_clients: notice.Clients(
        ..reproducible_sbom_clients(),
        fetch_spdx: fn(_) { Ok(Some("Canonical SPDX text\n")) },
      ),
    )
  use suffix <- list.each(["", "=true", "=false"])
  let primary =
    licence_audit.run_configured(
      list.append(args, ["--licence-text" <> suffix]),
      clients,
      progress.disabled(),
    ).0
  let alias =
    licence_audit.run_configured(
      list.append(args, ["--license-text" <> suffix]),
      clients,
      progress.disabled(),
    ).0
  should.equal(primary.exit_code, 0)
  should.equal(alias, primary)
  should.equal(
    string.contains(primary.output, "Canonical SPDX text\\n"),
    suffix != "=false",
  )
}

pub fn git_subdirectory_sbom_and_notices_use_selected_package_test() {
  source_archive_test.with_beryl_archive(fn(bytes) {
    let root = "build/tmp/git-subdirectory-integration"
    let manifest_path = root <> "/manifest.toml"
    let assert Ok(Nil) = simplifile.create_directory_all(root)
    let assert Ok(manifest_text) =
      simplifile.read("test/fixtures/manifest_git_subdirectories.toml")
    let assert Ok(Nil) =
      simplifile.write(contents: manifest_text, to: manifest_path)
    let assert Ok(Nil) =
      simplifile.write(
        contents: "name = \"fixture\"\nversion = \"1.0.0\"\n[dependencies]\nberyl_protocol = \"1.0.0\"\nberyl_sibling = \"1.0.0\"\n",
        to: root <> "/gleam.toml",
      )
    let clients =
      licence_audit.Clients(
        ..test_clients(mutable_registry_metadata),
        notice_clients: notice.Clients(
          ..reproducible_sbom_clients(),
          fetch_git_archive: fn(repo, commit) {
            should.equal(
              repo,
              repository.Repository(repository.GitHub, "example", "beryl"),
            )
            should.equal(commit, "abcdef")
            Ok(bytes)
          },
        ),
      )
    let sbom =
      licence_audit.run_configured(
        ["sbom", "--reproducible", "--manifest=" <> manifest_path],
        clients,
        progress.disabled(),
      ).0
    should.equal(sbom.exit_code, 0)
    assert string.contains(sbom.output, "Selected protocol metadata")
    assert string.contains(sbom.output, "Sibling package metadata")
    assert string.contains(sbom.output, "\"id\": \"MIT\"")
    assert string.contains(sbom.output, "\"id\": \"Apache-2.0\"")
    assert !string.contains(sbom.output, "Repository root metadata")
    assert string.contains(
      sbom.output,
      "pkg:github/example/beryl@abcdef#packages/beryl_protocol",
    )
    assert string.contains(
      sbom.output,
      "pkg:github/example/beryl@abcdef#packages/beryl_sibling",
    )
    should.equal(
      licence_audit.run_configured(
        ["sbom", "--reproducible", "--manifest=" <> manifest_path],
        clients,
        progress.disabled(),
      ).0,
      sbom,
    )
    let notices =
      licence_audit.run_configured(
        ["notices", "--manifest=" <> manifest_path],
        clients,
        progress.disabled(),
      ).0
    should.equal(notices.exit_code, 0)
    assert string.contains(notices.output, "Protocol licence")
    assert string.contains(notices.output, "Protocol attribution")
    assert string.contains(notices.output, "Sibling licence")
    assert !string.contains(notices.output, "Repository root licence")
    assert !string.contains(notices.output, "Vendored licence")
    assert !string.contains(notices.output, "Prefix sibling licence")
  })
}

pub fn reproducible_git_subdirectory_missing_metadata_is_error_test() {
  source_archive_test.with_beryl_archive(fn(bytes) {
    let root = "build/tmp/git-subdirectory-missing-metadata"
    let assert Ok(Nil) = simplifile.create_directory_all(root)
    let assert Ok(Nil) =
      simplifile.write(
        contents: "name = \"fixture\"\nversion = \"1.0.0\"\n",
        to: root <> "/gleam.toml",
      )
    let assert Ok(Nil) =
      simplifile.write(
        contents: "packages = [{ name = \"notice_only\", version = \"1.0.0\", source = \"git\", repo = \"https://github.com/example/beryl\", commit = \"abcdef\", path = \"packages/notice_only\" }]\n[requirements]\nnotice_only = \"1.0.0\"\n",
        to: root <> "/manifest.toml",
      )
    let output =
      licence_audit.run_configured(
        ["sbom", "--reproducible", "--manifest=" <> root <> "/manifest.toml"],
        licence_audit.Clients(
          ..test_clients(mutable_registry_metadata),
          notice_clients: notice.Clients(
            ..reproducible_sbom_clients(),
            fetch_git_archive: fn(_repo, _commit) { Ok(bytes) },
          ),
        ),
        progress.disabled(),
      ).0
    should.equal(output.exit_code, 2)
    assert string.contains(output.output, "notice_only")
    assert string.contains(output.output, "archive missing root file")
    assert !string.contains(output.output, "Repository root metadata")
  })
}

fn mutable_registry_metadata(
  _name: String,
) -> Result(hex.PackageMetadata, hex.Error) {
  Ok(hex.PackageMetadata(
    licences: ["MUTABLE"],
    description: Some("Mutable registry metadata"),
    links: [#("Live Playground", "https://example.com/mutable")],
    publisher: Some("Mutable Owner"),
  ))
}

pub fn sbom_reproducible_uses_locked_source_metadata_test() {
  let root = "build/tmp/reproducible-sbom-metadata"
  let manifest_path = root <> "/manifest.toml"
  let local_git_path = root <> "/build/packages/git_dep"
  let assert Ok(Nil) = simplifile.create_directory_all(local_git_path)
  let assert Ok(hex_archive) =
    simplifile.read_bits("test/fixtures/sbom_metadata/hex.tar")
  let assert Ok(checksum) = source_archive.sha256_hex(hex_archive)
  let assert Ok(Nil) =
    simplifile.write(
      to: root <> "/gleam.toml",
      contents: "name = \"fixture\"\nversion = \"1.0.0\"\n",
    )
  let assert Ok(Nil) =
    simplifile.write(
      to: local_git_path <> "/gleam.toml",
      contents: "name = \"git_dep\"\ndescription = \"Mutable local checkout\"\n",
    )
  let assert Ok(Nil) =
    simplifile.write(to: manifest_path, contents: "packages = [
  { name = \"hex_dep\", version = \"1.0.0\", source = \"hex\", outer_checksum = \"" <> checksum <> "\" },
  { name = \"git_dep\", version = \"2.0.0\", source = \"git\", repo = \"https://github.com/example/git_dep\", commit = \"abcdef\" },
]

[requirements]
hex_dep = \"1.0.0\"
git_dep = { git = \"https://github.com/example/git_dep\" }
")

  let first =
    licence_audit.run_configured(
      ["sbom", "--reproducible", "--manifest=" <> manifest_path],
      licence_audit.Clients(
        ..test_clients(mutable_registry_metadata),
        notice_clients: reproducible_sbom_clients(),
      ),
      progress.disabled(),
    ).0
  let assert Ok(Nil) =
    simplifile.write(
      to: local_git_path <> "/gleam.toml",
      contents: "name = \"git_dep\"\ndescription = \"Changed local checkout\"\n",
    )
  let second =
    licence_audit.run_configured(
      ["sbom", "--reproducible", "--manifest=" <> manifest_path],
      licence_audit.Clients(
        ..test_clients(mutable_registry_metadata),
        notice_clients: reproducible_sbom_clients(),
      ),
      progress.disabled(),
    ).0

  should.equal(first.exit_code, 0)
  should.equal(second, first)
  assert string.contains(first.output, "Metadata from the locked Hex archive")
  assert string.contains(first.output, "中文")
  assert string.contains(first.output, "Metadata from the locked Git archive")
  assert string.contains(first.output, "\"id\": \"Apache-2.0\"")
  assert string.contains(first.output, "\"id\": \"MIT\"")
  assert string.contains(first.output, "https://github.com/example/hex_dep")
  assert string.contains(first.output, "https://github.com/example/git_dep")
  assert !string.contains(first.output, "Mutable registry metadata")
  assert !string.contains(first.output, "Mutable local checkout")
  assert !string.contains(first.output, "Changed local checkout")
  assert !string.contains(first.output, "\"publisher\"")
}

pub fn sbom_reproducible_offline_requires_locked_metadata_test() {
  let root = "build/sbom-reproducible-offline"
  let local_git_path = root <> "/build/packages/gluegun"
  let assert Ok(_) = simplifile.create_directory_all(local_git_path)
  let assert Ok(manifest) =
    simplifile.read("test/fixtures/manifest_github_git.toml")
  let assert Ok(_) =
    simplifile.write(to: root <> "/manifest.toml", contents: manifest)
  let assert Ok(_) =
    simplifile.write(
      to: root <> "/gleam.toml",
      contents: "name = \"fixture\"\nversion = \"1.0.0\"\n",
    )
  let assert Ok(_) =
    simplifile.write(
      to: local_git_path <> "/gleam.toml",
      contents: "licences = [\"MIT\"]\ndescription = \"Local Git enrichment\"\n",
    )
  let result =
    licence_audit.run_configured(
      [
        "sbom",
        "--reproducible",
        "--offline",
        "--manifest=" <> root <> "/manifest.toml",
      ],
      licence_audit.Clients(
        ..test_clients(fn(_) { panic as "must not fetch Hex metadata" }),
        notice_clients: notice.Clients(
          ..reproducible_sbom_clients(),
          fetch_hex_tarball: fn(_, _) { panic as "must not fetch Hex archive" },
          fetch_git_archive: fn(_, _) { panic as "must not fetch Git archive" },
        ),
      ),
      progress.disabled(),
    ).0

  should.equal(result.exit_code, 2)
  assert string.contains(result.output, "offline: required locked metadata")
  assert !string.contains(result.output, "Local Git enrichment")
  let assert Ok(_) = simplifile.delete(root)
}

pub fn sbom_subcommand_vulns_conflicts_with_reproducible_test() {
  let result =
    licence_audit.run_configured(
      [
        "sbom",
        "--vulns",
        "--reproducible",
        "--manifest=test/fixtures/manifest_github_git.toml",
      ],
      test_clients(sbom_fetcher),
      progress.disabled(),
    ).0

  should.equal(result.exit_code, 2)
  assert string.contains(result.output, "--reproducible")
}

fn one_vuln_batch(
  purls: List(String),
) -> Result(List(osv.BatchEntry), osv.Error) {
  Ok(
    list.map(purls, fn(purl) {
      osv.BatchEntry(purl: purl, vuln_ids: ["CVE-2024-0001"])
    }),
  )
}

fn one_vuln_detail(_id: String) -> Result(osv.Vulnerability, osv.Error) {
  Ok(
    osv.Vulnerability(
      aliases: [],
      id: "CVE-2024-0001",
      summary: "example",
      severity: osv.High,
      affected: [],
      scores: [
        osv.Score(
          kind: "CVSS_V3",
          vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        ),
      ],
    ),
  )
}

pub fn vulns_report_labels_scope_test() {
  let licence_audit.RunResult(exit_code, output) =
    licence_audit.run_configured(
      ["vulns", "--manifest=test/fixtures/manifest_github_git.toml"],
      licence_audit.Clients(
        ..test_clients(fake_fetcher),
        osv_batch_fetcher: one_vuln_batch,
        osv_detail_fetcher: one_vuln_detail,
      ),
      progress.disabled(),
    ).0

  should.equal(exit_code, 0)
  assert string.contains(output, "gleam_stdlib")
  assert string.contains(output, "[prod]")
}

pub fn sbom_color_modes_preserve_plain_json_payload_test() {
  let root = "build/tmp/sbom-color"
  prepare_sbom_metadata_project(root)
  let assert Ok(_) =
    simplifile.write(
      root <> "/gleam.toml",
      "name = \"color_fixture\"\nversion = \"1.0.0\"\n",
    )
  let args = [
    "sbom",
    "--manifest=" <> root <> "/manifest.toml",
    "--offline",
    "--reproducible",
  ]
  let plain =
    licence_audit.run_configured(
      list.append(args, ["--color=never"]),
      test_clients(fake_fetcher),
      progress.disabled(),
    ).0
  let forced =
    licence_audit.run_configured(
      list.append(args, ["--colour=always"]),
      test_clients(fake_fetcher),
      progress.disabled(),
    ).0
  should.equal(plain.exit_code, 0)
  should.equal(forced, plain)
  assert string.contains(plain.output, "\"bomFormat\"")
  assert !string.contains(plain.output, "\u{001b}[")
  let assert Ok(_) = simplifile.delete(root)
}

pub fn vulns_reuses_shared_advisory_details_test() {
  reset_detail_fetch("CVE-2024-0001")
  let result =
    licence_audit.run_configured(
      [
        "vulns",
        "--manifest=test/fixtures/manifest_github_git.toml",
        "--ignore-config",
      ],
      licence_audit.Clients(
        ..test_clients(fake_fetcher),
        osv_batch_fetcher: one_vuln_batch,
        osv_detail_fetcher: fn(id) {
          should.equal(record_detail_fetch(id), 1)
          one_vuln_detail(id)
        },
      ),
      progress.disabled(),
    ).0
  should.equal(result.exit_code, 0)
  assert string.contains(result.output, "gleam_stdlib")
  assert string.contains(result.output, "gluegun")
  should.equal(list.length(string.split(result.output, "CVE-2024-0001")), 3)
}

pub fn vulns_reuses_shared_advisory_failures_test() {
  reset_detail_fetch("CVE-2024-0001")
  let #(result, events) =
    licence_audit.run_configured(
      [
        "vulns",
        "--manifest=test/fixtures/manifest_github_git.toml",
        "--ignore-config",
      ],
      licence_audit.Clients(
        ..test_clients(fake_fetcher),
        osv_batch_fetcher: one_vuln_batch,
        osv_detail_fetcher: fn(id) {
          should.equal(record_detail_fetch(id), 1)
          Error(osv.NetworkFailure("connection refused"))
        },
      ),
      progress.capturing(progress.Verbose, "vulns"),
    )
  should.equal(result.exit_code, 0)
  should.equal(
    list.length(string.split(result.output, "(details unavailable)")),
    3,
  )
  let warnings =
    list.filter(events, fn(event) {
      string.contains(event.message, "Failed to fetch OSV details")
    })
  should.equal(list.length(warnings), 1)
}

fn write_project_root_fixture(project_root: String) -> String {
  let manifest_path = project_root <> "/manifest.toml"
  let assert Ok(Nil) = simplifile.create_directory_all(project_root)
  let assert Ok(Nil) =
    simplifile.write(
      to: project_root <> "/gleam.toml",
      contents: "name = \"other_project\"
version = \"1.2.3\"

[dependencies]
prod_dep = \">= 1.0.0\"

[dev-dependencies]
dev_dep = \">= 1.0.0\"

[tools.licence_audit]
allow = [\"MIT\", \"AGPL-3.0\"]
",
    )
  let assert Ok(Nil) =
    simplifile.write(
      to: manifest_path,
      contents: "packages = [
  { name = \"prod_dep\", version = \"1.0.0\", source = \"hex\", outer_checksum = \"4C4C81A8F753EE1917FCC9C611745DBB1F8730F2A8B7A1BBDBC9A6B1C69F7A66\" },
  { name = \"dev_dep\", version = \"1.0.0\", source = \"hex\", outer_checksum = \"B6A799B33DDCB78EDB6A17EA45D24813304C77E8C132E0D44B374529E6334956\" },
]

[requirements]
prod_dep = { version = \">= 1.0.0\" }
dev_dep = { version = \">= 1.0.0\" }
",
    )
  manifest_path
}

fn project_root_fetcher(
  name: String,
) -> Result(hex.PackageMetadata, hex.Error) {
  case name {
    "prod_dep" -> Ok(hex.licences_only(["MIT"]))
    "dev_dep" -> Ok(hex.licences_only(["AGPL-3.0"]))
    _ -> Error(hex.NotFound)
  }
}

pub fn audit_manifest_path_uses_manifest_project_config_test() {
  let manifest_path =
    write_project_root_fixture("build/tmp/project-root-audit-config")
    |> path_test.absolute_native_path
  let result =
    licence_audit.run_configured(
      ["--manifest=" <> manifest_path, "check"],
      test_clients(project_root_fetcher),
      progress.disabled(),
    ).0

  should.equal(result.exit_code, 0)
}

pub fn audit_manifest_path_uses_manifest_project_for_scope_test() {
  let manifest_path =
    write_project_root_fixture("build/tmp/project-root-audit-scope")
  let result =
    licence_audit.run_configured(
      [
        "--manifest=" <> manifest_path,
        "check",
        test_policy.flag(["MIT", "AGPL-3.0"], []),
        "--scope=prod",
      ],
      test_clients(project_root_fetcher),
      progress.disabled(),
    ).0

  should.equal(result.exit_code, 0)
  assert string.contains(result.output, "prod_dep")
  assert !string.contains(result.output, "dev_dep")
}

fn project_root_vuln_batch(
  purls: List(String),
) -> Result(List(osv.BatchEntry), osv.Error) {
  Ok(
    list.map(purls, fn(purl) {
      let id = case string.contains(purl, "prod_dep") {
        True -> "CVE-PROD"
        False -> "CVE-DEV"
      }
      osv.BatchEntry(purl: purl, vuln_ids: [id])
    }),
  )
}

pub fn vulns_manifest_path_uses_manifest_project_for_scope_test() {
  let manifest_path =
    write_project_root_fixture("build/tmp/project-root-vulns-scope")
  let result =
    licence_audit.run_configured(
      ["vulns", "--manifest=" <> manifest_path],
      licence_audit.Clients(
        ..test_clients(project_root_fetcher),
        osv_batch_fetcher: project_root_vuln_batch,
        osv_detail_fetcher: dev_only_vuln_detail,
      ),
      progress.disabled(),
    ).0

  should.equal(result.exit_code, 0)
  assert string.contains(result.output, "prod_dep 1.0.0  [prod]")
  assert string.contains(result.output, "dev_dep 1.0.0  [dev]")
}

fn prod_dev_fetcher(name: String) -> Result(hex.PackageMetadata, hex.Error) {
  case name {
    "gleam_stdlib" -> Ok(hex.licences_only(["MIT"]))
    // A denied licence on the dev dependency.
    "gleeunit" -> Ok(hex.licences_only(["AGPL-3.0"]))
    _ -> Error(hex.NotFound)
  }
}

pub fn check_fails_on_dev_dependency_violation_by_default_test() {
  let licence_audit.RunResult(exit_code, _output) =
    licence_audit.run_configured(
      [
        "--manifest=test/fixtures/prod_dev_manifest.toml",
        "check",
        test_policy.flag(["MIT"], ["AGPL-3.0"]),
      ],
      test_clients(prod_dev_fetcher),
      progress.disabled(),
    ).0

  should.equal(exit_code, 1)
}

pub fn check_prod_scope_ignores_dev_dependency_violation_test() {
  let licence_audit.RunResult(exit_code, output) =
    licence_audit.run_configured(
      [
        "--manifest=test/fixtures/prod_dev_manifest.toml",
        "check",
        test_policy.flag(["MIT"], ["AGPL-3.0"]),
        "--scope=prod",
      ],
      test_clients(prod_dev_fetcher),
      progress.disabled(),
    ).0

  should.equal(exit_code, 0)
  assert string.contains(output, "gleam_stdlib")
  assert !string.contains(output, "gleeunit")
}

fn dev_only_vuln_batch(
  purls: List(String),
) -> Result(List(osv.BatchEntry), osv.Error) {
  Ok(
    list.map(purls, fn(purl) {
      let vuln_ids = case string.contains(purl, "gleeunit") {
        True -> ["CVE-DEV-0001"]
        False -> []
      }
      osv.BatchEntry(purl: purl, vuln_ids: vuln_ids)
    }),
  )
}

fn dev_only_vuln_detail(id: String) -> Result(osv.Vulnerability, osv.Error) {
  Ok(
    osv.Vulnerability(
      aliases: [],
      id: id,
      summary: "dev dependency advisory",
      severity: osv.High,
      scores: [],
      affected: [],
    ),
  )
}

pub fn check_prod_scope_vulns_ignores_dev_dependency_advisory_test() {
  let licence_audit.RunResult(exit_code, output) =
    licence_audit.run_configured(
      [
        "--manifest=test/fixtures/prod_dev_manifest.toml",
        "check",
        test_policy.flag(["MIT"], []),
        "--scope=prod",
        "--checks=all",
      ],
      licence_audit.Clients(
        ..test_clients(prod_dev_fetcher),
        osv_batch_fetcher: dev_only_vuln_batch,
        osv_detail_fetcher: dev_only_vuln_detail,
      ),
      progress.disabled(),
    ).0

  should.equal(exit_code, 0)
  assert string.contains(output, "gleam_stdlib")
  assert string.contains(
    output,
    "No known vulnerabilities reported by OSV.dev.",
  )
  assert !string.contains(output, "gleeunit")
  assert !string.contains(output, "CVE-DEV-0001")
  assert !string.contains(output, "Vulnerability check failed")
}

pub fn gleam_toml_metadata_parses_fields_test() {
  let contents =
    "
name = \"glint_markdown\"
version = \"0.0.0\"
description = \"Markdown for glint\"
licences = [\"Apache-2.0\"]
repository = { type = \"github\", user = \"upstream\", repo = \"glint_markdown\" }
"
  let assert Ok(meta) =
    gleam_toml.package_metadata(
      contents,
      "https://github.com/tylerbutler/glint_markdown",
    )
  should.equal(meta.description, Some("Markdown for glint"))
  should.equal(meta.licences, ["Apache-2.0"])
  should.equal(meta.publisher, None)
  // The repository link uses the manifest repo (the actual source), not the
  // `repository` table in gleam.toml, which may point at an upstream project.
  should.equal(meta.links, [
    #("Repository", "https://github.com/tylerbutler/glint_markdown"),
  ])
}

pub fn gleam_toml_metadata_includes_links_and_dedups_repo_test() {
  let contents =
    "
links = [
  { title = \"Hex\", href = \"https://hex.pm/packages/glint\" },
  { title = \"Repository\", href = \"https://github.com/tylerbutler/glint.git\" },
]
"
  let assert Ok(meta) =
    gleam_toml.package_metadata(
      contents,
      "https://github.com/tylerbutler/glint",
    )
  // The explicit Hex link is preserved; the repository link is not duplicated
  // because an existing link already points at it (ignoring a `.git` suffix).
  should.equal(meta.links, [
    #("Hex", "https://hex.pm/packages/glint"),
    #("Repository", "https://github.com/tylerbutler/glint.git"),
  ])
}

pub fn sbom_git_dep_without_local_source_falls_back_to_repo_link_test() {
  let #(result, events) =
    licence_audit.run_configured(
      ["sbom", "--manifest=test/fixtures/manifest_github_git.toml"],
      test_clients(sbom_fetcher),
      progress.capturing(progress.Normal, "report"),
    )
  should.equal(result.exit_code, 0)
  // gluegun has no local build/packages checkout, so enrichment falls back to a
  // vcs reference built from the manifest repo URL.
  let assert True =
    string.contains(
      result.output,
      "\"url\": \"https://github.com/tylerbutler/gluegun\"",
    )
  let assert True = string.contains(result.output, "\"type\": \"vcs\"")
  // ...and a warning records that the richer local metadata was unavailable.
  let assert True =
    list.any(events, fn(event) {
      case event {
        progress.Event(progress.Warning, message) ->
          string.contains(message, "gluegun")
        _ -> False
      }
    })
}

// --- Direct command metadata resolution for local git/path gleam.toml --------

/// Clients whose SPDX fallback synthesizes MIT text; git/hex/repository fetchers
/// are supplied per test. Used to prove declared licences read from a local
/// `gleam.toml` drive the SPDX fallback for git and path dependencies.
fn mit_spdx_clients(
  git_archive: fn(repository.Repository, String) ->
    Result(BitArray, notice.FetchError),
) -> notice.Clients {
  notice.Clients(
    fetch_hex_tarball: fn(_name, _version) { Error(notice.FetchNetworkFailure) },
    fetch_git_archive: git_archive,
    resolve_commit: fn(_repo, _tag) { Ok(None) },
    fetch_repo_archive: fn(_repo, _commit) { Error(notice.FetchNetworkFailure) },
    fetch_spdx_index: fn(kind) {
      case kind {
        spdx.LicenceIndex -> Ok(["MIT"])
        spdx.ExceptionIndex -> Ok([])
      }
    },
    fetch_spdx: fn(_requirement) { Ok(Some("SYNTHESIZED MIT CANONICAL TEXT")) },
  )
}

pub fn notices_path_dep_uses_declared_licence_from_gleam_toml_test() {
  let root = "build/tmp/notices-path-meta"
  let _ = simplifile.delete(root)
  let assert Ok(Nil) = simplifile.create_directory_all(root <> "/local_dep")
  // The path dependency ships only a NOTICE file — no licence text — so the
  // declared licence in its gleam.toml must drive the SPDX fallback.
  let assert Ok(Nil) =
    simplifile.write(
      to: root <> "/local_dep/NOTICE.txt",
      contents: "Local notice\n",
    )
  let assert Ok(Nil) =
    simplifile.write(
      to: root <> "/local_dep/gleam.toml",
      contents: "name = \"local_dep\"\nlicences = [\"MIT\"]\n",
    )
  let manifest_path = root <> "/manifest.toml"
  let assert Ok(Nil) =
    simplifile.write(
      to: manifest_path,
      contents: "packages = [
  { name = \"local_dep\", version = \"0.1.0\", source = \"local\", path = \"local_dep\" },
]

[requirements]
local_dep = { version = \">= 0.0.0\" }
",
    )

  let result =
    licence_audit.run_configured(
      ["notices", "--manifest=" <> manifest_path, "--no-cache"],
      licence_audit.Clients(
        ..test_clients(notice_metadata_fetcher),
        notice_clients: mit_spdx_clients(unused_git_archive),
      ),
      progress.disabled(),
    ).0

  should.equal(result.exit_code, 0)
  assert string.contains(result.output, "Declared licences: MIT")
  assert string.contains(result.output, "SPDX-License-List/MIT.txt")
  assert string.contains(result.output, "SYNTHESIZED MIT CANONICAL TEXT")
  assert string.contains(result.output, "NOTICE.txt")
}

pub fn notices_local_package_result_is_unchanged_after_build_test() {
  let root = "build/tmp/notices-local-generated-build"
  let _ = simplifile.delete(root)
  let dependency = root <> "/local"
  let assert Ok(_) = simplifile.create_directory_all(dependency)
  let assert Ok(_) =
    simplifile.write(
      "licences = [\"LicenseRef-Custom\"]\n",
      to: dependency <> "/gleam.toml",
    )
  let assert Ok(_) =
    simplifile.write(
      "packages = [{ name = \"widget\", version = \"1.0.0\", source = \"local\", path = \"local\" }]\n[requirements]\nwidget = \"1.0.0\"\n",
      to: root <> "/manifest.toml",
    )
  let args = [
    "notices",
    "--manifest=" <> root <> "/manifest.toml",
    "--no-cache",
  ]
  let clients =
    licence_audit.Clients(
      ..test_clients(notice_metadata_fetcher),
      notice_clients: mit_spdx_clients(unused_git_archive),
    )
  let before =
    licence_audit.run_configured(args, clients, progress.disabled()).0
  should.equal(before.exit_code, 2)
  assert string.contains(
    before.output,
    "Missing licence text for packages: widget",
  )
  let assert Ok(_) =
    simplifile.create_directory_all(dependency <> "/build/packages/third_party")
  let assert Ok(_) =
    simplifile.write(
      "Wrong dependency licence",
      to: dependency <> "/build/packages/third_party/LICENSE",
    )
  should.equal(
    licence_audit.run_configured(args, clients, progress.disabled()).0,
    before,
  )
  let assert Ok(_) = simplifile.create_directory_all(dependency <> "/legal")
  let assert Ok(_) =
    simplifile.write("Package licence", to: dependency <> "/legal/LICENSE")
  let legal = licence_audit.run_configured(args, clients, progress.disabled()).0
  should.equal(legal.exit_code, 0)
  assert string.contains(legal.output, "Package licence")
  assert !string.contains(legal.output, "Wrong dependency licence")
  let assert Ok(_) = simplifile.delete(root)
}

pub fn notices_git_dep_uses_locked_declaration_without_checkout_test() {
  assert_notices_locked_git_metadata("")
}

pub fn notices_git_subdirectory_uses_package_not_root_declaration_test() {
  assert_notices_locked_git_metadata("packages/git_dep")
}

fn assert_notices_locked_git_metadata(directory: String) {
  let git_source =
    source_archive_test.with_tar_gz(
      case directory {
        "" -> [
          #("repo/gleam.toml", <<"licences = [\"MIT\"]\n":utf8>>),
          #("repo/NOTICE.txt", <<"Locked attribution":utf8>>),
        ]
        _ -> [
          #("repo/gleam.toml", <<"licences = [\"Apache-2.0\"]\n":utf8>>),
          #("repo/" <> directory <> "/gleam.toml", <<
            "licences = [\"MIT\"]\n":utf8,
          >>),
          #("repo/" <> directory <> "/NOTICE.txt", <<"Locked attribution":utf8>>),
        ]
      },
      fn(bytes) { bytes },
    )
  let root =
    "build/tmp/notices-git-meta/"
    <> case directory {
      "" -> "root"
      _ -> "subdirectory"
    }
  let _ = simplifile.delete(root)
  let assert Ok(Nil) = simplifile.create_directory_all(root)
  let manifest_path = root <> "/manifest.toml"
  let assert Ok(Nil) =
    simplifile.write(to: manifest_path, contents: "packages = [
  { name = \"git_dep\", version = \"1.0.0\", source = \"git\", repo = \"https://github.com/example/git_dep\", commit = \"abc\"" <> case
      directory
    {
      "" -> ""
      _ -> ", path = \"" <> directory <> "\""
    } <> " },
]

[requirements]
git_dep = { version = \">= 0.0.0\" }
")

  let git_archive = fn(repo: repository.Repository, commit: String) {
    should.equal(
      repo,
      repository.Repository(repository.GitHub, "example", "git_dep"),
    )
    should.equal(commit, "abc")
    Ok(git_source)
  }

  let result =
    licence_audit.run_configured(
      ["notices", "--manifest=" <> manifest_path, "--no-cache"],
      licence_audit.Clients(
        ..test_clients(notice_metadata_fetcher),
        notice_clients: mit_spdx_clients(git_archive),
      ),
      progress.disabled(),
    ).0

  should.equal(result.exit_code, 0)
  assert string.contains(result.output, "Declared licences: MIT")
  assert string.contains(result.output, "SPDX-License-List/MIT.txt")
  assert string.contains(result.output, "SYNTHESIZED MIT CANONICAL TEXT")
  assert string.contains(result.output, "NOTICE.txt")
  let assert Ok(Nil) =
    simplifile.create_directory_all(root <> "/build/packages/git_dep")
  let assert Ok(Nil) =
    simplifile.write(
      to: root <> "/build/packages/git_dep/gleam.toml",
      contents: "licences = [\"Apache-2.0\"]\n",
    )
  should.equal(
    licence_audit.run_configured(
      ["notices", "--manifest=" <> manifest_path, "--no-cache"],
      licence_audit.Clients(
        ..test_clients(notice_metadata_fetcher),
        notice_clients: mit_spdx_clients(git_archive),
      ),
      progress.disabled(),
    ).0,
    result,
  )
  let assert Ok(_) = simplifile.delete(root)
}

pub fn notices_and_report_use_locked_hex_declaration_not_registry_test() {
  let archive = source_archive_test.notice_archive(["MIT"])
  let assert Ok(checksum) = source_archive.sha256_hex(archive)
  let root = "build/tmp/notices-locked-hex"
  let _ = simplifile.delete(root)
  let assert Ok(_) = simplifile.create_directory_all(root)
  let manifest_path = root <> "/manifest.toml"
  let assert Ok(_) =
    simplifile.write(
      "packages = [{ name = \"widget\", version = \"1.0.0\", source = \"hex\", outer_checksum = \""
        <> checksum
        <> "\" }]\n[requirements]\nwidget = \"1.0.0\"\n",
      to: manifest_path,
    )
  let clients =
    licence_audit.Clients(
      ..test_clients(fn(_) { Ok(hex.licences_only(["Apache-2.0"])) }),
      notice_clients: notice.Clients(
        ..mit_spdx_clients(unused_git_archive),
        fetch_hex_tarball: fn(_, _) { Ok(archive) },
        fetch_spdx_index: fn(_) { Ok(["MIT", "Apache-2.0"]) },
        fetch_spdx: fn(requirement) {
          Ok(
            Some(case requirement {
              spdx.LicenseRequirement("MIT") -> "LOCKED MIT TEXT"
              _ -> "NEWER APACHE TEXT"
            }),
          )
        },
      ),
    )
  let report =
    licence_audit.run_configured(
      ["report", "--manifest=" <> manifest_path, "--ignore-config"],
      clients,
      progress.disabled(),
    ).0
  let notices =
    licence_audit.run_configured(
      ["notices", "--manifest=" <> manifest_path, "--no-cache"],
      clients,
      progress.disabled(),
    ).0
  should.equal(report.exit_code, 0)
  should.equal(notices.exit_code, 0)
  assert string.contains(report.output, "MIT")
  assert string.contains(notices.output, "Declared licences: MIT")
  assert string.contains(notices.output, "SPDX-License-List/MIT.txt")
  assert string.contains(notices.output, "LOCKED MIT TEXT")
  assert !string.contains(notices.output, "Apache-2.0")
  assert !string.contains(notices.output, "NEWER APACHE TEXT")
  let assert Ok(_) = simplifile.delete(root)
}
