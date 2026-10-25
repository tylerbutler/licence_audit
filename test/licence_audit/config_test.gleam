import gleam/list
import gleam/option.{None, Some}
import gleam/string
import gleeunit/should
import licence_audit
import licence_audit/config
import licence_audit/progress

const tools_section =
  "[tools.licence_audit]\nallow = [\"MIT\", \"Apache-2.0\"]\ndeny = [\"GPL-3.0-only\"]\n"

const gleam_toml_with_tools =
  "name = \"fixture\"\n\n[tools.licence_audit]\nallow = [\"MIT\", \"Apache-2.0\"]\ndeny = [\"GPL-3.0-only\"]\n"

const legacy_licences = "[licences]\nallow = [\"MIT\"]\ndeny = []\n"

const legacy_licence_audit = "[licence_audit]\nallow = [\"MIT\"]\ndeny = []\n"

pub fn parse_tools_licence_audit_section_test() {
  let assert Ok(policy) = config.parse(tools_section)

  should.equal(
    policy,
    config.Policy(
      exceptions: [],
      allow: ["MIT", "Apache-2.0"],
      deny: ["GPL-3.0-only"],
      vuln_severity: None,
      vuln_block_unknown: False,
    ),
  )
}

pub fn parse_gleam_toml_finds_tools_licence_audit_test() {
  let assert Ok(policy) = config.parse(gleam_toml_with_tools)

  should.equal(
    policy,
    config.Policy(
      exceptions: [],
      allow: ["MIT", "Apache-2.0"],
      deny: ["GPL-3.0-only"],
      vuln_severity: None,
      vuln_block_unknown: False,
    ),
  )
}

pub fn parse_rejects_legacy_licences_section_test() {
  let assert Error(error) = config.parse(legacy_licences)
  should.equal(error, config.MissingPolicy)
}

pub fn parse_rejects_bare_licence_audit_section_test() {
  let assert Error(error) = config.parse(legacy_licence_audit)
  should.equal(error, config.MissingPolicy)
}

pub fn merge_combines_file_and_cli_policy_with_stable_deduplication_test() {
  let file =
    config.Policy(
      exceptions: [],
      allow: ["MIT", "Apache-2.0"],
      deny: ["GPL-3.0-only"],
      vuln_severity: None,
      vuln_block_unknown: False,
    )
  let cli =
    config.Policy(
      exceptions: [],
      allow: ["MIT", "BSD-3-Clause"],
      deny: [
        "AGPL-3.0-only",
        "GPL-3.0-only",
      ],
      vuln_severity: None,
      vuln_block_unknown: False,
    )

  let assert Ok(policy) = config.merge(file, cli)

  should.equal(policy.allow, ["MIT", "Apache-2.0", "BSD-3-Clause"])
  should.equal(policy.deny, ["GPL-3.0-only", "AGPL-3.0-only"])
}

pub fn merge_errors_on_empty_licence_identifier_test() {
  let file =
    config.Policy(
      exceptions: [],
      allow: ["MIT"],
      deny: [],
      vuln_severity: None,
      vuln_block_unknown: False,
    )
  let cli =
    config.Policy(
      exceptions: [],
      allow: [""],
      deny: [],
      vuln_severity: None,
      vuln_block_unknown: False,
    )

  let assert Error(error) = config.merge(file, cli)

  should.equal(error, config.InvalidLicenceIdentifier)
}

pub fn parse_errors_on_invalid_field_type_test() {
  let assert Error(error) =
    config.parse("[tools.licence_audit]\nallow = \"MIT\"\n")

  case error {
    config.InvalidField(field: "allow", expected: "List(String)") -> Nil
    _ -> panic as "expected InvalidField for allow"
  }
}

pub fn parse_rejects_nested_reserved_policy_fields_test() {
  [
    #("allow", "List(String)"),
    #("deny", "List(String)"),
    #("vuln_severity", "String"),
    #("vuln_block_unknown", "Bool"),
  ]
  |> list.each(fn(setting) {
    let #(field, expected) = setting
    [
      "[tools.licence_audit." <> field <> "]\nlicences = [\"MIT\"]\n",
      "[tools.licence_audit." <> field <> "]\n",
      "[tools.licence_audit." <> field <> ".nested]\nvalue = true\n",
      "[tools.licence_audit]\n" <> field <> ".value = true\n",
      "tools.licence_audit." <> field <> ".value = true\n",
      "[tools.licence_audit]\n" <> field <> " = { value = true }\n",
      "[[tools.licence_audit." <> field <> "]]\nvalue = true\n",
    ]
    |> list.each(fn(input) {
      should.equal(
        config.parse(input),
        Error(config.InvalidField(field: field, expected: expected)),
      )
    })
  })
}

pub fn parse_keeps_unrelated_nested_configuration_test() {
  let assert Ok(expected) =
    config.parse(
      "[tools.licence_audit]\nallow = [\"MIT\"]\ndeny = []\nvuln_severity = \"high\"\nvuln_block_unknown = true\n",
    )
  let assert Ok(actual) =
    config.parse(
      "[tools.licence_audit]
allow = [\"MIT\"]
deny = []
vuln_severity = \"high\"
vuln_block_unknown = true
\"allow.licences\" = [\"Apache-2.0\"]
custom.allow = [\"Apache-2.0\"]
[tools.licence_audit.notices]
exclude = [\"example\"]
[tools.licence_audit.custom.deny]
value = true
[tools.other.allow]
licences = [\"Apache-2.0\"]
",
    )
  should.equal(actual, expected)
}

pub fn parse_rejects_nested_exceptions_setting_test() {
  [
    "[tools.licence_audit.exceptions]\n",
    "[tools.licence_audit.exceptions]\nvalue = true\n",
    "[tools.licence_audit]\nexceptions.value = true\n",
    "tools.licence_audit.exceptions.value = true\n",
  ]
  |> list.each(fn(input) {
    let assert Error(config.InvalidException(_)) = config.parse(input)
  })
}

pub fn parse_accepts_correctly_typed_dotted_policy_values_test() {
  let assert Ok(expected) = config.parse(tools_section)
  should.equal(
    config.parse(
      "tools.licence_audit.allow = [\"MIT\", \"Apache-2.0\"]\ntools.licence_audit.deny = [\"GPL-3.0-only\"]\n",
    ),
    Ok(expected),
  )
}

pub fn check_rejects_nested_policy_before_fetching_metadata_test() {
  let clients =
    licence_audit.Clients(..licence_audit.default_clients(), fetcher: fn(_) {
      panic as "invalid config must stop before fetching"
    })
  let #(result, _) =
    licence_audit.run_configured(
      [
        "check",
        "--manifest=test/fixtures/manifest.toml",
        "--config=test/fixtures/nested_policy_config.toml",
      ],
      clients,
      progress.disabled(),
    )
  should.equal(result.exit_code, 2)
  assert string.contains(
    result.output,
    "Invalid config field allow: expected List(String)",
  )
}

pub fn parse_errors_on_invalid_vuln_severity_test() {
  let assert Error(error) =
    config.parse("[tools.licence_audit]\nvuln_severity = \"crit\"\n")

  case error {
    config.InvalidField(
      field: "vuln_severity",
      expected: "low|medium|high|critical",
    ) -> Nil
    _ -> panic as "expected InvalidField for vuln_severity"
  }
}

pub fn parse_vuln_block_unknown_defaults_false_and_accepts_boolean_test() {
  let assert Ok(default_policy) = config.parse("[tools.licence_audit]\n")
  let assert Ok(enabled_policy) =
    config.parse("[tools.licence_audit]\nvuln_block_unknown = true\n")
  let assert Ok(disabled_policy) =
    config.parse("[tools.licence_audit]\nvuln_block_unknown = false\n")

  should.equal(default_policy.vuln_block_unknown, False)
  should.equal(enabled_policy.vuln_block_unknown, True)
  should.equal(disabled_policy.vuln_block_unknown, False)
}

pub fn parse_errors_on_non_boolean_vuln_block_unknown_test() {
  let assert Error(error) =
    config.parse("[tools.licence_audit]\nvuln_block_unknown = \"true\"\n")

  should.equal(
    error,
    config.InvalidField(field: "vuln_block_unknown", expected: "Bool"),
  )
}

pub fn merge_preserves_configured_vuln_block_unknown_test() {
  let file =
    config.Policy(
      exceptions: [],
      allow: [],
      deny: [],
      vuln_severity: None,
      vuln_block_unknown: True,
    )
  let cli =
    config.Policy(
      exceptions: [],
      allow: [],
      deny: [],
      vuln_severity: None,
      vuln_block_unknown: False,
    )

  let assert Ok(policy) = config.merge(file, cli)

  should.equal(policy.vuln_block_unknown, True)
}

pub fn load_uses_explicit_config_before_project_config_test() {
  let options =
    config.LoadOptions(
      config_path: Some("test/fixtures/licence_audit_config.toml"),
      project_root: "test/fixtures",
      allow_licences: [],
      deny_licences: [],
      vuln_severity: None,
      vuln_block_unknown: False,
      ignore_config: False,
      check: False,
    )

  let assert Ok(policy) = config.load(options)

  should.equal(
    policy,
    config.Policy(
      exceptions: [],
      allow: ["BSD-3-Clause"],
      deny: ["AGPL-3.0-only"],
      vuln_severity: None,
      vuln_block_unknown: False,
    ),
  )
}

pub fn load_reads_project_gleam_toml_test() {
  let options =
    config.LoadOptions(
      config_path: None,
      project_root: "test/fixtures",
      allow_licences: [],
      deny_licences: [],
      vuln_severity: None,
      vuln_block_unknown: False,
      ignore_config: False,
      check: False,
    )

  let assert Ok(policy) = config.load(options)

  should.equal(
    policy,
    config.Policy(
      exceptions: [],
      allow: ["MIT", "Apache-2.0"],
      deny: ["GPL-3.0-only"],
      vuln_severity: None,
      vuln_block_unknown: False,
    ),
  )
}

pub fn load_uses_cli_policy_when_no_file_policy_exists_test() {
  let options =
    config.LoadOptions(
      config_path: None,
      project_root: "test/fixtures/no-policy",
      allow_licences: ["MIT"],
      deny_licences: ["GPL-3.0-only"],
      vuln_severity: None,
      vuln_block_unknown: False,
      ignore_config: False,
      check: True,
    )

  let assert Ok(policy) = config.load(options)

  should.equal(
    policy,
    config.Policy(
      exceptions: [],
      allow: ["MIT"],
      deny: ["GPL-3.0-only"],
      vuln_severity: None,
      vuln_block_unknown: False,
    ),
  )
}

pub fn load_uses_cli_only_when_ignore_config_is_set_test() {
  let options =
    config.LoadOptions(
      config_path: Some("test/fixtures/licence_audit_config.toml"),
      project_root: "test/fixtures",
      allow_licences: ["ISC"],
      deny_licences: ["Unlicence"],
      vuln_severity: None,
      vuln_block_unknown: False,
      ignore_config: True,
      check: False,
    )

  let assert Ok(policy) = config.load(options)

  should.equal(
    policy,
    config.Policy(
      exceptions: [],
      allow: ["ISC"],
      deny: ["Unlicence"],
      vuln_severity: None,
      vuln_block_unknown: False,
    ),
  )
}

pub fn load_allows_missing_policy_in_report_mode_test() {
  let options =
    config.LoadOptions(
      config_path: None,
      project_root: "test/fixtures/no-policy",
      allow_licences: [],
      deny_licences: [],
      vuln_severity: None,
      vuln_block_unknown: False,
      ignore_config: False,
      check: False,
    )

  let assert Ok(policy) = config.load(options)

  should.equal(
    policy,
    config.Policy(
      exceptions: [],
      allow: [],
      deny: [],
      vuln_severity: None,
      vuln_block_unknown: False,
    ),
  )
}

pub fn load_errors_on_missing_policy_in_check_mode_test() {
  let options =
    config.LoadOptions(
      config_path: None,
      project_root: "test/fixtures/no-policy",
      allow_licences: [],
      deny_licences: [],
      vuln_severity: None,
      vuln_block_unknown: False,
      ignore_config: False,
      check: True,
    )

  let assert Error(error) = config.load(options)

  should.equal(error, config.MissingPolicy)
}
