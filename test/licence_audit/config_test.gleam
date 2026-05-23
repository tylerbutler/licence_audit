import gleam/option.{None, Some}
import gleeunit/should
import licence_audit/config

const tools_section = "[tools.licence_audit]\nallow = [\"MIT\", \"Apache-2.0\"]\ndeny = [\"GPL-3.0-only\"]\n"

const gleam_toml_with_tools = "name = \"fixture\"\n\n[tools.licence_audit]\nallow = [\"MIT\", \"Apache-2.0\"]\ndeny = [\"GPL-3.0-only\"]\n"

const legacy_licences = "[licences]\nallow = [\"MIT\"]\ndeny = []\n"

const legacy_licence_audit = "[licence_audit]\nallow = [\"MIT\"]\ndeny = []\n"

pub fn parse_tools_licence_audit_section_test() {
  let assert Ok(policy) = config.parse(tools_section)

  should.equal(
    policy,
    config.Policy(
      allow: ["MIT", "Apache-2.0"],
      deny: ["GPL-3.0-only"],
      vuln_severity: None,
    ),
  )
}

pub fn parse_gleam_toml_finds_tools_licence_audit_test() {
  let assert Ok(policy) = config.parse(gleam_toml_with_tools)

  should.equal(
    policy,
    config.Policy(
      allow: ["MIT", "Apache-2.0"],
      deny: ["GPL-3.0-only"],
      vuln_severity: None,
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
      allow: ["MIT", "Apache-2.0"],
      deny: ["GPL-3.0-only"],
      vuln_severity: None,
    )
  let cli =
    config.Policy(
      allow: ["MIT", "BSD-3-Clause"],
      deny: [
        "AGPL-3.0-only",
        "GPL-3.0-only",
      ],
      vuln_severity: None,
    )

  let assert Ok(policy) = config.merge(file, cli)

  should.equal(policy.allow, ["MIT", "Apache-2.0", "BSD-3-Clause"])
  should.equal(policy.deny, ["GPL-3.0-only", "AGPL-3.0-only"])
}

pub fn merge_errors_on_empty_licence_identifier_test() {
  let file = config.Policy(allow: ["MIT"], deny: [], vuln_severity: None)
  let cli = config.Policy(allow: [""], deny: [], vuln_severity: None)

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

pub fn load_uses_explicit_config_before_project_config_test() {
  let options =
    config.LoadOptions(
      config_path: Some("test/fixtures/licence_audit_config.toml"),
      project_root: "test/fixtures",
      allow_licences: [],
      deny_licences: [],
      vuln_severity: None,
      ignore_config: False,
      check: False,
    )

  let assert Ok(policy) = config.load(options)

  should.equal(
    policy,
    config.Policy(
      allow: ["BSD-3-Clause"],
      deny: ["AGPL-3.0-only"],
      vuln_severity: None,
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
      ignore_config: False,
      check: False,
    )

  let assert Ok(policy) = config.load(options)

  should.equal(
    policy,
    config.Policy(
      allow: ["MIT", "Apache-2.0"],
      deny: ["GPL-3.0-only"],
      vuln_severity: None,
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
      ignore_config: False,
      check: True,
    )

  let assert Ok(policy) = config.load(options)

  should.equal(
    policy,
    config.Policy(allow: ["MIT"], deny: ["GPL-3.0-only"], vuln_severity: None),
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
      ignore_config: True,
      check: False,
    )

  let assert Ok(policy) = config.load(options)

  should.equal(
    policy,
    config.Policy(allow: ["ISC"], deny: ["Unlicence"], vuln_severity: None),
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
      ignore_config: False,
      check: False,
    )

  let assert Ok(policy) = config.load(options)

  should.equal(policy, config.Policy(allow: [], deny: [], vuln_severity: None))
}

pub fn load_errors_on_missing_policy_in_check_mode_test() {
  let options =
    config.LoadOptions(
      config_path: None,
      project_root: "test/fixtures/no-policy",
      allow_licences: [],
      deny_licences: [],
      vuln_severity: None,
      ignore_config: False,
      check: True,
    )

  let assert Error(error) = config.load(options)

  should.equal(error, config.MissingPolicy)
}
