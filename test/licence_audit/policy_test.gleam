import gleam/option.{None}
import gleeunit/should
import licence_audit/config
import licence_audit/policy

pub fn known_allowed_licence_is_ok_test() {
  let assert Ok(audit_policy) =
    policy.new(allow: ["MIT"], deny: [], check_mode: True)

  should.equal(policy.audit(audit_policy, ["MIT"]), policy.Allowed)
}

pub fn licence_not_in_allow_list_fails_test() {
  let assert Ok(audit_policy) =
    policy.new(allow: ["MIT"], deny: [], check_mode: True)

  should.equal(
    policy.audit(audit_policy, ["Apache-2.0"]),
    policy.UnallowedLicence("Apache-2.0"),
  )
}

pub fn denied_licence_fails_even_if_allowed_test() {
  let assert Ok(audit_policy) =
    policy.new(
      allow: ["MIT", "GPL-3.0-only"],
      deny: ["GPL-3.0-only"],
      check_mode: True,
    )

  should.equal(
    policy.audit(audit_policy, ["GPL-3.0-only"]),
    policy.DeniedLicence("GPL-3.0-only"),
  )
}

pub fn missing_licence_fails_in_audit_mode_test() {
  let assert Ok(audit_policy) =
    policy.new(allow: ["MIT"], deny: [], check_mode: False)

  should.equal(policy.audit(audit_policy, []), policy.NoLicencesDeclared)
}

pub fn multiple_allowed_licences_are_ok_test() {
  let assert Ok(audit_policy) =
    policy.new(allow: ["MIT", "Apache-2.0"], deny: [], check_mode: True)

  should.equal(
    policy.audit(audit_policy, ["MIT", "Apache-2.0"]),
    policy.Allowed,
  )
}

pub fn deny_list_only_policy_permits_non_denied_licences_test() {
  let assert Ok(audit_policy) =
    policy.new(allow: [], deny: ["GPL-3.0-only"], check_mode: True)

  should.equal(policy.audit(audit_policy, ["MIT"]), policy.Allowed)
}

pub fn any_denied_licence_in_multi_licence_package_fails_test() {
  let assert Ok(audit_policy) =
    policy.new(
      allow: ["MIT", "Apache-2.0"],
      deny: ["GPL-3.0-only"],
      check_mode: True,
    )

  should.equal(
    policy.audit(audit_policy, ["MIT", "GPL-3.0-only"]),
    policy.DeniedLicence("GPL-3.0-only"),
  )
}

pub fn any_unallowed_licence_in_multi_licence_package_fails_test() {
  let assert Ok(audit_policy) =
    policy.new(allow: ["MIT"], deny: [], check_mode: True)

  should.equal(
    policy.audit(audit_policy, ["MIT", "Apache-2.0"]),
    policy.UnallowedLicence("Apache-2.0"),
  )
}

pub fn empty_policy_is_an_error_only_when_check_mode_is_used_test() {
  should.equal(
    policy.new(allow: [], deny: [], check_mode: True),
    Error(policy.MissingPolicy),
  )

  should.equal(
    policy.new(allow: [], deny: [], check_mode: False),
    Ok(policy.Policy(allow: [], deny: [])),
  )
}

pub fn dedupe_preserves_stable_order_test() {
  let assert Ok(audit_policy) =
    policy.new(
      allow: ["MIT", "Apache-2.0", "MIT", "BSD-3-Clause"],
      deny: ["GPL-3.0-only", "AGPL-3.0-only", "GPL-3.0-only"],
      check_mode: True,
    )

  should.equal(audit_policy.allow, ["MIT", "Apache-2.0", "BSD-3-Clause"])
  should.equal(audit_policy.deny, ["GPL-3.0-only", "AGPL-3.0-only"])
}

pub fn config_policy_can_be_converted_to_policy_test() {
  let config_policy =
    config.Policy(
      allow: ["MIT", "MIT"],
      deny: ["GPL-3.0-only"],
      vuln_severity: None,
    )

  let assert Ok(audit_policy) =
    policy.from_config(config_policy, check_mode: True)

  should.equal(
    audit_policy,
    policy.Policy(allow: ["MIT"], deny: ["GPL-3.0-only"]),
  )
}
