import gleam/list
import gleam/option.{None}
import gleeunit/should
import licence_audit/config
import licence_audit/exception
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
      exceptions: [],
      allow: ["MIT", "MIT"],
      deny: ["GPL-3.0-only"],
      vuln_severity: None,
      vuln_block_unknown: False,
    )

  let assert Ok(audit_policy) =
    policy.from_config(config_policy, check_mode: True)

  should.equal(
    audit_policy,
    policy.Policy(allow: ["MIT"], deny: ["GPL-3.0-only"]),
  )
}

pub fn expressions_apply_policy_to_operands_test() {
  let assert Ok(deny_only) =
    policy.new(allow: [], deny: ["GPL-3.0-only"], check_mode: True)
  let assert Ok(allow_and_deny) =
    policy.new(allow: ["MIT"], deny: ["GPL-3.0-only"], check_mode: True)
  [
    #(deny_only, "MIT AND GPL-3.0-only", policy.DeniedLicence("GPL-3.0-only")),
    #(deny_only, "MIT OR GPL-3.0-only", policy.Allowed),
    #(allow_and_deny, "MIT OR GPL-3.0-only", policy.Allowed),
    #(
      allow_and_deny,
      "GPL-3.0-only OR Apache-2.0",
      policy.DeniedLicence("GPL-3.0-only"),
    ),
    #(allow_and_deny, "MIT OR Apache-2.0 AND GPL-3.0-only", policy.Allowed),
    #(
      allow_and_deny,
      "(MIT OR Apache-2.0) AND GPL-3.0-only",
      policy.DeniedLicence("GPL-3.0-only"),
    ),
    #(
      allow_and_deny,
      "MIT AND Apache-2.0",
      policy.UnallowedLicence("Apache-2.0"),
    ),
    #(allow_and_deny, "mit", policy.Allowed),
    #(deny_only, "mit AND gpl-3.0-only", policy.DeniedLicence("gpl-3.0-only")),
  ]
  |> list.each(fn(test_case) {
    let #(audit_policy, declared, expected) = test_case
    should.equal(policy.audit(audit_policy, [declared]), expected)
  })
}

pub fn with_and_plus_are_distinct_licence_terms_test() {
  let term = "GPL-2.0-only WITH Classpath-exception-2.0"
  let assert Ok(bare) =
    policy.new(allow: ["GPL-2.0-only"], deny: [], check_mode: True)
  should.equal(policy.audit(bare, [term]), policy.UnallowedLicence(term))
  should.equal(
    policy.audit(bare, ["GPL-2.0-only+"]),
    policy.UnallowedLicence("GPL-2.0-only+"),
  )
  let assert Ok(extended) =
    policy.new(allow: [term], deny: ["GPL-2.0-only"], check_mode: True)
  should.equal(policy.audit(extended, [term <> " OR MIT"]), policy.Allowed)
  should.equal(
    policy.audit(extended, ["GPL-2.0-only"]),
    policy.DeniedLicence("GPL-2.0-only"),
  )
  let assert Ok(denied) =
    policy.new(allow: [term], deny: [term], check_mode: True)
  should.equal(policy.audit(denied, [term]), policy.DeniedLicence(term))
}

pub fn explicit_expression_allow_cannot_override_operand_deny_test() {
  let expression = "MIT AND GPL-3.0-only"
  let assert Ok(audit_policy) =
    policy.new(allow: [expression], deny: ["GPL-3.0-only"], check_mode: True)
  should.equal(
    policy.audit(audit_policy, [expression]),
    policy.DeniedLicence("GPL-3.0-only"),
  )
  let assert Ok(audit_policy) =
    policy.new(allow: [expression], deny: [], check_mode: True)
  should.equal(policy.audit(audit_policy, [expression]), policy.Allowed)
}

pub fn malformed_expressions_fail_closed_even_when_allowed_test() {
  list.each(["MIT AND", "MIT OR (GPL-3.0-only", "MIT WITH"], fn(expression) {
    let assert Ok(audit_policy) =
      policy.new(allow: [expression], deny: ["GPL-3.0-only"], check_mode: True)
    should.equal(
      policy.audit(audit_policy, [expression]),
      policy.InvalidLicenceExpression(expression),
    )
    let assert Ok(deny_only) =
      policy.new(allow: [], deny: ["GPL-3.0-only"], check_mode: True)
    should.equal(
      policy.audit(deny_only, [expression]),
      policy.InvalidLicenceExpression(expression),
    )
  })
}

pub fn findings_preserve_every_required_operand_test() {
  let assert Ok(audit_policy) =
    policy.new(allow: ["MIT"], deny: ["GPL-3.0-only"], check_mode: True)
  should.equal(
    policy.findings(audit_policy, ["GPL-3.0-only AND Apache-2.0"], fn(_) {
      False
    }),
    [
      exception.DeniedLicence("GPL-3.0-only"),
      exception.UnallowedLicence("Apache-2.0"),
    ],
  )
  should.equal(
    policy.findings(audit_policy, ["GPL-3.0-only OR Apache-2.0"], fn(finding) {
      finding == exception.DeniedLicence("GPL-3.0-only")
    }),
    [exception.DeniedLicence("GPL-3.0-only")],
  )
  should.equal(
    policy.audit(audit_policy, ["MIT OR Apache-2.0", "GPL-3.0-only"]),
    policy.DeniedLicence("GPL-3.0-only"),
  )
  should.equal(
    policy.findings(audit_policy, [" GPL-3.0-only "], fn(_) { False }),
    [exception.DeniedLicence(" GPL-3.0-only ")],
  )
}

pub fn custom_references_preserve_only_their_own_case_test() {
  [
    #(
      "LicenseRef-Custom WITH Classpath-exception-2.0",
      "LicenseRef-Custom WITH classpath-exception-2.0",
    ),
    #("MIT AND LicenseRef-Custom", "mit AND LicenseRef-Custom"),
    #(
      "(MIT)AND(DocumentRef-Project:LicenseRef-Custom)",
      "(mit)AND(DocumentRef-Project:LicenseRef-Custom)",
    ),
  ]
  |> list.each(fn(test_case) {
    let #(configured, declared) = test_case
    let assert Ok(deny_only) =
      policy.new(allow: [], deny: [configured], check_mode: True)
    should.equal(
      policy.audit(deny_only, [declared]),
      policy.DeniedLicence(declared),
    )
    let assert Ok(allow_only) =
      policy.new(allow: [configured], deny: [], check_mode: True)
    should.equal(policy.audit(allow_only, [declared]), policy.Allowed)
  })
  let assert Ok(deny_only) =
    policy.new(allow: [], deny: ["LicenseRef-Custom"], check_mode: True)
  should.equal(policy.audit(deny_only, ["LicenseRef-custom"]), policy.Allowed)
  let assert Ok(allow_only) =
    policy.new(allow: ["LicenseRef-Custom"], deny: [], check_mode: True)
  should.equal(
    policy.audit(allow_only, ["LicenseRef-custom"]),
    policy.UnallowedLicence("LicenseRef-custom"),
  )
}
