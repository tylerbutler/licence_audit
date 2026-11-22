//// Run with `just test-spdx-policy`. Each property uses 200 cases and a fixed
//// seed below. Rerun the same test to reproduce qcheck's original and shrunk
//// counterexamples; keep the seed, generator, and dependency lock unchanged.
//// The renderer is test-only: the parser has no production rendering API.

import gleam/list
import gleam/string
import gleeunit/should
import licence_audit/policy
import licence_audit/spdx_expression.{type Expression, And, Licence, Or, With}
import qcheck.{type Generator}

fn config(seed: Int) -> qcheck.Config {
  qcheck.config(test_count: 200, max_retries: 1, seed: qcheck.seed(seed))
}

fn suffix() -> Generator(String) {
  qcheck.generic_string(
    qcheck.alphanumeric_ascii_codepoint(),
    qcheck.bounded_int(1, 10),
  )
}

fn licence_id() -> Generator(String) {
  qcheck.from_generators(qcheck.constant("MIT"), [
    qcheck.constant("Apache-2.0"),
    qcheck.constant("GPL-2.0+"),
    qcheck.map(suffix(), fn(value) { "LicenseRef-Custom-" <> value }),
    qcheck.map(suffix(), fn(value) {
      "DocumentRef-Project:LicenseRef-" <> value
    }),
  ])
}

fn term() -> Generator(Expression) {
  qcheck.from_generators(qcheck.map(licence_id(), Licence), [
    qcheck.map2(licence_id(), suffix(), fn(licence, value) {
      With(licence, "Exception-" <> value)
    }),
  ])
}

fn expression_at_depth(depth: Int) -> Generator(Expression) {
  case depth {
    0 -> term()
    _ -> {
      let operand = expression_at_depth(depth - 1)
      qcheck.from_generators(term(), [
        qcheck.map2(operand, operand, And),
        qcheck.map2(operand, operand, Or),
      ])
    }
  }
}

fn expression() -> Generator(Expression) {
  qcheck.bounded_int(0, 3)
  |> qcheck.bind(expression_at_depth)
}

fn render(expression: Expression, whitespace: String) -> String {
  case expression {
    Licence(id) -> id
    With(licence, exception) ->
      licence <> whitespace <> "WITH" <> whitespace <> exception
    And(left, right) ->
      "("
      <> render(left, whitespace)
      <> whitespace
      <> "AND"
      <> whitespace
      <> render(right, whitespace)
      <> ")"
    Or(left, right) ->
      "("
      <> render(left, whitespace)
      <> whitespace
      <> "OR"
      <> whitespace
      <> render(right, whitespace)
      <> ")"
  }
}

pub fn supported_tree_roundtrip_and_whitespace_test() -> Nil {
  use tree <- qcheck.run(config(2720), expression())
  // CRLF is excluded: the current tokenizer does not split that grapheme.
  list.each([" ", "\t", "\r", "\n", " \t\n "], fn(whitespace) {
    should.equal(spdx_expression.parse(render(tree, whitespace)), Ok(tree))
  })
}

pub fn malformed_mutations_fail_closed_test() -> Nil {
  use tree <- qcheck.run(config(2721), expression())
  let valid = render(tree, " ")
  list.each(
    [
      valid <> " AND",
      valid <> " WITH",
      "(" <> valid,
      valid <> ")",
      valid <> " AND OR MIT",
    ],
    fn(invalid) {
      should.equal(
        spdx_expression.parse(invalid),
        Error(spdx_expression.InvalidExpression),
      )
      let audit_policy = policy.Policy(allow: [invalid], deny: [])
      should.equal(
        policy.audit(audit_policy, [invalid]),
        policy.InvalidLicenceExpression(invalid),
      )
    },
  )
}

pub fn exact_declaration_deny_overrides_allow_test() -> Nil {
  use tree <- qcheck.run(config(2722), expression())
  let declared = render(tree, " ")
  let audit_policy = policy.Policy(allow: [declared], deny: [declared])
  should.equal(
    policy.audit(audit_policy, [declared]),
    policy.DeniedLicence(declared),
  )
}

pub fn explicit_conjunction_allow_cannot_bypass_operand_deny_test() -> Nil {
  use #(left, right) <- qcheck.run(config(2723), qcheck.tuple2(term(), term()))
  let declared = render(And(left, right), " ")
  let denied = render(left, " ")
  let audit_policy = policy.Policy(allow: [declared], deny: [denied])
  should.equal(
    policy.audit(audit_policy, [declared]),
    policy.DeniedLicence(denied),
  )
}

pub fn passing_or_branch_and_required_and_branch_test() -> Nil {
  use value <- qcheck.run(config(2724), suffix())
  let allowed = "Allowed-" <> value
  let denied = "Denied-" <> value
  let audit_policy = policy.Policy(allow: [allowed], deny: [denied])
  // No whole-expression rules: only the distinct operands are configured.
  list.each(
    [#(Licence(allowed), Licence(denied)), #(Licence(denied), Licence(allowed))],
    fn(operands) {
      let #(left, right) = operands
      should.equal(
        policy.audit(audit_policy, [render(Or(left, right), " ")]),
        policy.Allowed,
      )
      should.equal(
        policy.audit(audit_policy, [render(And(left, right), " ")]),
        policy.DeniedLicence(denied),
      )
    },
  )
}

pub fn ordinary_case_folds_but_reference_case_is_exact_test() -> Nil {
  use value <- qcheck.run(config(2725), suffix())
  let ordinary = "Example-" <> value <> " WITH Exception-" <> value
  let folded = string.uppercase(ordinary)
  should.equal(
    policy.audit(policy.Policy(allow: [ordinary], deny: []), [folded]),
    policy.Allowed,
  )
  should.equal(
    policy.audit(policy.Policy(allow: [folded], deny: [ordinary]), [folded]),
    policy.DeniedLicence(folded),
  )
  list.each(
    [
      #("LicenseRef-Custom-" <> value, "LicenseRef-custom-" <> value),
      #(
        "DocumentRef-Project:LicenseRef-" <> value,
        "DocumentRef-project:LicenseRef-" <> value,
      ),
      #(
        "DocumentRef-Project:LicenseRef-Custom-" <> value,
        "DocumentRef-Project:LicenseRef-custom-" <> value,
      ),
    ],
    fn(references) {
      let #(configured, different) = references
      let declared = configured <> " WITH exception-" <> value
      let configured = configured <> " WITH Exception-" <> value
      let different = different <> " WITH exception-" <> value
      let allow = policy.Policy(allow: [configured], deny: [])
      let deny = policy.Policy(allow: [], deny: [configured])
      should.equal(policy.audit(allow, [declared]), policy.Allowed)
      should.equal(
        policy.audit(deny, [declared]),
        policy.DeniedLicence(declared),
      )
      should.equal(
        policy.audit(allow, [different]),
        policy.UnallowedLicence(different),
      )
      should.equal(policy.audit(deny, [different]), policy.Allowed)
    },
  )
}

pub fn accepting_findings_never_adds_a_finding_test() -> Nil {
  use tree <- qcheck.run(config(2726), expression())
  let declared = render(tree, " ")
  let audit_policy = policy.Policy(allow: ["MIT"], deny: ["Apache-2.0"])
  let original = policy.findings(audit_policy, [declared], fn(_) { False })
  let accepted = policy.findings(audit_policy, [declared], fn(_) { True })
  should.be_true(
    list.all(accepted, fn(finding) { list.contains(original, finding) }),
  )
}
