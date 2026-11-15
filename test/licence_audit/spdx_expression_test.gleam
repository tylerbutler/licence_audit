import gleam/list
import gleam/string
import gleeunit/should
import licence_audit/spdx_expression.{And, Licence, Or, With}

pub fn precedence_and_parentheses_test() {
  should.equal(
    spdx_expression.parse(
      "MIT OR Apache-2.0 AND GPL-2.0+ WITH Classpath-exception-2.0",
    ),
    Ok(Or(
      Licence("MIT"),
      And(Licence("Apache-2.0"), With("GPL-2.0+", "Classpath-exception-2.0")),
    )),
  )
  should.equal(
    spdx_expression.parse("(MIT\tOR\nApache-2.0)\rAND LicenseRef-Custom"),
    Ok(And(
      Or(Licence("MIT"), Licence("Apache-2.0")),
      Licence("LicenseRef-Custom"),
    )),
  )
  should.equal(
    spdx_expression.parse("DocumentRef-project:LicenseRef-Custom"),
    Ok(Licence("DocumentRef-project:LicenseRef-Custom")),
  )
  should.equal(
    spdx_expression.parse("DocumentRef-AND:LicenseRef-WITH"),
    Ok(Licence("DocumentRef-AND:LicenseRef-WITH")),
  )
}

pub fn malformed_expressions_are_rejected_test() {
  [
    "", " ", "MIT AND", "OR MIT", "MIT Apache-2.0", "(MIT", "MIT)", "()",
    "MIT OR OR Apache-2.0", "MIT WITH", "MIT WITH AND",
    "(MIT OR Apache-2.0) WITH LLVM-exception",
    "MIT WITH LLVM-exception WITH other", "MIT and Apache-2.0", "GPL-2.0++",
    "MIT +", "MIT/Apache-2.0", "LicenseRef-", "LicenseRef-custom+",
    "DocumentRef-:LicenseRef-custom", "DocumentRef-project:LicenseRef-",
    "DocumentRef-project",
  ]
  |> list.each(fn(input) {
    should.equal(
      spdx_expression.parse(input),
      Error(spdx_expression.InvalidExpression),
    )
  })
}

pub fn untrusted_input_limits_test() {
  let nested = fn(depth) {
    string.repeat("(", depth) <> "MIT" <> string.repeat(")", depth)
  }
  should.equal(spdx_expression.parse(nested(64)), Ok(Licence("MIT")))
  let longest = string.repeat("a", 65_536)
  should.equal(spdx_expression.parse(longest), Ok(Licence(longest)))
  let assert Ok(_) =
    spdx_expression.parse(string.repeat("MIT OR ", 511) <> "MIT")
  should.equal(
    spdx_expression.parse(nested(65)),
    Error(spdx_expression.NestingTooDeep),
  )
  should.equal(
    spdx_expression.parse(string.repeat("a", 65_537)),
    Error(spdx_expression.ExpressionTooLarge),
  )
  should.equal(
    spdx_expression.parse(string.repeat("MIT OR ", 512) <> "MIT"),
    Error(spdx_expression.ExpressionTooLarge),
  )
}
