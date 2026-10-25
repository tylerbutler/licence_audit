import gleam/list
import gleam/string
import licence_audit/config
import licence_audit/exception
import licence_audit/spdx_expression

pub type Policy {
  Policy(allow: List(String), deny: List(String))
}

pub type AuditStatus {
  Allowed
  NoLicencesDeclared
  DeniedLicence(String)
  UnallowedLicence(String)
  InvalidLicenceExpression(String)
}

pub type Error {
  MissingPolicy
}

pub fn new(
  allow allow: List(String),
  deny deny: List(String),
  check_mode check_mode: Bool,
) -> Result(Policy, Error) {
  let audit_policy = Policy(allow: list.unique(allow), deny: list.unique(deny))

  case check_mode && is_empty(audit_policy) {
    True -> Error(MissingPolicy)
    False -> Ok(audit_policy)
  }
}

pub fn from_config(
  config_policy config_policy: config.Policy,
  check_mode check_mode: Bool,
) -> Result(Policy, Error) {
  new(
    allow: config_policy.allow,
    deny: config_policy.deny,
    check_mode: check_mode,
  )
}

pub fn audit(policy: Policy, licences: List(String)) -> AuditStatus {
  case failures(policy, licences, fn(_) { False }) {
    [] -> Allowed
    [failure, ..] -> failure
  }
}

/// Return the findings needed to satisfy every declaration. An OR selects a
/// passing branch, including scoped decisions supplied by `accepted`.
pub fn findings(
  policy: Policy,
  licences: List(String),
  accepted: fn(exception.Finding) -> Bool,
) -> List(exception.Finding) {
  failures(policy, licences, fn(status) {
    case to_finding(status) {
      Ok(finding) -> accepted(finding)
      Error(Nil) -> True
    }
  })
  |> list.filter_map(to_finding)
}

fn to_finding(status: AuditStatus) -> Result(exception.Finding, Nil) {
  case status {
    Allowed -> Error(Nil)
    DeniedLicence(licence) -> Ok(exception.DeniedLicence(licence))
    UnallowedLicence(licence) -> Ok(exception.UnallowedLicence(licence))
    InvalidLicenceExpression(licence) ->
      Ok(exception.InvalidLicenceExpression(licence))
    NoLicencesDeclared -> Ok(exception.NoLicencesDeclared)
  }
}

fn failures(
  policy: Policy,
  licences: List(String),
  accepted: fn(AuditStatus) -> Bool,
) -> List(AuditStatus) {
  let failures = case licences {
    [] -> [NoLicencesDeclared]
    _ ->
      licences
      |> list.flat_map(declared_failures(policy, _, accepted))
      |> list.unique
  }
  let #(denied, other) =
    list.partition(failures, fn(status) {
      case status {
        DeniedLicence(_) -> True
        Allowed
        | UnallowedLicence(_)
        | InvalidLicenceExpression(_)
        | NoLicencesDeclared -> False
      }
    })
  list.append(denied, other)
}

fn declared_failures(
  policy: Policy,
  declared: String,
  accepted: fn(AuditStatus) -> Bool,
) -> List(AuditStatus) {
  case spdx_expression.parse(declared) {
    Error(_) -> [InvalidLicenceExpression(declared)]
    Ok(expression) -> {
      // An explicitly allowed declaration must still pass operand deny rules.
      let effective_policy = case matches(policy.allow, declared) {
        True -> Policy(..policy, allow: [])
        False -> policy
      }
      let findings = evaluate(effective_policy, expression, accepted)
      case matches(policy.deny, declared), expression {
        True, spdx_expression.And(_, _) | True, spdx_expression.Or(_, _) -> [
          DeniedLicence(declared),
          ..findings
        ]
        True, spdx_expression.Licence(_) | True, spdx_expression.With(_, _) -> [
          DeniedLicence(declared),
        ]
        False, _ -> findings
      }
    }
  }
}

fn evaluate(
  policy: Policy,
  expression: spdx_expression.Expression,
  accepted: fn(AuditStatus) -> Bool,
) -> List(AuditStatus) {
  case expression {
    spdx_expression.Licence(id) -> licence_failures(policy, id)
    spdx_expression.With(licence, exception) ->
      licence_failures(policy, licence <> " WITH " <> exception)
    spdx_expression.And(left, right) ->
      list.append(
        evaluate(policy, left, accepted),
        evaluate(policy, right, accepted),
      )
    spdx_expression.Or(left, right) -> {
      let left = evaluate(policy, left, accepted)
      let right = evaluate(policy, right, accepted)
      case left, right {
        [], _ | _, [] -> []
        _, _ ->
          case list.all(left, accepted), list.all(right, accepted) {
            True, _ -> left
            False, True -> right
            False, False -> list.append(left, right)
          }
      }
    }
  }
}

fn licence_failures(policy: Policy, licence: String) -> List(AuditStatus) {
  case matches(policy.deny, licence) {
    True -> [DeniedLicence(licence)]
    False ->
      case policy.allow == [] || matches(policy.allow, licence) {
        True -> []
        False -> [UnallowedLicence(licence)]
      }
  }
}

fn matches(licences: List(String), licence: String) -> Bool {
  let tokens = matching_tokens(licence)
  list.any(licences, fn(configured) { matching_tokens(configured) == tokens })
}

fn matching_tokens(expression: String) -> List(String) {
  expression
  |> spdx_expression.tokenize
  |> list.map(fn(token) {
    case token {
      "LicenseRef-" <> _ | "DocumentRef-" <> _ -> token
      _ -> string.lowercase(token)
    }
  })
}

fn is_empty(policy: Policy) -> Bool {
  policy.allow == [] && policy.deny == []
}

pub fn has_rules(policy: Policy) -> Bool {
  !is_empty(policy)
}
