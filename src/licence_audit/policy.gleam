import gleam/list
import licence_audit/config

pub type Policy {
  Policy(allow: List(String), deny: List(String))
}

pub type AuditStatus {
  Allowed
  NoLicencesDeclared
  DeniedLicence(String)
  UnallowedLicence(String)
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
  case licences {
    [] -> NoLicencesDeclared
    _ -> {
      case find_present(licences, policy.deny) {
        Ok(licence) -> DeniedLicence(licence)
        Error(Nil) -> check_allow_list(policy, licences)
      }
    }
  }
}

fn check_allow_list(policy: Policy, licences: List(String)) -> AuditStatus {
  case policy.allow {
    [] -> Allowed
    _ -> {
      case find_missing(licences, policy.allow) {
        Ok(licence) -> UnallowedLicence(licence)
        Error(Nil) -> Allowed
      }
    }
  }
}

fn find_present(
  licences: List(String),
  denied: List(String),
) -> Result(String, Nil) {
  case licences {
    [] -> Error(Nil)
    [licence, ..rest] -> {
      case list.contains(denied, licence) {
        True -> Ok(licence)
        False -> find_present(rest, denied)
      }
    }
  }
}

fn find_missing(
  licences: List(String),
  allowed: List(String),
) -> Result(String, Nil) {
  case licences {
    [] -> Error(Nil)
    [licence, ..rest] -> {
      case list.contains(allowed, licence) {
        True -> find_missing(rest, allowed)
        False -> Ok(licence)
      }
    }
  }
}

fn is_empty(policy: Policy) -> Bool {
  policy.allow == [] && policy.deny == []
}

pub fn has_rules(policy: Policy) -> Bool {
  !is_empty(policy)
}
