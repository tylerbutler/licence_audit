import gleam/bool
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import licence_audit/toml
import simplifile
import tomlet.{type Value}

pub type Policy {
  Policy(allow: List(String), deny: List(String), vuln_severity: Option(String))
}

pub type LoadOptions {
  LoadOptions(
    config_path: Option(String),
    project_root: String,
    allow_licences: List(String),
    deny_licences: List(String),
    vuln_severity: Option(String),
    ignore_config: Bool,
    check: Bool,
  )
}

pub type Error {
  InvalidToml(String)
  MissingPolicy
  InvalidField(field: String, expected: String)
  InvalidLicenceIdentifier
  FileReadError(String)
}

pub fn load(options: LoadOptions) -> Result(Policy, Error) {
  let cli_policy =
    Policy(
      allow: options.allow_licences,
      deny: options.deny_licences,
      vuln_severity: options.vuln_severity,
    )

  use <- bool.guard(when: options.ignore_config, return: validate(cli_policy))

  case load_file_policy(options) {
    Error(error) -> Error(error)
    Ok(Some(file_policy)) -> merge(file_policy, cli_policy)
    Ok(None) ->
      case options.check && is_empty(cli_policy) {
        True -> Error(MissingPolicy)
        False -> validate(cli_policy)
      }
  }
}

pub fn parse(input: String) -> Result(Policy, Error) {
  case toml.parse(input) {
    Error(_) -> Error(InvalidToml("Invalid TOML"))
    Ok(document) ->
      case toml.get_table(document, ["tools", "licence_audit"]) {
        Error(toml.TableLookupMissing) -> Error(MissingPolicy)
        Error(toml.TableLookupNotTable) ->
          Error(InvalidField(field: "tools.licence_audit", expected: "Table"))
        Ok(section) -> parse_policy_section(section)
      }
  }
}

pub fn merge(file_policy: Policy, cli_policy: Policy) -> Result(Policy, Error) {
  // CLI vuln_severity overrides config when present.
  let resolved_severity = case cli_policy.vuln_severity {
    Some(_) -> cli_policy.vuln_severity
    None -> file_policy.vuln_severity
  }

  Policy(
    allow: list.unique(list.append(file_policy.allow, cli_policy.allow)),
    deny: list.unique(list.append(file_policy.deny, cli_policy.deny)),
    vuln_severity: resolved_severity,
  )
  |> validate
}

fn load_file_policy(options: LoadOptions) -> Result(Option(Policy), Error) {
  case options.config_path {
    None -> load_project_policy(options.project_root)
    Some(path) -> {
      use contents <- result.try(read_required(path))
      case parse(contents) {
        Ok(policy) -> Ok(Some(policy))
        Error(MissingPolicy) -> Ok(None)
        Error(error) -> Error(error)
      }
    }
  }
}

fn load_project_policy(project_root: String) -> Result(Option(Policy), Error) {
  let gleam_toml_path = project_root <> "/gleam.toml"

  case read_optional(gleam_toml_path) {
    Error(error) -> Error(error)
    Ok(None) -> Ok(None)
    Ok(Some(contents)) -> {
      case parse(contents) {
        Ok(policy) -> Ok(Some(policy))
        Error(MissingPolicy) -> Ok(None)
        Error(error) -> Error(error)
      }
    }
  }
}

fn read_required(path: String) -> Result(String, Error) {
  case simplifile.read(from: path) {
    Ok(contents) -> Ok(contents)
    Error(_) -> Error(FileReadError(path))
  }
}

fn read_optional(path: String) -> Result(Option(String), Error) {
  case simplifile.is_file(path) {
    Ok(True) -> {
      case read_required(path) {
        Ok(contents) -> Ok(Some(contents))
        Error(error) -> Error(error)
      }
    }
    Ok(False) -> Ok(None)
    Error(_) -> Error(FileReadError(path))
  }
}

fn parse_policy_section(section: toml.Entry) -> Result(Policy, Error) {
  use allow <- result.try(optional_string_list(section, "allow"))
  use deny <- result.try(optional_string_list(section, "deny"))
  use severity <- result.try(optional_string(section, "vuln_severity"))
  validate(Policy(allow: allow, deny: deny, vuln_severity: severity))
}

fn optional_string(
  section: toml.Entry,
  field: String,
) -> Result(Option(String), Error) {
  case toml.field(section, field) {
    Error(_) -> Ok(None)
    Ok(value) ->
      case toml.as_string(value) {
        Error(_) -> Error(InvalidField(field: field, expected: "String"))
        Ok(s) -> Ok(Some(s))
      }
  }
}

fn optional_string_list(
  section: toml.Entry,
  field: String,
) -> Result(List(String), Error) {
  case toml.field(section, field) {
    Error(_) -> Ok([])
    Ok(value) -> {
      case toml.as_array(value) {
        Error(_) -> Error(InvalidField(field: field, expected: "List(String)"))
        Ok(values) -> strings_from_toml(values, field, [])
      }
    }
  }
}

fn strings_from_toml(
  values: List(Value),
  field: String,
  decoded: List(String),
) -> Result(List(String), Error) {
  case values {
    [] -> Ok(list.reverse(decoded))
    [value, ..rest] -> {
      case toml.as_string(value) {
        Ok(value) -> strings_from_toml(rest, field, [value, ..decoded])
        Error(_) -> Error(InvalidField(field: field, expected: "List(String)"))
      }
    }
  }
}

fn validate(policy: Policy) -> Result(Policy, Error) {
  use <- bool.guard(
    when: has_empty_identifier(policy.allow)
      || has_empty_identifier(policy.deny),
    return: Error(InvalidLicenceIdentifier),
  )
  validate_vuln_severity(policy)
}

fn validate_vuln_severity(policy: Policy) -> Result(Policy, Error) {
  case policy.vuln_severity {
    None -> Ok(policy)
    Some(value) -> {
      case list.contains(["low", "medium", "high", "critical"], value) {
        True -> Ok(policy)
        False ->
          Error(InvalidField(
            field: "vuln_severity",
            expected: "low|medium|high|critical",
          ))
      }
    }
  }
}

fn has_empty_identifier(licences: List(String)) -> Bool {
  list.any(licences, fn(licence) { string.trim(licence) == "" })
}

fn is_empty(policy: Policy) -> Bool {
  policy.allow == [] && policy.deny == [] && policy.vuln_severity == None
}
