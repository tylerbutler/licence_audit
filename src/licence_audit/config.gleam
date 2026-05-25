import gleam/dict.{type Dict}
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/string
import simplifile
import tom.{type Toml}

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

  case options.ignore_config {
    True -> validate(cli_policy)
    False -> {
      case load_file_policy(options) {
        Error(error) -> Error(error)
        Ok(Some(file_policy)) -> merge(file_policy, cli_policy)
        Ok(None) -> {
          case options.check && is_empty(cli_policy) {
            True -> Error(MissingPolicy)
            False -> validate(cli_policy)
          }
        }
      }
    }
  }
}

pub fn parse(input: String) -> Result(Policy, Error) {
  case parse_document(input) {
    Error(error) -> Error(error)
    Ok(document) -> {
      case find_section(document, [["tools", "licence_audit"]]) {
        Error(error) -> Error(error)
        Ok(section) -> parse_policy_section(section)
      }
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
    allow: append_unique(file_policy.allow, cli_policy.allow),
    deny: append_unique(file_policy.deny, cli_policy.deny),
    vuln_severity: resolved_severity,
  )
  |> validate
}

fn load_file_policy(options: LoadOptions) -> Result(Option(Policy), Error) {
  case options.config_path {
    Some(path) -> {
      case read_required(path) {
        Error(error) -> Error(error)
        Ok(contents) -> {
          case parse(contents) {
            Ok(policy) -> Ok(Some(policy))
            Error(MissingPolicy) -> Ok(None)
            Error(error) -> Error(error)
          }
        }
      }
    }

    None -> load_project_policy(options.project_root)
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

fn parse_document(input: String) -> Result(Dict(String, Toml), Error) {
  case tom.parse(input) {
    Ok(document) -> Ok(document)
    Error(_) -> Error(InvalidToml("Invalid TOML"))
  }
}

fn find_section(
  document: Dict(String, Toml),
  candidates: List(List(String)),
) -> Result(Dict(String, Toml), Error) {
  case candidates {
    [] -> Error(MissingPolicy)
    [candidate, ..rest] -> {
      case tom.get_table(document, candidate) {
        Ok(section) -> Ok(section)
        Error(tom.NotFound(_)) -> find_section(document, rest)
        Error(_) ->
          Error(InvalidField(field: key_name(candidate), expected: "Table"))
      }
    }
  }
}

fn parse_policy_section(section: Dict(String, Toml)) -> Result(Policy, Error) {
  case optional_string_list(section, "allow") {
    Error(error) -> Error(error)
    Ok(allow) -> {
      case optional_string_list(section, "deny") {
        Error(error) -> Error(error)
        Ok(deny) -> {
          case optional_string(section, "vuln_severity") {
            Error(error) -> Error(error)
            Ok(severity) ->
              validate(Policy(allow: allow, deny: deny, vuln_severity: severity))
          }
        }
      }
    }
  }
}

fn optional_string(
  section: Dict(String, Toml),
  field: String,
) -> Result(Option(String), Error) {
  case dict.get(section, field) {
    Error(_) -> Ok(None)
    Ok(value) ->
      case tom.as_string(value) {
        Error(_) -> Error(InvalidField(field: field, expected: "String"))
        Ok(s) -> Ok(Some(s))
      }
  }
}

fn optional_string_list(
  section: Dict(String, Toml),
  field: String,
) -> Result(List(String), Error) {
  case dict.get(section, field) {
    Error(_) -> Ok([])
    Ok(value) -> {
      case tom.as_array(value) {
        Error(_) -> Error(InvalidField(field: field, expected: "List(String)"))
        Ok(values) -> strings_from_toml(values, field, [])
      }
    }
  }
}

fn strings_from_toml(
  values: List(Toml),
  field: String,
  decoded: List(String),
) -> Result(List(String), Error) {
  case values {
    [] -> Ok(list.reverse(decoded))
    [value, ..rest] -> {
      case tom.as_string(value) {
        Ok(value) -> strings_from_toml(rest, field, [value, ..decoded])
        Error(_) -> Error(InvalidField(field: field, expected: "List(String)"))
      }
    }
  }
}

fn validate(policy: Policy) -> Result(Policy, Error) {
  case has_empty_identifier(policy.allow) || has_empty_identifier(policy.deny) {
    True -> Error(InvalidLicenceIdentifier)
    False -> Ok(policy)
  }
}

fn has_empty_identifier(licences: List(String)) -> Bool {
  list.any(licences, fn(licence) { string.trim(licence) == "" })
}

fn append_unique(first: List(String), second: List(String)) -> List(String) {
  append_unique_loop(second, first)
}

fn append_unique_loop(
  to_add: List(String),
  current: List(String),
) -> List(String) {
  case to_add {
    [] -> current
    [licence, ..rest] -> {
      case list.contains(current, licence) {
        True -> append_unique_loop(rest, current)
        False -> append_unique_loop(rest, list.append(current, [licence]))
      }
    }
  }
}

fn is_empty(policy: Policy) -> Bool {
  policy.allow == [] && policy.deny == [] && policy.vuln_severity == None
}

fn key_name(key: List(String)) -> String {
  string.join(key, ".")
}
