import gleam/bool
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/order
import gleam/result
import gleam/string
import gleam/time/calendar
import gleam/time/timestamp
import licence_audit/semver
import licence_audit/toml

pub type Finding {
  DeniedLicence(String)
  UnallowedLicence(String)
  InvalidLicenceExpression(String)
  NoLicencesDeclared
  Advisory(String)
}

pub type Exception {
  Exception(
    number: Int,
    purl: String,
    finding: Finding,
    reason: String,
    expires: Option(String),
  )
}

pub type Decision {
  Unaccepted
  Excepted(Exception)
  Expired(Exception)
}

pub type Coverage {
  NotEvaluated(String)
  Evaluated(matched: List(Int), unavailable: List(#(String, String)))
}

pub type Error {
  UnknownField(String)
  NestedFields
  RequiredString(String)
  UnexpectedField(String)
  InvalidFinding
  LicenceRequiresHex
  InvalidExpiryType
  InvalidPurl
  InvalidDate
  OverlappingEntries(first: Exception, second: Exception)
  AmbiguousIdentity(Exception)
}

pub fn describe_error(error: Error) -> String {
  case error {
    UnknownField(field) -> "unknown field " <> field
    NestedFields -> "nested exception fields are not supported"
    RequiredString(field) -> field <> " must be a non-empty string"
    UnexpectedField(field) -> field <> " is not valid for this finding"
    InvalidFinding ->
      "finding must be denied-licence, unallowed-licence, no-licences-declared, or advisory"
    LicenceRequiresHex -> "licence exceptions require a pkg:hex identity"
    InvalidExpiryType -> "expires must be a quoted YYYY-MM-DD string"
    InvalidPurl ->
      "purl must be pkg:hex/<name>@<exact-version> or pkg:github/<owner>/<repo>@<full-commit> (lowercase, without qualifiers or subpaths)"
    InvalidDate -> "expires must be a valid YYYY-MM-DD date"
    OverlappingEntries(first, second) -> overlap_message(first, second)
    AmbiguousIdentity(entry) ->
      "exceptions["
      <> int.to_string(entry.number)
      <> "]: purl matches multiple locked packages: "
      <> entry.purl
  }
}

pub fn parse(table: toml.Entry, number: Int) -> Result(Exception, Error) {
  use _ <- result.try(
    list.try_each(table, fn(field) {
      case field.0 {
        [key] ->
          case
            list.contains(
              ["purl", "finding", "licence", "advisory", "reason", "expires"],
              key,
            )
          {
            True -> Ok(Nil)
            False -> Error(UnknownField(key))
          }
        _ -> Error(NestedFields)
      }
    }),
  )
  use purl <- result.try(required_string(table, "purl"))
  use _ <- result.try(validate_purl(purl))
  use kind <- result.try(required_string(table, "finding"))
  use finding <- result.try(case kind {
    "denied-licence" | "unallowed-licence" -> {
      use _ <- result.try(absent(table, "advisory"))
      use licence <- result.try(required_string(table, "licence"))
      Ok(case kind {
        "denied-licence" -> DeniedLicence(licence)
        _ -> UnallowedLicence(licence)
      })
    }
    "no-licences-declared" -> {
      use _ <- result.try(absent(table, "licence"))
      use _ <- result.try(absent(table, "advisory"))
      Ok(NoLicencesDeclared)
    }
    "advisory" -> {
      use _ <- result.try(absent(table, "licence"))
      result.map(required_string(table, "advisory"), Advisory)
    }
    _ -> Error(InvalidFinding)
  })
  use <- bool.guard(
    when: !is_advisory(finding) && !string.starts_with(purl, "pkg:hex/"),
    return: Error(LicenceRequiresHex),
  )
  use reason <- result.try(required_string(table, "reason"))
  use expires <- result.try(case toml.field(table, "expires") {
    Error(_) -> Ok(None)
    Ok(value) -> {
      use date <- result.try(
        toml.as_string(value)
        |> result.replace_error(InvalidExpiryType),
      )
      use _ <- result.try(validate_date(date))
      Ok(Some(date))
    }
  })
  Ok(Exception(number:, purl:, finding:, reason:, expires:))
}

fn required_string(table: toml.Entry, field: String) -> Result(String, Error) {
  let value =
    toml.field(table, field)
    |> result.try(toml.as_string)
  case value {
    Ok(value) ->
      case string.trim(value) == "" {
        False -> Ok(value)
        True -> Error(RequiredString(field))
      }
    Error(_) -> Error(RequiredString(field))
  }
}

fn absent(table: toml.Entry, field: String) -> Result(Nil, Error) {
  case toml.field(table, field) {
    Error(_) -> Ok(Nil)
    Ok(_) -> Error(UnexpectedField(field))
  }
}

fn characters(value: String, allowed: String) -> Bool {
  value != ""
  && list.all(string.to_graphemes(value), fn(c) { string.contains(allowed, c) })
}

fn validate_purl(purl: String) -> Result(Nil, Error) {
  let valid = case string.split(purl, "@") {
    [identity, version] ->
      case string.split(identity, "/") {
        ["pkg:hex", name] ->
          characters(name, "abcdefghijklmnopqrstuvwxyz0123456789_")
          && semver.is_valid(version)
        ["pkg:github", owner, repo] ->
          characters(owner, "abcdefghijklmnopqrstuvwxyz0123456789-")
          && characters(repo, "abcdefghijklmnopqrstuvwxyz0123456789-_.")
          && { string.length(version) == 40 || string.length(version) == 64 }
          && characters(version, "0123456789abcdef")
        _ -> False
      }
    _ -> False
  }
  case valid {
    True -> Ok(Nil)
    False -> Error(InvalidPurl)
  }
}

pub fn validate_date(date: String) -> Result(Nil, Error) {
  let parsed = timestamp.parse_rfc3339(date <> "T00:00:00Z")
  case parsed {
    Ok(value) ->
      case string.length(date) == 10 && utc_date(value) == date {
        True -> Ok(Nil)
        False -> Error(InvalidDate)
      }
    Error(_) -> Error(InvalidDate)
  }
}

pub fn utc_date(now: timestamp.Timestamp) -> String {
  now
  |> timestamp.to_rfc3339(calendar.utc_offset)
  |> string.slice(0, 10)
}

pub fn is_expired(entry: Exception, today: String) -> Bool {
  case entry.expires {
    None -> False
    Some(date) -> string.compare(today, date) == order.Gt
  }
}

fn is_advisory(finding: Finding) -> Bool {
  case finding {
    Advisory(_) -> True
    DeniedLicence(_)
    | UnallowedLicence(_)
    | InvalidLicenceExpression(_)
    | NoLicencesDeclared -> False
  }
}

pub fn validate_unique(entries: List(Exception)) -> Result(Nil, Error) {
  case entries {
    [] -> Ok(Nil)
    [entry, ..rest] ->
      case
        list.find(rest, fn(other) {
          entry.purl == other.purl && entry.finding == other.finding
        })
      {
        Ok(other) -> Error(OverlappingEntries(entry, other))
        Error(_) -> validate_unique(rest)
      }
  }
}

pub fn validate_identities(
  entries: List(Exception),
  purls: List(String),
) -> Result(Nil, Error) {
  list.try_each(entries, fn(entry) {
    case list.length(list.filter(purls, fn(purl) { purl == entry.purl })) > 1 {
      True -> Error(AmbiguousIdentity(entry))
      False -> Ok(Nil)
    }
  })
}

pub fn decide(
  entries: List(Exception),
  purl: String,
  finding: Finding,
  aliases: List(String),
  today: String,
) -> Result(Decision, Error) {
  let matches =
    list.filter(entries, fn(entry) {
      entry.purl == purl
      && case entry.finding, finding {
        Advisory(configured), Advisory(id) ->
          configured == id || list.contains(aliases, configured)
        _, _ -> entry.finding == finding
      }
    })
  case matches {
    [] -> Ok(Unaccepted)
    [entry] ->
      Ok(case is_expired(entry, today) {
        True -> Expired(entry)
        False -> Excepted(entry)
      })
    [first, second, ..] -> Error(OverlappingEntries(first, second))
  }
}

fn overlap_message(first: Exception, second: Exception) -> String {
  "exceptions["
  <> int.to_string(first.number)
  <> "] and exceptions["
  <> int.to_string(second.number)
  <> "] overlap for "
  <> first.purl
  <> "; keep one review decision for this finding"
}

pub fn accepted(decision: Decision) -> Bool {
  case decision {
    Excepted(_) -> True
    Unaccepted | Expired(_) -> False
  }
}

pub fn matched(decisions: List(Decision)) -> List(Int) {
  list.filter_map(decisions, fn(decision) {
    case decision {
      Unaccepted -> Error(Nil)
      Excepted(entry) | Expired(entry) -> Ok(entry.number)
    }
  })
}

pub fn finding_text(finding: Finding) -> String {
  case finding {
    DeniedLicence(licence) -> "denied: " <> licence
    UnallowedLicence(licence) -> "unknown: " <> licence
    InvalidLicenceExpression(licence) -> "invalid SPDX expression: " <> licence
    NoLicencesDeclared -> "no licences declared"
    Advisory(id) -> id
  }
}

pub fn decision_text(decision: Decision) -> String {
  case decision {
    Unaccepted -> ""
    Excepted(entry) -> "excepted " <> review_text(entry)
    Expired(entry) -> "expired " <> review_text(entry)
  }
}

fn review_text(entry: Exception) -> String {
  "#"
  <> int.to_string(entry.number)
  <> ": "
  <> entry.reason
  <> " ("
  <> case entry.expires {
    None -> "no expiry"
    Some(date) -> "expires " <> date <> " UTC"
  }
  <> ")"
}

pub fn summary(
  entries: List(Exception),
  today: String,
  licences: Coverage,
  advisories: Coverage,
) -> String {
  use <- bool.guard(when: entries == [], return: "")
  "\nPolicy exceptions:\n"
  <> string.join(
    list.map(entries, fn(entry) {
      let coverage = case is_advisory(entry.finding) {
        True -> advisories
        False -> licences
      }
      let state = case coverage {
        NotEvaluated(reason) -> "not evaluated: " <> reason
        Evaluated(matched, unavailable) ->
          case list.contains(matched, entry.number) {
            True -> "matched"
            False ->
              case list.key_find(unavailable, entry.purl) {
                Ok(reason) -> "not evaluated: " <> reason
                Error(_) -> "unused"
              }
          }
      }
      let state = case is_expired(entry, today), state {
        True, _ -> "expired; " <> state
        False, "matched" -> "excepted"
        False, _ -> state
      }
      "  "
      <> state
      <> " "
      <> review_text(entry)
      <> " - "
      <> entry.purl
      <> " - "
      <> finding_text(entry.finding)
    }),
    "\n",
  )
  <> "\n"
}
