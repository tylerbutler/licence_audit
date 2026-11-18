import gleam/bool
import gleam/int
import gleam/list
import gleam/order.{type Order, Eq, Gt, Lt}
import gleam/result
import gleam/string

/// Compare SemVer precedence, ignoring build metadata.
pub fn compare(left: String, right: String) -> Result(Order, Nil) {
  use <- bool.guard(
    when: !is_valid(left) || !is_valid(right),
    return: Error(Nil),
  )
  let #(left_core, left_suffix) = precedence_parts(left)
  let #(right_core, right_suffix) = precedence_parts(right)
  Ok(case compare_parts(left_core, right_core, compare_numeric) {
    Lt -> Lt
    Gt -> Gt
    Eq ->
      case left_suffix, right_suffix {
        [], [] -> Eq
        [], _ -> Gt
        _, [] -> Lt
        _, _ -> compare_parts(left_suffix, right_suffix, compare_identifier)
      }
  })
}

fn precedence_parts(version: String) -> #(List(String), List(String)) {
  let #(release, _) =
    string.split_once(version, "+") |> result.unwrap(#(version, ""))
  let #(core, suffix) =
    string.split_once(release, "-") |> result.unwrap(#(release, ""))
  #(string.split(core, "."), case suffix {
    "" -> []
    _ -> string.split(suffix, ".")
  })
}

fn compare_parts(
  left: List(String),
  right: List(String),
  compare: fn(String, String) -> Order,
) -> Order {
  case left, right {
    [], [] -> Eq
    [], _ -> Lt
    _, [] -> Gt
    [first, ..left], [second, ..right] ->
      case compare(first, second) {
        Eq -> compare_parts(left, right, compare)
        Lt -> Lt
        Gt -> Gt
      }
  }
}

fn compare_identifier(left: String, right: String) -> Order {
  case
    valid_characters(left, "0123456789"),
    valid_characters(right, "0123456789")
  {
    True, True -> compare_numeric(left, right)
    True, False -> Lt
    False, True -> Gt
    False, False -> string.compare(left, right)
  }
}

fn compare_numeric(left: String, right: String) -> Order {
  case int.compare(string.length(left), string.length(right)) {
    Eq -> string.compare(left, right)
    Lt -> Lt
    Gt -> Gt
  }
}

/// Check whether a string is a Semantic Versioning 2.0.0 version.
pub fn is_valid(version: String) -> Bool {
  case string.split(version, "+") {
    [release] -> valid_release(release)
    [release, build] ->
      valid_release(release) && valid_identifiers(build, False)
    _ -> False
  }
}

fn valid_release(release: String) -> Bool {
  let #(core, prerelease) = case string.split_once(release, "-") {
    Ok(#(core, suffix)) -> #(core, valid_identifiers(suffix, True))
    Error(_) -> #(release, True)
  }
  prerelease
  && case string.split(core, ".") {
    [major, minor, patch] ->
      list.all([major, minor, patch], valid_numeric_identifier)
    _ -> False
  }
}

fn valid_numeric_identifier(value: String) -> Bool {
  valid_characters(value, "0123456789")
  && { value == "0" || !string.starts_with(value, "0") }
}

fn valid_identifiers(value: String, prerelease: Bool) -> Bool {
  list.all(string.split(value, "."), fn(part) {
    valid_characters(
      part,
      "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-",
    )
    && {
      !prerelease
      || !valid_characters(part, "0123456789")
      || valid_numeric_identifier(part)
    }
  })
}

fn valid_characters(value: String, allowed: String) -> Bool {
  value != ""
  && list.all(string.to_graphemes(value), fn(character) {
    string.contains(allowed, character)
  })
}
