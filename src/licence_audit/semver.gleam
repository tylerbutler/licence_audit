import gleam/list
import gleam/string

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
