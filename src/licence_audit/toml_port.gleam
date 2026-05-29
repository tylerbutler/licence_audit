//// Wrapper around the `tomlet` dependency for comment-preserving TOML edits.

import gleam/int
import gleam/list
import gleam/string
import tomlet

pub type Error {
  TomlError(message: String)
}

/// Replace (or create) a string array at the table named by `path` (a list of
/// segments forming nested tables) and key `key` in the provided TOML source,
/// preserving comments, formatting, and unrelated sections.
pub fn set_string_array(
  existing_toml: String,
  path: List(String),
  key: String,
  values: List(String),
) -> Result(String, Error) {
  let full_key = list.append(path, [key])
  let sentinel = array_sentinel(key, values)

  case tomlet.parse(existing_toml) {
    Error(error) -> Error(TomlError(parse_error_message(error)))
    Ok(document) ->
      case tomlet.set_string(document, full_key, sentinel) {
        Error(error) -> Error(TomlError(edit_error_message(error)))
        Ok(updated) -> {
          let output = tomlet.to_string(updated)
          let updated_output =
            rewrite_array_value(output, key, render_array_literal(values))

          case tomlet.parse(updated_output) {
            Error(_) -> Error(TomlError("failed to serialize TOML array value"))
            Ok(_) -> Ok(updated_output)
          }
        }
      }
  }
}

pub fn error_message(error: Error) -> String {
  let TomlError(message) = error
  "TOML edit failed: " <> message
}

fn array_sentinel(key: String, values: List(String)) -> String {
  "__licence_audit_array__" <> key <> "_" <> int.to_string(list.length(values))
}

fn render_array_literal(values: List(String)) -> String {
  case values {
    [] -> "[]"
    _ ->
      values
      |> list.map(quote_string)
      |> string.join(with: ", ")
      |> fn(items) { "[" <> items <> "]" }
  }
}

fn quote_string(value: String) -> String {
  let escaped =
    value
    |> string.replace(each: "\\", with: "\\\\")
    |> string.replace(each: "\"", with: "\\\"")

  "\"" <> escaped <> "\""
}

fn rewrite_array_value(
  source: String,
  key: String,
  replacement: String,
) -> String {
  case string.contains(source, "\r\n") {
    True ->
      rewrite_array_lines(
        string.split(source, on: "\r\n"),
        key,
        replacement,
        "\r\n",
      )
    False ->
      rewrite_array_lines(
        string.split(source, on: "\n"),
        key,
        replacement,
        "\n",
      )
  }
}

fn rewrite_array_lines(
  lines: List(String),
  key: String,
  replacement: String,
  line_ending: String,
) -> String {
  case lines {
    [] -> ""
    [line] -> rewrite_array_line(line, key, replacement)
    [line, ..rest] ->
      rewrite_array_line(line, key, replacement)
      <> line_ending
      <> rewrite_array_lines(rest, key, replacement, line_ending)
  }
}

fn rewrite_array_line(
  line: String,
  key: String,
  replacement: String,
) -> String {
  case string.split_once(line, "=") {
    Error(_) -> line
    Ok(#(left, right)) ->
      case string.trim(left) == key {
        False -> line
        True ->
          case string.split(right, on: "\"") {
            [prefix, _, suffix] ->
              left <> "=" <> prefix <> replacement <> suffix
            _ -> line
          }
      }
  }
}

fn parse_error_message(error: tomlet.ParseError) -> String {
  case error {
    tomlet.InvalidEncoding -> "invalid TOML encoding"
    tomlet.Unexpected(got, expected, offset) ->
      "unexpected "
      <> got
      <> ", expected "
      <> expected
      <> " at offset "
      <> int.to_string(offset)
    tomlet.KeyAlreadyInUse(key, offset) ->
      "key already in use: "
      <> path_to_string(key)
      <> " at offset "
      <> int.to_string(offset)
  }
}

fn edit_error_message(error: tomlet.EditError) -> String {
  case error {
    tomlet.EmptyKeyPath -> "empty TOML key path"
    tomlet.InvalidKeySegment(segment) -> "invalid TOML key segment: " <> segment
    tomlet.InvalidCommentText -> "invalid TOML comment text"
    tomlet.MissingEditKey(key) -> "missing TOML key: " <> path_to_string(key)
    tomlet.KeyConflict(key) -> "key conflict for: " <> path_to_string(key)
  }
}

fn path_to_string(path: List(String)) -> String {
  string.join(path, with: ".")
}
