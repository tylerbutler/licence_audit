//// Shared TOML access layer for licence_audit, built on the `tomlet`
//// dependency: comment-preserving array edits (`set_string_array`) plus the
//// read accessors used by manifest/config parsing.
////
//// These are thin wrappers over tomlet's own accessors (`get`, `table_keys`,
//// `as_string`, `set_array`, …), adapting tomlet's rich error types to the
//// simpler `Error(Nil)` / domain errors the callers expect.

import gleam/int
import gleam/list
import gleam/result
import gleam/string
import tomlet.{type Document, type Value}

pub type Error {
  TomlError(message: String)
}

/// A table's entries as tomlet exposes them: an ordered assoc list of
/// `#(dotted_key_path, value)`.
pub type Entry =
  List(#(List(String), Value))

pub type ArrayError {
  ArrayMissing
  ArrayNotArray
}

pub type TableLookupError {
  TableLookupMissing
  TableLookupNotTable
}

/// Parse TOML source, collapsing tomlet's rich parse error to `Error(Nil)`.
pub fn parse(input: String) -> Result(Document, Nil) {
  case tomlet.parse(input) {
    Ok(doc) -> Ok(doc)
    Error(_) -> Error(Nil)
  }
}

/// Read a top-level (or path-addressed) string scalar.
pub fn get_string(doc: Document, path: List(String)) -> Result(String, Nil) {
  case tomlet.get_string(doc, path) {
    Ok(value) -> Ok(value)
    Error(_) -> Error(Nil)
  }
}

/// Read the array at `path` as its item values.
pub fn get_array(
  doc: Document,
  path: List(String),
) -> Result(List(Value), ArrayError) {
  case tomlet.get(doc, path) {
    Error(_) -> Error(ArrayMissing)
    Ok(tomlet.ArrayValue(items)) -> Ok(items)
    Ok(_) -> Error(ArrayNotArray)
  }
}

/// Read the table at `path` as its entry assoc list.
pub fn get_table(
  doc: Document,
  path: List(String),
) -> Result(Entry, TableLookupError) {
  case tomlet.get(doc, path) {
    Error(_) -> Error(TableLookupMissing)
    Ok(value) ->
      case as_table(value) {
        Ok(entries) -> Ok(entries)
        Error(_) -> Error(TableLookupNotTable)
      }
  }
}

/// Top-level keys of the table at `path`, in source order. `Error(Nil)` when
/// the path is absent or is not a table.
pub fn table_keys(
  doc: Document,
  path: List(String),
) -> Result(List(String), Nil) {
  tomlet.table_keys(doc, path)
  |> result.replace_error(Nil)
}

/// Look up a simple (single-segment) field within a table's entries.
pub fn field(entry: Entry, name: String) -> Result(Value, Nil) {
  case list.find(entry, fn(pair) { pair.0 == [name] }) {
    Ok(pair) -> Ok(pair.1)
    Error(_) -> Error(Nil)
  }
}

/// Value -> String.
pub fn as_string(value: Value) -> Result(String, Nil) {
  tomlet.as_string(value)
  |> result.replace_error(Nil)
}

/// Value -> array item list.
pub fn as_array(value: Value) -> Result(List(Value), Nil) {
  case value {
    tomlet.ArrayValue(items) -> Ok(items)
    _ -> Error(Nil)
  }
}

/// Value -> table entries (standard or inline table).
pub fn as_table(value: Value) -> Result(Entry, Nil) {
  case value {
    tomlet.StandardTableValue(entries) -> Ok(entries)
    tomlet.InlineTableValue(entries) -> Ok(entries)
    _ -> Error(Nil)
  }
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
  let items = list.map(values, tomlet.StringValue)

  case tomlet.parse(existing_toml) {
    Error(error) -> Error(TomlError(parse_error_message(error)))
    Ok(document) ->
      case tomlet.set_array(document, full_key, items) {
        Error(error) -> Error(TomlError(edit_error_message(error)))
        Ok(updated) -> Ok(tomlet.to_string(updated))
      }
  }
}

pub fn error_message(error: Error) -> String {
  let TomlError(message) = error
  "TOML edit failed: " <> message
}

fn parse_error_message(error: tomlet.ParseError) -> String {
  case error {
    tomlet.InvalidEncoding -> "invalid TOML encoding"
    tomlet.InvalidSyntax(kind, offset) ->
      "invalid TOML syntax ("
      <> syntax_error_kind_message(kind)
      <> ") at offset "
      <> int.to_string(offset)
    tomlet.DuplicateKey(key, offset) ->
      "duplicate key: "
      <> path_to_string(key)
      <> " at offset "
      <> int.to_string(offset)
  }
}

fn syntax_error_kind_message(kind: tomlet.SyntaxErrorKind) -> String {
  case kind {
    tomlet.ExpectedValue -> "expected a value"
    tomlet.ExpectedKey -> "expected a key"
    tomlet.ExpectedTableHeader -> "expected a table header"
    tomlet.InvalidToml -> "invalid TOML"
  }
}

fn edit_error_message(error: tomlet.EditError) -> String {
  case error {
    tomlet.EmptyKeyPath -> "empty TOML key path"
    tomlet.InvalidKeySegment(segment) -> "invalid TOML key segment: " <> segment
    tomlet.InvalidCommentText -> "invalid TOML comment text"
    tomlet.MissingEditKey(key) -> "missing TOML key: " <> path_to_string(key)
    tomlet.KeyConflict(key) -> "key conflict for: " <> path_to_string(key)
    tomlet.InlineTableInsertUnsupported(key) ->
      "cannot insert into inline table: " <> path_to_string(key)
    tomlet.InvalidValue -> "value cannot be represented in this edit context"
  }
}

fn path_to_string(path: List(String)) -> String {
  string.join(path, with: ".")
}
