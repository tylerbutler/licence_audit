//// Shared TOML access layer for licence_audit, built on the `tomlet`
//// dependency: comment-preserving edits (`set_string_array`) plus the read
//// accessors used by manifest/config parsing.
////
//// The read accessors below walk tomlet's raw `Value` assoc lists by hand
//// because tomlet has no value-level accessors and no table-key enumeration.
//// Tracked upstream — if these land, the helpers become thin pass-throughs:
////   - value-level accessors: https://github.com/tylerbutler/tomlet/issues/22
////   - table key enumeration:  https://github.com/tylerbutler/tomlet/issues/23

import gleam/int
import gleam/list
import gleam/string
import tomlet.{type Document, type Value}

pub type Error {
  TomlError(message: String)
}

/// A table's entries as tomlet exposes them: an ordered assoc list of
/// `#(dotted_key_path, value)`. See tylerbutler/tomlet#22.
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

type QuoteMode {
  NotQuoted
  BasicString(escaped: Bool)
  LiteralString
}

type MultilineMode {
  NoMultiline
  BasicMultiline
  LiteralMultiline
}

type HeaderError {
  NoHeader
  InvalidHeader
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
/// Workaround for tylerbutler/tomlet#22 (no value-level array accessor).
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
/// Workaround for tylerbutler/tomlet#23 (no table-key enumeration).
pub fn table_keys(
  doc: Document,
  path: List(String),
) -> Result(List(String), Nil) {
  case tomlet.get(doc, path) {
    Ok(value) ->
      case as_table(value) {
        Ok(entries) -> Ok(entry_keys(entries))
        Error(_) -> Error(Nil)
      }
    Error(_) -> Error(Nil)
  }
}

/// Look up a simple (single-segment) field within a table's entries.
/// Workaround for tylerbutler/tomlet#22.
pub fn field(entry: Entry, name: String) -> Result(Value, Nil) {
  case list.find(entry, fn(pair) { pair.0 == [name] }) {
    Ok(pair) -> Ok(pair.1)
    Error(_) -> Error(Nil)
  }
}

/// Value -> String.
pub fn as_string(value: Value) -> Result(String, Nil) {
  case value {
    tomlet.StringValue(s) -> Ok(s)
    _ -> Error(Nil)
  }
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

fn entry_keys(entries: Entry) -> List(String) {
  list.filter_map(entries, fn(pair) {
    case pair.0 {
      [name, ..] -> Ok(name)
      [] -> Error(Nil)
    }
  })
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
          let #(updated_output, rewritten) =
            rewrite_array_value(
              output,
              path,
              key,
              sentinel,
              render_array_literal(values),
            )

          case rewritten {
            False -> Error(TomlError("failed to rewrite TOML array value"))
            True ->
              case tomlet.parse(updated_output) {
                Error(_) ->
                  Error(TomlError("failed to serialize TOML array value"))
                Ok(_) -> Ok(updated_output)
              }
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

fn sentinel_token(sentinel: String) -> String {
  "\"" <> sentinel <> "\""
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
  path: List(String),
  key: String,
  sentinel: String,
  replacement: String,
) -> #(String, Bool) {
  case string.contains(source, "\r\n") {
    True ->
      rewrite_array_lines(
        string.split(source, on: "\r\n"),
        path,
        [],
        True,
        0,
        NoMultiline,
        key,
        sentinel,
        replacement,
        "\r\n",
      )
    False ->
      rewrite_array_lines(
        string.split(source, on: "\n"),
        path,
        [],
        True,
        0,
        NoMultiline,
        key,
        sentinel,
        replacement,
        "\n",
      )
  }
}

fn rewrite_array_lines(
  lines: List(String),
  path: List(String),
  active_path: List(String),
  active_standard: Bool,
  depth: Int,
  multiline: MultilineMode,
  key: String,
  sentinel: String,
  replacement: String,
  line_ending: String,
) -> #(String, Bool) {
  case lines {
    [] -> #("", False)
    [line] -> {
      let #(current_path, current_standard) =
        current_table_scope(
          line,
          active_path,
          active_standard,
          depth,
          multiline,
        )
      rewrite_array_line(
        line,
        depth == 0
          && multiline == NoMultiline
          && current_standard
          && current_path == path,
        key,
        sentinel,
        replacement,
      )
    }
    [line, ..rest] -> {
      let #(current_path, current_standard) =
        current_table_scope(
          line,
          active_path,
          active_standard,
          depth,
          multiline,
        )
      let #(rewritten_line, line_changed) =
        rewrite_array_line(
          line,
          depth == 0
            && multiline == NoMultiline
            && current_standard
            && current_path == path,
          key,
          sentinel,
          replacement,
        )
      let #(rewritten_rest, rest_changed) =
        rewrite_array_lines(
          rest,
          path,
          current_path,
          current_standard,
          next_depth(line, depth, multiline),
          next_multiline_mode(line, multiline),
          key,
          sentinel,
          replacement,
          line_ending,
        )

      #(
        rewritten_line <> line_ending <> rewritten_rest,
        line_changed || rest_changed,
      )
    }
  }
}

fn rewrite_array_line(
  line: String,
  in_target_table: Bool,
  key: String,
  sentinel: String,
  replacement: String,
) -> #(String, Bool) {
  case in_target_table {
    False -> #(line, False)
    True ->
      case string.split_once(line, "=") {
        Error(_) -> #(line, False)
        Ok(#(left, right)) ->
          case assignment_key_matches(left, key) {
            False -> #(line, False)
            True -> {
              case string.split_once(right, sentinel_token(sentinel)) {
                Error(_) -> #(line, False)
                Ok(#(prefix, suffix)) -> #(
                  left <> "=" <> prefix <> replacement <> suffix,
                  True,
                )
              }
            }
          }
      }
  }
}

fn assignment_key_matches(left: String, key: String) -> Bool {
  case quoted_assignment_key(string.trim(left)) {
    Ok(parsed) -> parsed == key
    Error(_) -> string.trim(left) == key
  }
}

fn quoted_assignment_key(source: String) -> Result(String, Nil) {
  case string.starts_with(source, "\"") {
    True -> quoted_assignment_key_with(source, "\"")
    False ->
      case string.starts_with(source, "'") {
        True -> quoted_assignment_key_with(source, "'")
        False -> Error(Nil)
      }
  }
}

fn quoted_assignment_key_with(
  source: String,
  quote: String,
) -> Result(String, Nil) {
  case string.split_once(string.drop_start(source, 1), quote) {
    Ok(#(inside, suffix)) ->
      case string.trim(suffix) == "" {
        True -> Ok(inside)
        False -> Error(Nil)
      }
    _ -> Error(Nil)
  }
}

fn current_table_scope(
  line: String,
  active_path: List(String),
  active_standard: Bool,
  depth: Int,
  multiline: MultilineMode,
) -> #(List(String), Bool) {
  case depth == 0 && multiline == NoMultiline {
    False -> #(active_path, active_standard)
    True -> {
      case table_header_scope(line) {
        Ok(scope) -> scope
        Error(NoHeader) -> #(active_path, active_standard)
        Error(InvalidHeader) -> #([], False)
      }
    }
  }
}

fn table_header_scope(
  line: String,
) -> Result(#(List(String), Bool), HeaderError) {
  let trimmed = string.trim(line)

  case string.starts_with(trimmed, "[[") {
    True -> parse_table_header_path(string.drop_start(trimmed, 2), "]]", False)
    False ->
      case string.starts_with(trimmed, "[") {
        True ->
          parse_table_header_path(string.drop_start(trimmed, 1), "]", True)
        False -> Error(NoHeader)
      }
  }
}

fn parse_table_header_path(
  source: String,
  closing: String,
  standard: Bool,
) -> Result(#(List(String), Bool), HeaderError) {
  case string.split_once(source, closing) {
    Error(_) -> Error(InvalidHeader)
    Ok(#(inside, suffix)) ->
      case valid_table_header_suffix(suffix) {
        False -> Error(InvalidHeader)
        True ->
          case parse_header_path(inside) {
            Ok(path) -> Ok(#(path, standard))
            Error(_) -> Error(InvalidHeader)
          }
      }
  }
}

fn valid_table_header_suffix(suffix: String) -> Bool {
  let trimmed = string.trim(suffix)
  string.is_empty(trimmed) || string.starts_with(trimmed, "#")
}

fn parse_header_path(source: String) -> Result(List(String), Nil) {
  parse_header_graphemes(string.to_graphemes(source), [], False, [], NotQuoted)
}

fn parse_header_graphemes(
  graphemes: List(String),
  current_rev: List(String),
  current_quoted: Bool,
  segments_rev: List(String),
  mode: QuoteMode,
) -> Result(List(String), Nil) {
  case graphemes, mode {
    [], NotQuoted ->
      Ok(finish_header_path(current_rev, current_quoted, segments_rev))
    [], _ -> Error(Nil)
    [".", ..rest], NotQuoted ->
      parse_header_graphemes(
        rest,
        [],
        False,
        finish_header_segment(current_rev, current_quoted, segments_rev),
        NotQuoted,
      )
    ["\"", ..rest], NotQuoted ->
      parse_header_graphemes(
        rest,
        current_rev,
        True,
        segments_rev,
        BasicString(False),
      )
    ["'", ..rest], NotQuoted ->
      parse_header_graphemes(
        rest,
        current_rev,
        True,
        segments_rev,
        LiteralString,
      )
    [grapheme, ..rest], NotQuoted ->
      parse_header_graphemes(
        rest,
        [grapheme, ..current_rev],
        current_quoted,
        segments_rev,
        NotQuoted,
      )
    [grapheme, ..rest], BasicString(True) ->
      parse_header_graphemes(
        rest,
        [grapheme, ..current_rev],
        current_quoted,
        segments_rev,
        BasicString(False),
      )
    ["\\", ..rest], BasicString(False) ->
      parse_header_graphemes(
        rest,
        current_rev,
        current_quoted,
        segments_rev,
        BasicString(True),
      )
    ["\"", ..rest], BasicString(False) ->
      parse_header_graphemes(
        rest,
        current_rev,
        current_quoted,
        segments_rev,
        NotQuoted,
      )
    [grapheme, ..rest], BasicString(False) ->
      parse_header_graphemes(
        rest,
        [grapheme, ..current_rev],
        current_quoted,
        segments_rev,
        BasicString(False),
      )
    ["'", ..rest], LiteralString ->
      parse_header_graphemes(
        rest,
        current_rev,
        current_quoted,
        segments_rev,
        NotQuoted,
      )
    [grapheme, ..rest], LiteralString ->
      parse_header_graphemes(
        rest,
        [grapheme, ..current_rev],
        current_quoted,
        segments_rev,
        LiteralString,
      )
  }
}

fn finish_header_path(
  current_rev: List(String),
  current_quoted: Bool,
  segments_rev: List(String),
) -> List(String) {
  finish_header_segment(current_rev, current_quoted, segments_rev)
  |> list.reverse
}

fn finish_header_segment(
  current_rev: List(String),
  current_quoted: Bool,
  segments_rev: List(String),
) -> List(String) {
  [
    current_rev
      |> list.reverse
      |> string.join(with: "")
      |> finish_header_key(current_quoted),
    ..segments_rev
  ]
}

fn finish_header_key(key: String, quoted: Bool) -> String {
  case quoted {
    True -> key
    False -> string.trim(key)
  }
}

fn next_depth(line: String, depth: Int, multiline: MultilineMode) -> Int {
  case multiline {
    NoMultiline -> scan_depth(string.to_graphemes(line), depth, NotQuoted)
    _ ->
      scan_depth_after_multiline_close(
        string.to_graphemes(line),
        depth,
        multiline,
      )
  }
}

fn scan_depth_after_multiline_close(
  graphemes: List(String),
  depth: Int,
  multiline: MultilineMode,
) -> Int {
  case graphemes, multiline {
    [], _ -> depth
    ["\"", "\"", "\"", ..rest], BasicMultiline ->
      scan_depth(rest, depth, NotQuoted)
    ["'", "'", "'", ..rest], LiteralMultiline ->
      scan_depth(rest, depth, NotQuoted)
    [_, ..rest], _ -> scan_depth_after_multiline_close(rest, depth, multiline)
  }
}

fn scan_depth(graphemes: List(String), depth: Int, mode: QuoteMode) -> Int {
  case graphemes, mode {
    [], _ -> depth
    ["#", ..], NotQuoted -> depth
    ["\"", "\"", "\"", ..rest], NotQuoted ->
      scan_depth_after_multiline_close(rest, depth, BasicMultiline)
    ["'", "'", "'", ..rest], NotQuoted ->
      scan_depth_after_multiline_close(rest, depth, LiteralMultiline)
    ["\"", ..rest], NotQuoted -> scan_depth(rest, depth, BasicString(False))
    ["'", ..rest], NotQuoted -> scan_depth(rest, depth, LiteralString)
    ["[", ..rest], NotQuoted -> scan_depth(rest, depth + 1, NotQuoted)
    ["{", ..rest], NotQuoted -> scan_depth(rest, depth + 1, NotQuoted)
    ["]", ..rest], NotQuoted ->
      scan_depth(rest, decrement_depth(depth), NotQuoted)
    ["}", ..rest], NotQuoted ->
      scan_depth(rest, decrement_depth(depth), NotQuoted)
    [_, ..rest], NotQuoted -> scan_depth(rest, depth, NotQuoted)
    [_, ..rest], BasicString(True) ->
      scan_depth(rest, depth, BasicString(False))
    ["\\", ..rest], BasicString(False) ->
      scan_depth(rest, depth, BasicString(True))
    ["\"", ..rest], BasicString(False) -> scan_depth(rest, depth, NotQuoted)
    [_, ..rest], BasicString(False) ->
      scan_depth(rest, depth, BasicString(False))
    ["'", ..rest], LiteralString -> scan_depth(rest, depth, NotQuoted)
    [_, ..rest], LiteralString -> scan_depth(rest, depth, LiteralString)
  }
}

fn next_multiline_mode(line: String, mode: MultilineMode) -> MultilineMode {
  scan_multiline_mode(string.to_graphemes(line), mode, NotQuoted)
}

fn scan_multiline_mode(
  graphemes: List(String),
  multiline: MultilineMode,
  quote: QuoteMode,
) -> MultilineMode {
  case graphemes, multiline, quote {
    [], mode, _ -> mode
    ["\"", "\"", "\"", ..rest], NoMultiline, NotQuoted ->
      scan_multiline_mode(rest, BasicMultiline, NotQuoted)
    ["'", "'", "'", ..rest], NoMultiline, NotQuoted ->
      scan_multiline_mode(rest, LiteralMultiline, NotQuoted)
    ["\"", "\"", "\"", ..rest], BasicMultiline, _ ->
      scan_multiline_mode(rest, NoMultiline, NotQuoted)
    ["'", "'", "'", ..rest], LiteralMultiline, _ ->
      scan_multiline_mode(rest, NoMultiline, NotQuoted)
    ["#", ..], NoMultiline, NotQuoted -> NoMultiline
    ["\"", ..rest], NoMultiline, NotQuoted ->
      scan_multiline_mode(rest, NoMultiline, BasicString(False))
    ["'", ..rest], NoMultiline, NotQuoted ->
      scan_multiline_mode(rest, NoMultiline, LiteralString)
    [_, ..rest], NoMultiline, NotQuoted ->
      scan_multiline_mode(rest, NoMultiline, NotQuoted)
    [_, ..rest], NoMultiline, BasicString(True) ->
      scan_multiline_mode(rest, NoMultiline, BasicString(False))
    ["\\", ..rest], NoMultiline, BasicString(False) ->
      scan_multiline_mode(rest, NoMultiline, BasicString(True))
    ["\"", ..rest], NoMultiline, BasicString(False) ->
      scan_multiline_mode(rest, NoMultiline, NotQuoted)
    [_, ..rest], NoMultiline, BasicString(False) ->
      scan_multiline_mode(rest, NoMultiline, BasicString(False))
    ["'", ..rest], NoMultiline, LiteralString ->
      scan_multiline_mode(rest, NoMultiline, NotQuoted)
    [_, ..rest], NoMultiline, LiteralString ->
      scan_multiline_mode(rest, NoMultiline, LiteralString)
    [_, ..rest], BasicMultiline, _ ->
      scan_multiline_mode(rest, BasicMultiline, NotQuoted)
    [_, ..rest], LiteralMultiline, _ ->
      scan_multiline_mode(rest, LiteralMultiline, NotQuoted)
  }
}

fn decrement_depth(depth: Int) -> Int {
  case depth > 0 {
    True -> depth - 1
    False -> 0
  }
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
