//// Bridge to the Rust `licence_audit_toml` port program.
////
//// The port program performs comment-preserving edits to TOML documents
//// using the Rust `toml_edit` crate. It is invoked as a one-shot
//// subprocess: one JSON request line in, one JSON response line out.

import gleam/dynamic/decode
import gleam/json
import gleam/result
import gleam/string

pub type Error {
  BinaryMissing(path: String)
  SpawnFailed(message: String)
  ProtocolError(message: String)
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
  let request =
    json.object([
      #("op", json.string("set_string_array")),
      #("input", json.string(existing_toml)),
      #("path", json.array(path, of: json.string)),
      #("key", json.string(key)),
      #("values", json.array(values, of: json.string)),
    ])
    |> json.to_string

  use raw <- result.try(invoke(request))
  decode_response(raw)
}

fn invoke(request: String) -> Result(String, Error) {
  let path = binary_path()
  case run_port(path, request) {
    Ok(bytes) -> Ok(bytes)
    Error(message) ->
      case string.contains(message, "binary not found") {
        True -> Error(BinaryMissing(path))
        False -> Error(SpawnFailed(message))
      }
  }
}

fn decode_response(raw: String) -> Result(String, Error) {
  let decoder = {
    use ok <- decode.field("ok", decode.bool)
    use output <- decode.optional_field("output", "", decode.string)
    use err <- decode.optional_field("error", "", decode.string)
    decode.success(#(ok, output, err))
  }
  case json.parse(raw, using: decoder) {
    Ok(#(True, output, _)) -> Ok(output)
    Ok(#(False, _, message)) -> Error(TomlError(message))
    Error(_) ->
      Error(ProtocolError("invalid JSON response: " <> truncate(raw, 200)))
  }
}

/// Returns the absolute path the port module *would* use for the binary on
/// this platform. Exposed so callers and tests can detect missing binaries
/// up front.
pub fn binary_path() -> String {
  priv_dir() <> "/" <> binary_name()
}

pub fn error_message(error: Error) -> String {
  case error {
    BinaryMissing(path) ->
      "TOML port binary not found at "
      <> path
      <> ". Run `just build-port` (requires Rust toolchain)."
    SpawnFailed(message) -> "Failed to invoke TOML port: " <> message
    ProtocolError(message) -> "TOML port protocol error: " <> message
    TomlError(message) -> "TOML edit failed: " <> message
  }
}

fn truncate(s: String, n: Int) -> String {
  case string.length(s) > n {
    True -> string.slice(s, at_index: 0, length: n) <> "..."
    False -> s
  }
}

@external(erlang, "licence_audit_toml_ffi", "priv_dir")
fn priv_dir() -> String

@external(erlang, "licence_audit_toml_ffi", "binary_name")
fn binary_name() -> String

@external(erlang, "licence_audit_toml_ffi", "run_port")
fn run_port(binary_path: String, request: String) -> Result(String, String)
