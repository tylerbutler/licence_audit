//// Resolution of declared SPDX licence identifiers and expressions to their
//// canonical licence text.
////
//// The canonical text is fetched from a pinned, immutable revision of the SPDX
//// License List data repository so results are reproducible: the same
//// identifier always yields byte-identical text regardless of when the fetch
//// happens. Detail records are served as JSON from `raw.githubusercontent.com`
//// at the pinned commit; the `licenseText` (for licences) and
//// `licenseExceptionText` (for `WITH` exceptions) fields carry the text
//// verbatim.
////
//// A declared licence may be a bare identifier (`Apache-2.0`) or a compound
//// expression (`(MIT OR Apache-2.0) WITH LLVM-exception`). Expressions are
//// reduced to the *set* of identifiers they reference: for an `OR` all
//// alternatives are included (we never try to pick a "best" one), and `AND`
//// obviously needs all operands. `LicenseRef-*`/`DocumentRef-*` custom
//// references have no canonical text and make an expression unresolvable.

import gleam/bool
import gleam/dynamic/decode
import gleam/http.{Get, Https}
import gleam/http/request.{type Request, Request}
import gleam/json
import gleam/list
import gleam/option.{None}
import gleam/result
import gleam/string

/// Immutable commit in `spdx/license-list-data`, pinned to the v3.28.0
/// release. Pinning to a commit (not a tag) guarantees the fetched text can
/// never drift.
pub const license_list_commit = "c4a7237ec8f4654e867546f9f409749300f1bf4c"

/// An identifier referenced by a declared licence expression.
pub type Requirement {
  /// An SPDX licence identifier, e.g. `Apache-2.0` (any trailing `+` stripped).
  LicenseRequirement(id: String)
  /// An SPDX licence exception identifier appearing after `WITH`.
  ExceptionRequirement(id: String)
}

pub type IndexKind {
  LicenceIndex
  ExceptionIndex
}

/// Reduce a list of declared licence strings (each a bare identifier or an
/// expression) to the deduplicated set of SPDX identifiers whose canonical text
/// is required. Returns `Error(Nil)` if any declared string references a
/// `LicenseRef-`/`DocumentRef-` custom licence, which cannot be resolved to
/// canonical text.
pub fn required_identifiers(
  declared: List(String),
) -> Result(List(Requirement), Nil) {
  use nested <- result.try(list.try_map(declared, identifiers_of))
  Ok(dedupe(list.flatten(nested)))
}

/// Reduce a single declared licence string to its required identifiers.
pub fn identifiers_of(expression: String) -> Result(List(Requirement), Nil) {
  let tokens = tokenize(expression)
  classify(tokens, expect_exception: False, acc: [])
}

fn classify(
  tokens: List(String),
  expect_exception expect_exception: Bool,
  acc acc: List(Requirement),
) -> Result(List(Requirement), Nil) {
  case tokens {
    [] -> Ok(list.reverse(acc))
    [token, ..rest] ->
      case string.uppercase(token), expect_exception {
        "AND", False | "OR", False ->
          classify(rest, expect_exception: False, acc: acc)
        "WITH", False -> classify(rest, expect_exception: True, acc: acc)
        _, True ->
          classify(rest, expect_exception: False, acc: [
            ExceptionRequirement(id: token),
            ..acc
          ])
        _, False -> {
          let id = drop_trailing_plus(token)
          case is_custom_ref(id) {
            True -> Error(Nil)
            False ->
              classify(rest, expect_exception: False, acc: [
                LicenseRequirement(id: id),
                ..acc
              ])
          }
        }
      }
  }
}

fn is_custom_ref(id: String) -> Bool {
  string.starts_with(id, "LicenseRef-")
  || string.starts_with(id, "DocumentRef-")
}

/// Split an expression into operand/keyword tokens, treating parentheses as
/// delimiters and collapsing surrounding whitespace.
fn tokenize(expression: String) -> List(String) {
  expression
  |> string.replace("(", " ")
  |> string.replace(")", " ")
  |> string.split(on: " ")
  |> list.map(string.trim)
  |> list.filter(fn(token) { token != "" })
}

fn drop_trailing_plus(id: String) -> String {
  use <- bool.guard(when: !string.ends_with(id, "+"), return: id)
  string.drop_end(id, 1)
}

fn dedupe(items: List(Requirement)) -> List(Requirement) {
  list.fold(items, [], fn(seen, item) {
    case list.contains(seen, item) {
      True -> seen
      False -> [item, ..seen]
    }
  })
  |> list.reverse
}

/// Synthetic archive path a resolved SPDX record is rendered under, clearly
/// labelling it as canonical text synthesized from the SPDX License List rather
/// than material shipped in the package source.
pub fn synthetic_path(requirement: Requirement) -> String {
  case requirement {
    LicenseRequirement(id) -> "SPDX-License-List/" <> id <> ".txt"
    ExceptionRequirement(id) -> "SPDX-License-List/exceptions/" <> id <> ".txt"
  }
}

/// Build the request that fetches the JSON detail record for a requirement from
/// the pinned SPDX License List revision.
pub fn detail_request(requirement: Requirement) -> Request(String) {
  let path = case requirement {
    LicenseRequirement(id) -> "json/details/" <> id <> ".json"
    ExceptionRequirement(id) -> "json/exceptions/" <> id <> ".json"
  }
  Request(
    method: Get,
    headers: [#("accept", "application/json")],
    body: "",
    scheme: Https,
    host: "raw.githubusercontent.com",
    port: None,
    path: "/spdx/license-list-data/" <> license_list_commit <> "/" <> path,
    query: None,
  )
}

/// Build the request for the pinned SPDX licence or exception index. The index
/// supplies canonical identifier casing before detail records are requested.
pub fn index_request(kind: IndexKind) -> Request(String) {
  let path = case kind {
    LicenceIndex -> "json/licenses.json"
    ExceptionIndex -> "json/exceptions.json"
  }
  Request(
    method: Get,
    headers: [#("accept", "application/json")],
    body: "",
    scheme: Https,
    host: "raw.githubusercontent.com",
    port: None,
    path: "/spdx/license-list-data/" <> license_list_commit <> "/" <> path,
    query: None,
  )
}

pub fn index_kind(requirement: Requirement) -> IndexKind {
  case requirement {
    LicenseRequirement(_) -> LicenceIndex
    ExceptionRequirement(_) -> ExceptionIndex
  }
}

pub fn index_slug(kind: IndexKind) -> String {
  case kind {
    LicenceIndex -> "licenses"
    ExceptionIndex -> "exceptions"
  }
}

/// Decode the canonical identifiers from a pinned SPDX index response.
pub fn decode_index(
  kind: IndexKind,
  body: String,
) -> Result(List(String), Nil) {
  let decoder = case kind {
    LicenceIndex ->
      decode.field(
        "licenses",
        decode.list(decode.field("licenseId", decode.string, decode.success)),
        decode.success,
      )
    ExceptionIndex ->
      decode.field(
        "exceptions",
        decode.list(decode.field(
          "licenseExceptionId",
          decode.string,
          decode.success,
        )),
        decode.success,
      )
  }
  json.parse(body, decoder)
  |> result.replace_error(Nil)
}

pub fn encode_index(ids: List(String)) -> String {
  json.to_string(json.array(ids, json.string))
}

pub fn decode_cached_index(encoded: String) -> Result(List(String), Nil) {
  json.parse(encoded, decode.list(decode.string))
  |> result.replace_error(Nil)
}

/// Normalize an identifier to the exact casing used by the pinned SPDX list.
/// SPDX identifiers are case-insensitive, while the raw GitHub paths are not.
pub fn canonical_requirement(
  requirement: Requirement,
  canonical_ids: List(String),
) -> Result(Requirement, Nil) {
  let requested = requirement_id(requirement)
  use canonical <- result.try(
    list.find(canonical_ids, fn(id) {
      string.lowercase(id) == string.lowercase(requested)
    }),
  )
  Ok(case requirement {
    LicenseRequirement(_) -> LicenseRequirement(canonical)
    ExceptionRequirement(_) -> ExceptionRequirement(canonical)
  })
}

fn requirement_id(requirement: Requirement) -> String {
  case requirement {
    LicenseRequirement(id) | ExceptionRequirement(id) -> id
  }
}

/// Extract the canonical text from a fetched detail-record body. Uses
/// `licenseText` for licences and `licenseExceptionText` for exceptions.
/// Returns `Error(Nil)` when the field is absent (e.g. an unknown identifier's
/// 404 body).
pub fn decode_text(
  requirement: Requirement,
  body: String,
) -> Result(String, Nil) {
  let field = case requirement {
    LicenseRequirement(_) -> "licenseText"
    ExceptionRequirement(_) -> "licenseExceptionText"
  }
  json.parse(body, decode.field(field, decode.string, decode.success))
  |> result.replace_error(Nil)
  |> result.try(fn(text) {
    case text {
      "" -> Error(Nil)
      _ -> Ok(text)
    }
  })
}
