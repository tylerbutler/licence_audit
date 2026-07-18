//// OSV.dev REST client.
////
//// Two endpoints are used:
////   - `POST /v1/querybatch` — given a list of purls, returns the
////     vulnerability IDs that affect each one.
////   - `GET  /v1/vulns/{id}` — returns the full advisory record for an ID
////     so we can extract a severity bucket and a human summary.
////
//// All public functions accept an injected HTTP client (mirroring
//// `licence_audit/hex`) so callers can drive the decoder/dispatch logic
//// from tests without performing real network I/O.

import gleam/bool
import gleam/dynamic/decode
import gleam/http.{Get, Https, Post}
import gleam/http/request.{type Request, Request}
import gleam/http/response.{type Response}
import gleam/int
import gleam/json
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/string
import licence_audit/httpc_adaptive

pub type Severity {
  Low
  Medium
  High
  Critical
  UnknownSeverity
}

/// A single CVSS score as reported by OSV's `severity[]` array. `kind` is the
/// OSV score type (e.g. "CVSS_V3"); `vector` is the raw CVSS vector string
/// (e.g. "CVSS:3.1/AV:N/..."). Retained so callers can surface the full vector
/// rather than only the coarse `Severity` bucket derived from it.
pub type Score {
  Score(kind: String, vector: String)
}

pub type Vulnerability {
  Vulnerability(
    id: String,
    summary: String,
    severity: Severity,
    scores: List(Score),
  )
}

/// A single per-purl result from `/v1/querybatch`.
pub type BatchEntry {
  BatchEntry(purl: String, vuln_ids: List(String))
}

type BatchPageEntry {
  BatchPageEntry(
    purl: String,
    vuln_ids: List(String),
    next_page_token: Option(String),
  )
}

pub type Error {
  InvalidJson(String)
  InvalidResponse(String)
  RateLimited
  NotFound
  UnexpectedResponse(status: Int)
  NetworkFailure
}

const osv_host = "api.osv.dev"

const osv_timeout_ms = 8000

const max_batch_pages = 32

// --- High-level injectable API -------------------------------------------

/// Query OSV for vulnerabilities affecting each of `purls`. Returns one
/// `BatchEntry` per input purl, preserving input order. Empty `vuln_ids`
/// means OSV reports no known vulnerabilities for that purl.
pub fn query_batch(
  purls: List(String),
  client: fn(Request(String)) -> Result(Response(String), Error),
) -> Result(List(BatchEntry), Error) {
  case purls {
    [] -> Ok([])
    _ ->
      case fetch_batch_page(purls, initial_page_tokens(purls), client) {
        Error(error) -> Error(error)
        Ok(entries) -> follow_paginated_entries(entries, client)
      }
  }
}

/// Fetch the full advisory record for a single OSV vulnerability ID.
fn fetch_vulnerability(
  id: String,
  client: fn(Request(String)) -> Result(Response(String), Error),
) -> Result(Vulnerability, Error) {
  let req = vuln_request(id)
  case client(req) {
    Error(error) -> Error(error)
    Ok(response) -> decode_vuln_response(response, id)
  }
}

// --- Default HTTP client (httpc, mirrors hex.gleam) ----------------------

/// Default OSV client. Suitable for the small number of requests a single
/// `licence_audit vulns` run makes.
pub fn query_batch_from_osv(
  purls: List(String),
) -> Result(List(BatchEntry), Error) {
  query_batch(purls, send)
}

pub fn fetch_vulnerability_from_osv(
  id: String,
) -> Result(Vulnerability, Error) {
  fetch_vulnerability(id, send)
}

/// Dispatches the request synchronously via Erlang's built-in `httpc`
/// (TLS verified by default).
fn send(req: Request(String)) -> Result(Response(String), Error) {
  let req =
    req
    |> request.set_header("user-agent", "licence_audit")
    |> request.set_header("accept", "application/json")
  let req = case req.method {
    Post -> request.set_header(req, "content-type", "application/json")
    _ -> req
  }
  case httpc_adaptive.dispatch(req, timeout_ms: osv_timeout_ms) {
    Ok(response) -> Ok(response)
    Error(_) -> Error(NetworkFailure)
  }
}

// --- Request construction ------------------------------------------------

fn batch_request(body: String) -> Request(String) {
  Request(
    method: Post,
    headers: [],
    body: body,
    scheme: Https,
    host: osv_host,
    port: None,
    path: "/v1/querybatch",
    query: None,
  )
}

fn vuln_request(id: String) -> Request(String) {
  Request(
    method: Get,
    headers: [],
    body: "",
    scheme: Https,
    host: osv_host,
    port: None,
    path: "/v1/vulns/" <> id,
    query: None,
  )
}

// --- Body encoding -------------------------------------------------------

pub fn encode_batch_body(purls: List(String)) -> String {
  encode_batch_body_with_tokens(list.map(purls, fn(purl) { #(purl, None) }))
}

fn encode_batch_body_with_tokens(
  purls: List(#(String, Option(String))),
) -> String {
  let queries =
    list.map(purls, fn(entry) {
      let #(purl, page_token) = entry
      let fields = [
        #("package", json.object([#("purl", json.string(purl))])),
      ]
      let fields = case page_token {
        None -> fields
        Some(token) -> [#("page_token", json.string(token)), ..fields]
      }
      json.object(fields)
    })

  json.object([#("queries", json.preprocessed_array(queries))])
  |> json.to_string
}

// --- Response decoding ---------------------------------------------------

fn fetch_batch_page(
  purls: List(String),
  page_tokens: List(Option(String)),
  client: fn(Request(String)) -> Result(Response(String), Error),
) -> Result(List(BatchPageEntry), Error) {
  let body =
    encode_batch_body_with_tokens(
      list.map2(purls, page_tokens, fn(purl, token) { #(purl, token) }),
    )
  let req = batch_request(body)
  case client(req) {
    Error(error) -> Error(error)
    Ok(response) -> decode_batch_response(response, purls)
  }
}

fn decode_batch_response(
  response: Response(String),
  purls: List(String),
) -> Result(List(BatchPageEntry), Error) {
  case response.status {
    404 -> Error(NotFound)
    429 -> Error(RateLimited)
    status if status >= 200 && status < 300 ->
      decode_batch_body(response.body, purls)
    status -> Error(UnexpectedResponse(status: status))
  }
}

fn decode_batch_body(
  body: String,
  purls: List(String),
) -> Result(List(BatchPageEntry), Error) {
  case json.parse(body, using: batch_results_decoder()) {
    Error(json.UnableToDecode(_)) ->
      Error(InvalidResponse("Invalid OSV batch response"))
    Error(_) -> Error(InvalidJson("Invalid JSON in OSV batch response"))
    Ok(results) -> zip_batch(purls, results)
  }
}

fn zip_batch(
  purls: List(String),
  results: List(BatchResult),
) -> Result(List(BatchPageEntry), Error) {
  use <- bool.guard(
    when: list.length(purls) != list.length(results),
    return: Error(InvalidResponse(
      "OSV batch response length ("
      <> int.to_string(list.length(results))
      <> ") does not match input purls ("
      <> int.to_string(list.length(purls))
      <> ")",
    )),
  )
  Ok(
    list.map2(purls, results, fn(purl, result) {
      BatchPageEntry(
        purl: purl,
        vuln_ids: result.vuln_ids,
        next_page_token: result.next_page_token,
      )
    }),
  )
}

type BatchResult {
  BatchResult(vuln_ids: List(String), next_page_token: Option(String))
}

fn batch_results_decoder() -> decode.Decoder(List(BatchResult)) {
  use results <- decode.optional_field(
    "results",
    [],
    decode.list(of: batch_entry_decoder()),
  )
  decode.success(results)
}

fn batch_entry_decoder() -> decode.Decoder(BatchResult) {
  use vulns <- decode.optional_field(
    "vulns",
    [],
    decode.list(of: vuln_id_decoder()),
  )
  use next_page_token <- decode.optional_field(
    "next_page_token",
    None,
    decode.map(decode.string, Some),
  )
  decode.success(BatchResult(vuln_ids: vulns, next_page_token:))
}

fn vuln_id_decoder() -> decode.Decoder(String) {
  use id <- decode.field("id", decode.string)
  decode.success(id)
}

fn initial_page_tokens(purls: List(String)) -> List(Option(String)) {
  list.map(purls, fn(_) { None })
}

fn follow_paginated_entries(
  entries: List(BatchPageEntry),
  client: fn(Request(String)) -> Result(Response(String), Error),
) -> Result(List(BatchEntry), Error) {
  case entries {
    [] -> Ok([])
    [entry, ..rest] ->
      case follow_entry_pages(entry, client) {
        Error(error) -> Error(error)
        Ok(resolved) ->
          case follow_paginated_entries(rest, client) {
            Error(error) -> Error(error)
            Ok(resolved_rest) -> Ok([resolved, ..resolved_rest])
          }
      }
  }
}

fn follow_entry_pages(
  entry: BatchPageEntry,
  client: fn(Request(String)) -> Result(Response(String), Error),
) -> Result(BatchEntry, Error) {
  follow_entry_pages_loop(
    entry.purl,
    entry.vuln_ids,
    entry.next_page_token,
    client,
    pages_seen: 1,
  )
}

fn follow_entry_pages_loop(
  purl: String,
  vuln_ids: List(String),
  next_page_token: Option(String),
  client: fn(Request(String)) -> Result(Response(String), Error),
  pages_seen pages_seen: Int,
) -> Result(BatchEntry, Error) {
  case next_page_token {
    None -> Ok(BatchEntry(purl: purl, vuln_ids: vuln_ids))
    Some(token) -> {
      use <- bool.guard(
        when: pages_seen >= max_batch_pages,
        return: Error(InvalidResponse(
          "OSV paginated response exceeded "
          <> int.to_string(max_batch_pages)
          <> " pages",
        )),
      )
      case fetch_batch_page([purl], [Some(token)], client) {
        Error(error) -> Error(error)
        Ok([page]) ->
          follow_entry_pages_loop(
            purl,
            list.append(vuln_ids, page.vuln_ids),
            page.next_page_token,
            client,
            pages_seen: pages_seen + 1,
          )
        Ok(_) ->
          Error(InvalidResponse(
            "OSV paginated response did not contain exactly one result",
          ))
      }
    }
  }
}

fn decode_vuln_response(
  response: Response(String),
  id: String,
) -> Result(Vulnerability, Error) {
  case response.status {
    404 -> Error(NotFound)
    429 -> Error(RateLimited)
    status if status >= 200 && status < 300 ->
      decode_vuln_body(response.body, id)
    status -> Error(UnexpectedResponse(status: status))
  }
}

pub fn decode_vuln_body(
  body: String,
  fallback_id: String,
) -> Result(Vulnerability, Error) {
  case json.parse(body, using: vulnerability_decoder(fallback_id)) {
    Error(json.UnableToDecode(_)) ->
      Error(InvalidResponse("Invalid OSV vulnerability response"))
    Error(_) -> Error(InvalidJson("Invalid JSON in OSV vulnerability response"))
    Ok(vuln) -> Ok(vuln)
  }
}

fn vulnerability_decoder(fallback_id: String) -> decode.Decoder(Vulnerability) {
  use id <- decode.optional_field("id", fallback_id, decode.string)
  use summary <- decode.optional_field("summary", "", decode.string)
  use details <- decode.optional_field("details", "", decode.string)
  use database_severity <- decode.optional_field(
    "database_specific",
    UnknownSeverity,
    database_specific_severity_decoder(),
  )
  use scores <- decode.optional_field(
    "severity",
    [],
    decode.list(of: score_decoder()),
  )

  let resolved_summary = case summary {
    "" -> details
    other -> other
  }

  let severity = case database_severity {
    UnknownSeverity ->
      highest_severity_from_vectors(list.map(scores, severity_from_score))
    known -> known
  }

  decode.success(Vulnerability(
    id: id,
    summary: resolved_summary,
    severity: severity,
    scores: scores,
  ))
}

fn database_specific_severity_decoder() -> decode.Decoder(Severity) {
  use raw <- decode.optional_field("severity", "", decode.string)
  decode.success(parse_severity_label(raw))
}

fn score_decoder() -> decode.Decoder(Score) {
  use kind <- decode.optional_field("type", "", decode.string)
  use vector <- decode.optional_field("score", "", decode.string)
  decode.success(Score(kind:, vector:))
}

fn severity_from_score(score: Score) -> Severity {
  case severity_from_cvss_vector(score.vector) {
    UnknownSeverity -> severity_from_cvss_kind(score.kind, score.vector)
    severity -> severity
  }
}

fn severity_from_cvss_kind(kind: String, vector: String) -> Severity {
  let upper_kind = string.uppercase(kind)
  let upper_vector = string.uppercase(vector)
  case upper_kind {
    "CVSS_V4" -> bucket_from_cvss4(upper_vector)
    "CVSS_V3" -> bucket_from_cvss3(upper_vector)
    "CVSS_V2" -> Medium
    _ -> UnknownSeverity
  }
}

fn highest_severity_from_vectors(severities: List(Severity)) -> Severity {
  list.fold(severities, UnknownSeverity, fn(acc, current) {
    case compare_severity(current, acc) {
      Greater -> current
      _ -> acc
    }
  })
}

type SeverityOrder {
  Less
  Equal
  Greater
}

fn compare_severity(a: Severity, b: Severity) -> SeverityOrder {
  let rank_a = severity_rank(a)
  let rank_b = severity_rank(b)
  case rank_a, rank_b {
    x, y if x == y -> Equal
    x, y if x > y -> Greater
    _, _ -> Less
  }
}

fn severity_rank(severity: Severity) -> Int {
  case severity {
    UnknownSeverity -> 0
    Low -> 1
    Medium -> 2
    High -> 3
    Critical -> 4
  }
}

/// Parse a textual severity label (e.g. "LOW", "moderate", "HIGH").
/// Treats "moderate" as `Medium` to match GHSA terminology.
pub fn parse_severity_label(raw: String) -> Severity {
  case string.lowercase(string.trim(raw)) {
    "low" -> Low
    "medium" -> Medium
    "moderate" -> Medium
    "high" -> High
    "critical" -> Critical
    _ -> UnknownSeverity
  }
}

/// Best-effort derivation of a severity bucket from a CVSS vector string.
/// We look at the `/A:` impact suffix as a coarse heuristic; the goal is a
/// reasonable bucket, not a precise CVSS score.
pub fn severity_from_cvss_vector(vector: String) -> Severity {
  let upper = string.uppercase(vector)
  case
    string.contains(upper, "CVSS:4.0"),
    string.contains(upper, "CVSS:3"),
    string.contains(upper, "CVSS:2")
  {
    True, _, _ -> bucket_from_cvss4(upper)
    _, True, _ -> bucket_from_cvss3(upper)
    _, _, True -> Medium
    _, _, _ -> UnknownSeverity
  }
}

fn bucket_from_cvss4(vector: String) -> Severity {
  case
    string.contains(vector, "/VC:H")
    || string.contains(vector, "/VI:H")
    || string.contains(vector, "/VA:H")
    || string.contains(vector, "/SC:H")
    || string.contains(vector, "/SI:H")
    || string.contains(vector, "/SA:H"),
    string.contains(vector, "/VC:L")
    || string.contains(vector, "/VI:L")
    || string.contains(vector, "/VA:L")
    || string.contains(vector, "/SC:L")
    || string.contains(vector, "/SI:L")
    || string.contains(vector, "/SA:L")
  {
    True, _ -> High
    _, True -> Medium
    _, _ -> Low
  }
}

fn bucket_from_cvss3(vector: String) -> Severity {
  // Crude: look for the impact metric letters. A more accurate parser would
  // compute the base score; OSV usually also populates `database_specific`
  // so this is just a fallback.
  case
    string.contains(vector, "/I:H") || string.contains(vector, "/C:H"),
    string.contains(vector, "/I:L") || string.contains(vector, "/C:L")
  {
    True, _ -> High
    _, True -> Medium
    _, _ -> Low
  }
}

pub fn severity_to_string(severity: Severity) -> String {
  case severity {
    Low -> "low"
    Medium -> "medium"
    High -> "high"
    Critical -> "critical"
    UnknownSeverity -> "unknown"
  }
}
