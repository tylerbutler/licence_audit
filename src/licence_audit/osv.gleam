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
import gleam/httpc
import gleam/int
import gleam/json
import gleam/list
import gleam/option.{None}
import gleam/string

pub type Severity {
  Low
  Medium
  High
  Critical
  UnknownSeverity
}

pub type Vulnerability {
  Vulnerability(id: String, summary: String, severity: Severity)
}

/// A single per-purl result from `/v1/querybatch`.
pub type BatchEntry {
  BatchEntry(purl: String, vuln_ids: List(String))
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
    _ -> {
      let body = encode_batch_body(purls)
      let req = batch_request(body)
      case client(req) {
        Error(error) -> Error(error)
        Ok(response) -> decode_batch_response(response, purls)
      }
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
  case
    httpc.configure()
    |> httpc.timeout(osv_timeout_ms)
    |> httpc.dispatch(req)
  {
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
  let queries =
    list.map(purls, fn(purl) {
      json.object([
        #("package", json.object([#("purl", json.string(purl))])),
      ])
    })

  json.object([#("queries", json.preprocessed_array(queries))])
  |> json.to_string
}

// --- Response decoding ---------------------------------------------------

fn decode_batch_response(
  response: Response(String),
  purls: List(String),
) -> Result(List(BatchEntry), Error) {
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
) -> Result(List(BatchEntry), Error) {
  case json.parse(body, using: batch_results_decoder()) {
    Error(json.UnableToDecode(_)) ->
      Error(InvalidResponse("Invalid OSV batch response"))
    Error(_) -> Error(InvalidJson("Invalid JSON in OSV batch response"))
    Ok(results) -> zip_batch(purls, results)
  }
}

fn zip_batch(
  purls: List(String),
  results: List(List(String)),
) -> Result(List(BatchEntry), Error) {
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
    list.map2(purls, results, fn(purl, ids) {
      BatchEntry(purl: purl, vuln_ids: ids)
    }),
  )
}

fn batch_results_decoder() -> decode.Decoder(List(List(String))) {
  use results <- decode.optional_field(
    "results",
    [],
    decode.list(of: batch_entry_decoder()),
  )
  decode.success(results)
}

fn batch_entry_decoder() -> decode.Decoder(List(String)) {
  use vulns <- decode.optional_field(
    "vulns",
    [],
    decode.list(of: vuln_id_decoder()),
  )
  decode.success(vulns)
}

fn vuln_id_decoder() -> decode.Decoder(String) {
  use id <- decode.field("id", decode.string)
  decode.success(id)
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
  use severity_vectors <- decode.optional_field(
    "severity",
    [],
    decode.list(of: severity_score_decoder()),
  )

  let resolved_summary = case summary {
    "" -> details
    other -> other
  }

  let severity = case database_severity {
    UnknownSeverity -> highest_severity_from_vectors(severity_vectors)
    known -> known
  }

  decode.success(Vulnerability(
    id: id,
    summary: resolved_summary,
    severity: severity,
  ))
}

fn database_specific_severity_decoder() -> decode.Decoder(Severity) {
  use raw <- decode.optional_field("severity", "", decode.string)
  decode.success(parse_severity_label(raw))
}

fn severity_score_decoder() -> decode.Decoder(Severity) {
  use score <- decode.optional_field("score", "", decode.string)
  decode.success(severity_from_cvss_vector(score))
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
  case string.contains(upper, "CVSS:3"), string.contains(upper, "CVSS:2") {
    True, _ -> bucket_from_cvss3(upper)
    _, True -> Medium
    _, _ -> UnknownSeverity
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
