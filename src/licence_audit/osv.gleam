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
import gleam/order
import gleam/result
import gleam/string
import gleam/uri
import licence_audit/cvss
import licence_audit/httpc_adaptive
import licence_audit/semver

pub type Severity {
  NoSeverity
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
    aliases: List(String),
    summary: String,
    severity: Severity,
    scores: List(Score),
    affected: List(AffectedPackage),
  )
}

pub opaque type AffectedPackage {
  AffectedPackage(
    purl: String,
    ecosystem: String,
    name: String,
    versions: List(String),
    ranges: List(AffectedRange),
    scores: List(Score),
  )
}

type AffectedRange {
  AffectedRange(kind: String, events: List(RangeEvent))
}

type RangeEvent {
  Introduced(String)
  Fixed(String)
  LastAffected(String)
  Limit(String)
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
  NetworkFailure(reason: String)
}

const osv_host = "api.osv.dev"

const osv_timeout_ms = 8000

const max_batch_pages = 32

// --- High-level injectable API -------------------------------------------

/// Query OSV for vulnerabilities affecting each of `purls`. Returns one
/// `BatchEntry` per input purl, preserving input order. Empty `vuln_ids`
/// means OSV reports no known vulnerabilities for that purl.
/// GitHub purls use commit queries; Hex purls use package queries.
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
    Error(error) -> Error(from_http_error(req, error))
  }
}

pub fn from_http_error(
  req: Request(String),
  error: httpc_adaptive.Error,
) -> Error {
  NetworkFailure(
    http.method_to_string(req.method)
    <> " "
    <> uri.to_string(request.to_uri(req))
    <> ": "
    <> httpc_adaptive.describe_error(error, osv_timeout_ms),
  )
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
      let fields = case string.split(purl, "@") {
        ["pkg:github/" <> _, revision] -> {
          let commit =
            string.split_once(revision, "#")
            |> result.map(fn(parts) { parts.0 })
            |> result.unwrap(revision)
          [#("commit", json.string(commit))]
        }
        _ -> [#("package", json.object([#("purl", json.string(purl))]))]
      }
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
  list.try_map(entries, follow_entry_pages(_, client))
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
  use aliases <- decode.optional_field(
    "aliases",
    [],
    decode.list(decode.string),
  )
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
  use affected <- decode.optional_field(
    "affected",
    [],
    decode.list(affected_package_decoder()),
  )

  let resolved_summary = case summary {
    "" -> details
    other -> other
  }

  let severity = case database_severity {
    UnknownSeverity ->
      highest_severity_from_vectors(list.map(scores, severity_from_score))
    NoSeverity | Low | Medium | High | Critical -> database_severity
  }

  decode.success(Vulnerability(
    id: id,
    aliases: aliases,
    summary: resolved_summary,
    severity: severity,
    scores: scores,
    affected: affected,
  ))
}

fn affected_package_decoder() -> decode.Decoder(AffectedPackage) {
  use package <- decode.optional_field("package", #("", "", ""), {
    use purl <- decode.optional_field("purl", "", decode.string)
    use ecosystem <- decode.optional_field("ecosystem", "", decode.string)
    use name <- decode.optional_field("name", "", decode.string)
    decode.success(#(purl, ecosystem, name))
  })
  use versions <- decode.optional_field(
    "versions",
    [],
    decode.list(decode.string),
  )
  use ranges <- decode.optional_field(
    "ranges",
    [],
    decode.list({
      use kind <- decode.field("type", decode.string)
      use events <- decode.field("events", decode.list(range_event_decoder()))
      decode.success(AffectedRange(kind:, events:))
    }),
  )
  use scores <- decode.optional_field(
    "severity",
    [],
    decode.list(score_decoder()),
  )
  decode.success(AffectedPackage(
    purl: package.0,
    ecosystem: package.1,
    name: package.2,
    versions:,
    ranges:,
    scores:,
  ))
}

fn range_event_decoder() -> decode.Decoder(RangeEvent) {
  decode.one_of(
    decode.field("introduced", decode.string, fn(value) {
      decode.success(Introduced(value))
    }),
    [
      decode.field("fixed", decode.string, fn(value) {
        decode.success(Fixed(value))
      }),
      decode.field("last_affected", decode.string, fn(value) {
        decode.success(LastAffected(value))
      }),
      decode.field("limit", decode.string, fn(value) {
        decode.success(Limit(value))
      }),
    ],
  )
}

/// Batch results establish advisory membership. Scope only the scores here;
/// never transfer scores from another affected package or version.
pub fn for_package(vuln: Vulnerability, purl: String) -> Vulnerability {
  let #(identity, version) = purl_identity(purl)
  let scores =
    vuln.affected
    |> list.filter(fn(affected) {
      let matches = case affected.purl {
        "" ->
          affected.ecosystem == "Hex"
          && {
            identity == "pkg:hex/" <> affected.name
            || affected.name == "*"
            && string.starts_with(identity, "pkg:hex/")
          }
        other -> other == identity
      }
      matches && affected_version(affected, version)
    })
    |> list.flat_map(fn(affected) { affected.scores })
    |> list.unique
  case scores {
    [] -> vuln
    _ ->
      Vulnerability(
        ..vuln,
        severity: highest_severity_from_vectors(list.map(
          scores,
          severity_from_score,
        )),
        scores:,
      )
  }
}

fn purl_identity(purl: String) -> #(String, String) {
  let #(package, subpath) =
    string.split_once(purl, "#")
    |> result.unwrap(#(purl, ""))
  let #(identity, version) =
    string.split_once(package, "@")
    |> result.unwrap(#(package, ""))
  #(
    identity
      <> case subpath {
      "" -> ""
      other -> "#" <> other
    },
    version,
  )
}

fn affected_version(affected: AffectedPackage, version: String) -> Bool {
  case affected.versions, affected.ranges {
    [], [] -> True
    versions, ranges ->
      list.contains(versions, version)
      || list.any(ranges, fn(range) { range_contains(range, version) })
  }
}

fn range_contains(range: AffectedRange, version: String) -> Bool {
  // Git ancestry cannot be inferred by ordering hashes; use OSV's versions list.
  use <- bool.guard(
    when: range.kind != "SEMVER" || !semver.is_valid(version),
    return: False,
  )
  let evaluated = {
    let limits =
      list.filter_map(range.events, fn(event) {
        case event {
          Limit(bound) -> Ok(bound)
          Introduced(_) | Fixed(_) | LastAffected(_) -> Error(Nil)
        }
      })
    use before_limits <- result.try(
      list.try_map(limits, fn(bound) {
        case string.contains(bound, "*") {
          True -> Ok(True)
          False ->
            semver.compare(version, bound)
            |> result.map(fn(comparison) { comparison == order.Lt })
        }
      }),
    )
    use <- bool.guard(
      when: limits != [] && !list.contains(before_limits, True),
      return: Ok(False),
    )
    // Choose the latest applicable event; OSV does not require sorted events.
    use latest <- result.try(
      list.try_fold(range.events, None, fn(latest, event) {
        case event {
          Limit(_) -> Ok(latest)
          Introduced("0") -> Ok(option.or(latest, Some(#("0", True))))
          Introduced(bound) | Fixed(bound) | LastAffected(bound) -> {
            use comparison <- result.try(semver.compare(version, bound))
            let applies = case event {
              LastAffected(_) -> comparison == order.Gt
              Introduced(_) | Fixed(_) -> comparison != order.Lt
              Limit(_) -> False
            }
            use <- bool.guard(when: !applies, return: Ok(latest))
            let active = case event {
              Introduced(_) -> True
              Fixed(_) | LastAffected(_) | Limit(_) -> False
            }
            use newer <- result.try(case latest {
              None | Some(#("0", _)) -> Ok(True)
              Some(#(previous, _)) ->
                semver.compare(bound, previous)
                |> result.map(fn(comparison) { comparison != order.Lt })
            })
            Ok(case newer {
              True -> Some(#(bound, active))
              False -> latest
            })
          }
        }
      }),
    )
    Ok(case latest {
      Some(#(_, affected)) -> affected
      None -> False
    })
  }
  result.unwrap(evaluated, False)
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
  let severity = severity_from_cvss_vector(score.vector)
  case severity {
    UnknownSeverity -> severity_from_cvss_kind(score.kind, score.vector)
    NoSeverity | Low | Medium | High | Critical -> severity
  }
}

fn severity_from_cvss_kind(kind: String, vector: String) -> Severity {
  let upper_kind = string.uppercase(kind)
  case upper_kind {
    "CVSS_V4" -> severity_from_cvss_vector(vector)
    "CVSS_V3" -> severity_from_cvss_vector(vector)
    "CVSS_V2" -> severity_from_cvss_v2_vector(vector)
    _ -> UnknownSeverity
  }
}

fn highest_severity_from_vectors(severities: List(Severity)) -> Severity {
  list.fold(severities, UnknownSeverity, fn(acc, current) {
    case severity_rank(current) > severity_rank(acc) {
      True -> current
      False -> acc
    }
  })
}

pub fn severity_rank(severity: Severity) -> Int {
  case severity {
    UnknownSeverity -> -1
    NoSeverity -> 0
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
    "none" -> NoSeverity
    "low" -> Low
    "medium" -> Medium
    "moderate" -> Medium
    "high" -> High
    "critical" -> Critical
    _ -> UnknownSeverity
  }
}

/// Calculate a severity bucket from a complete CVSS v2, v3, or v4 vector.
pub fn severity_from_cvss_vector(vector: String) -> Severity {
  let trimmed = string.trim(vector)
  let upper = string.uppercase(trimmed)
  case
    string.starts_with(upper, "CVSS:4.0/")
    || string.starts_with(upper, "CVSS:3.0/")
    || string.starts_with(upper, "CVSS:3.1/")
  {
    True -> severity_from_supported_vector(trimmed)
    False -> severity_from_cvss_v2_vector(trimmed)
  }
}

fn severity_from_cvss_v2_vector(vector: String) -> Severity {
  let trimmed = string.trim(vector)
  let upper = string.uppercase(trimmed)
  let bare = case string.starts_with(upper, "CVSS:2.0/") {
    True -> string.drop_start(trimmed, 9)
    False -> trimmed
  }
  case is_cvss_v2_vector(bare) {
    True -> severity_from_supported_vector(bare)
    False -> UnknownSeverity
  }
}

fn is_cvss_v2_vector(vector: String) -> Bool {
  let metrics = string.split(string.uppercase(vector), on: "/")
  let has_v2_access_vector =
    list.contains(metrics, "AV:N")
    || list.contains(metrics, "AV:A")
    || list.contains(metrics, "AV:L")
  let has_v2_authentication =
    list.contains(metrics, "AU:M")
    || list.contains(metrics, "AU:S")
    || list.contains(metrics, "AU:N")
  has_v2_access_vector && has_v2_authentication
}

fn severity_from_supported_vector(vector: String) -> Severity {
  case cvss.rating(vector) {
    Ok(cvss.None) -> NoSeverity
    Ok(cvss.Low) -> Low
    Ok(cvss.Medium) -> Medium
    Ok(cvss.High) -> High
    Ok(cvss.Critical) -> Critical
    Error(_) -> UnknownSeverity
  }
}

pub fn severity_to_string(severity: Severity) -> String {
  case severity {
    NoSeverity -> "none"
    Low -> "low"
    Medium -> "medium"
    High -> "high"
    Critical -> "critical"
    UnknownSeverity -> "unknown"
  }
}
