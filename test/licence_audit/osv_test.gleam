import gleam/http.{Post}
import gleam/http/request
import gleam/http/response.{Response}
import gleam/list
import gleam/string
import gleam/uri
import gleeunit/should
import licence_audit/osv
import simplifile

fn read_fixture(name: String) -> String {
  let assert Ok(contents) = simplifile.read(from: "test/fixtures/" <> name)
  contents
}

pub fn encode_batch_body_emits_querybatch_shape_test() {
  let body = osv.encode_batch_body(["pkg:hex/foo@1.0.0", "pkg:hex/bar@2.0.0"])

  // We don't pin the exact whitespace, just the structural pieces.
  assert string.contains(body, "queries")
  assert string.contains(body, "pkg:hex/foo@1.0.0")
  assert string.contains(body, "pkg:hex/bar@2.0.0")
  assert string.contains(body, "purl")
}

pub fn empty_purls_short_circuits_without_calling_client_test() {
  let client = fn(_req) {
    panic as "client should not be invoked for empty purls"
  }

  let assert Ok(entries) = osv.query_batch([], client)
  should.equal(entries, [])
}

pub fn batch_response_zips_with_input_purls_test() {
  let purls = [
    "pkg:hex/affected@1.0.0",
    "pkg:hex/empty@1.0.0",
    "pkg:hex/explicit_empty@1.0.0",
  ]

  let client = fn(req: request.Request(String)) {
    should.equal(req.method, Post)
    should.equal(
      req |> request.to_uri |> uri.to_string,
      "https://api.osv.dev/v1/querybatch",
    )
    Ok(Response(
      status: 200,
      headers: [],
      body: read_fixture("osv_querybatch.json"),
    ))
  }

  let assert Ok(entries) = osv.query_batch(purls, client)
  should.equal(list.length(entries), 3)

  let assert [first, second, third] = entries
  should.equal(first.purl, "pkg:hex/affected@1.0.0")
  should.equal(first.vuln_ids, ["GHSA-aaaa-bbbb-cccc", "CVE-2024-0001"])
  should.equal(second.vuln_ids, [])
  should.equal(third.vuln_ids, [])
}

pub fn batch_response_length_mismatch_returns_typed_error_test() {
  // Server returns 1 result but we asked about 2 purls — refuse to align.
  let client = fn(_req) {
    Ok(Response(
      status: 200,
      headers: [],
      body: "{\"results\":[{\"vulns\":[]}]}",
    ))
  }

  let assert Error(error) =
    osv.query_batch(["pkg:hex/a@1", "pkg:hex/b@1"], client)
  case error {
    osv.InvalidResponse(_) -> Nil
    _ -> panic as "expected InvalidResponse"
  }
}

pub fn batch_http_429_maps_to_rate_limited_test() {
  let client = fn(_req) { Ok(Response(status: 429, headers: [], body: "")) }
  let assert Error(err) = osv.query_batch(["pkg:hex/a@1"], client)
  should.equal(err, osv.RateLimited)
}

pub fn batch_unexpected_status_preserves_status_test() {
  let client = fn(_req) { Ok(Response(status: 500, headers: [], body: "boom")) }
  let assert Error(err) = osv.query_batch(["pkg:hex/a@1"], client)
  should.equal(err, osv.UnexpectedResponse(status: 500))
}

pub fn decode_vuln_response_extracts_severity_from_database_specific_test() {
  let assert Ok(vuln) =
    osv.decode_vuln_body(
      read_fixture("osv_vuln_high.json"),
      "GHSA-aaaa-bbbb-cccc",
    )
  should.equal(vuln.id, "GHSA-aaaa-bbbb-cccc")
  should.equal(vuln.severity, osv.High)
  assert string.contains(vuln.summary, "Cross-site scripting")
}

pub fn decode_vuln_response_retains_cvss_scores_test() {
  let assert Ok(vuln) =
    osv.decode_vuln_body(
      read_fixture("osv_vuln_high.json"),
      "GHSA-aaaa-bbbb-cccc",
    )
  should.equal(vuln.scores, [
    osv.Score(
      kind: "CVSS_V3",
      vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    ),
  ])
}

pub fn decode_vuln_response_falls_back_to_details_for_summary_test() {
  let assert Ok(vuln) =
    osv.decode_vuln_body(read_fixture("osv_vuln_medium.json"), "CVE-2024-0001")
  should.equal(vuln.id, "CVE-2024-0001")
  // database_specific absent, cvss vector has low confidentiality impact → Medium
  should.equal(vuln.severity, osv.Medium)
  assert string.contains(vuln.summary, "Memory corruption")
}

pub fn parse_severity_label_recognises_common_labels_test() {
  should.equal(osv.parse_severity_label("LOW"), osv.Low)
  should.equal(osv.parse_severity_label("Moderate"), osv.Medium)
  should.equal(osv.parse_severity_label("medium"), osv.Medium)
  should.equal(osv.parse_severity_label("HIGH"), osv.High)
  should.equal(osv.parse_severity_label("Critical"), osv.Critical)
  should.equal(osv.parse_severity_label("unknown"), osv.UnknownSeverity)
  should.equal(osv.parse_severity_label(""), osv.UnknownSeverity)
}

pub fn severity_from_cvss_vector_buckets_test() {
  should.equal(
    osv.severity_from_cvss_vector(
      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    ),
    osv.High,
  )
  should.equal(
    osv.severity_from_cvss_vector(
      "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N",
    ),
    osv.Medium,
  )
  should.equal(osv.severity_from_cvss_vector(""), osv.UnknownSeverity)
}

pub fn severity_to_string_round_trip_test() {
  should.equal(osv.severity_to_string(osv.Critical), "critical")
  should.equal(osv.severity_to_string(osv.High), "high")
  should.equal(osv.severity_to_string(osv.Medium), "medium")
  should.equal(osv.severity_to_string(osv.Low), "low")
  should.equal(osv.severity_to_string(osv.UnknownSeverity), "unknown")
}
