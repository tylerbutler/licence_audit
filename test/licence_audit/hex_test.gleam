import gleam/http.{Get}
import gleam/http/request
import gleam/http/response.{Response}
import gleam/time/duration
import gleam/time/timestamp
import gleam/uri
import gleeunit/should
import licence_audit/hex
import simplifile

const british_licences_json = "{\"name\":\"example\",\"meta\":{\"licences\":[\"BSD-3-Clause\"]}}"

const missing_licences_json = "{\"name\":\"example\",\"meta\":{\"description\":\"Example package\"}}"

const invalid_metadata_json = "{\"name\":\"example\",\"meta\":{\"licences\":\"MIT\"}}"

fn package_fixture() -> String {
  let assert Ok(contents) =
    simplifile.read(from: "test/fixtures/hex_package.json")
  contents
}

pub fn decode_package_response_with_upstream_licences_test() {
  let assert Ok(metadata) = hex.decode_package(package_fixture())

  should.equal(metadata, hex.PackageMetadata(licences: ["Apache-2.0", "MIT"]))
}

pub fn decode_package_response_with_licences_test() {
  let assert Ok(metadata) = hex.decode_package(british_licences_json)

  should.equal(metadata.licences, ["BSD-3-Clause"])
}

pub fn decode_package_response_missing_licences_as_empty_list_test() {
  let assert Ok(metadata) = hex.decode_package(missing_licences_json)

  should.equal(metadata.licences, [])
}

pub fn decode_package_response_invalid_json_returns_typed_error_test() {
  let assert Error(error) = hex.decode_package("{")

  case error {
    hex.InvalidJson(_) -> Nil
    _ -> panic as "expected InvalidJson"
  }
}

pub fn decode_package_response_invalid_metadata_returns_typed_error_test() {
  let assert Error(error) = hex.decode_package(invalid_metadata_json)

  case error {
    hex.InvalidMetadata(_) -> Nil
    _ -> panic as "expected InvalidMetadata"
  }
}

pub fn injected_http_success_fetches_hex_package_url_and_decodes_metadata_test() {
  let client = fn(req: request.Request(String)) {
    should.equal(req.method, Get)
    should.equal(
      req |> request.to_uri |> uri.to_string,
      "https://hex.pm/api/packages/example",
    )
    Ok(Response(status: 200, headers: [], body: package_fixture()))
  }

  let assert Ok(metadata) = hex.fetch_package_metadata("example", client)

  should.equal(metadata.licences, ["Apache-2.0", "MIT"])
}

pub fn http_404_maps_to_not_found_test() {
  let client = fn(_req) { Ok(Response(status: 404, headers: [], body: "")) }

  let assert Error(error) = hex.fetch_package_metadata("missing", client)

  should.equal(error, hex.NotFound)
}

pub fn http_429_maps_to_rate_limited_test() {
  let client = fn(_req) { Ok(Response(status: 429, headers: [], body: "")) }

  let assert Error(error) = hex.fetch_package_metadata("example", client)

  should.equal(error, hex.RateLimited)
}

pub fn unexpected_http_status_preserves_status_test() {
  let client = fn(_req) { Ok(Response(status: 500, headers: [], body: "oops")) }

  let assert Error(error) = hex.fetch_package_metadata("example", client)

  should.equal(error, hex.UnexpectedResponse(status: 500))
}

pub fn injected_network_failure_maps_to_network_failure_test() {
  let client = fn(_req) { Error(hex.NetworkFailure) }

  let assert Error(error) = hex.fetch_package_metadata("example", client)

  should.equal(error, hex.NetworkFailure)
}

pub fn hex_metadata_fetch_returns_without_ipv6_fallback_delay_test() {
  let started = timestamp.system_time()

  let assert Ok(metadata) = hex.fetch_package_metadata_from_hex("gleam_stdlib")

  assert metadata.licences != []
  assert timestamp.difference(started, timestamp.system_time())
    |> duration.to_milliseconds
    < 5000
}
