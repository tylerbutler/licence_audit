import gleeunit/should
import licence_audit/sbom_json

pub fn pretty_print_rejects_trailing_content_test() {
  let assert Error(error) = sbom_json.pretty_print("{\"ok\":true} []")

  should.equal(error, sbom_json.InvalidJson)
}

pub fn pretty_print_rejects_invalid_json_test() {
  let assert Error(error) = sbom_json.pretty_print("{")

  should.equal(error, sbom_json.InvalidJson)
}

pub fn pretty_print_formats_json_test() {
  let assert Ok(formatted) = sbom_json.pretty_print("{\"ok\":true}")

  should.equal(formatted, "{ \"ok\": true }")
}

pub fn describe_error_maps_invalid_json_test() {
  should.equal(sbom_json.describe_error(sbom_json.InvalidJson), "invalid JSON")
}
