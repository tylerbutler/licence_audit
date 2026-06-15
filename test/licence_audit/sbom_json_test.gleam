import gleeunit/should
import licence_audit/sbom_json

pub fn pretty_print_rejects_trailing_content_test() {
  let assert Error(error) = sbom_json.pretty_print("{\"ok\":true} []")

  should.equal(error, sbom_json.TrailingContent)
}

pub fn pretty_print_rejects_invalid_json_test() {
  let assert Error(error) = sbom_json.pretty_print("{")

  should.equal(error, sbom_json.InvalidJson)
}

pub fn describe_error_maps_trailing_content_test() {
  should.equal(
    sbom_json.describe_error(sbom_json.TrailingContent),
    "unexpected trailing JSON content",
  )
}

pub fn describe_error_maps_invalid_json_test() {
  should.equal(sbom_json.describe_error(sbom_json.InvalidJson), "invalid JSON")
}

pub fn describe_error_maps_encode_failed_test() {
  should.equal(
    sbom_json.describe_error(sbom_json.EncodeFailed),
    "failed to encode JSON",
  )
}
