import gleam/string
import gleeunit/should
import licence_audit/sbom_uuid

pub fn serial_number_from_content_is_deterministic_test() {
  sbom_uuid.serial_number_from_content("hello")
  |> should.equal(sbom_uuid.serial_number_from_content("hello"))
}

pub fn serial_number_from_content_is_content_sensitive_test() {
  let alpha = sbom_uuid.serial_number_from_content("alpha")
  let beta = sbom_uuid.serial_number_from_content("beta")
  { alpha == beta } |> should.equal(False)
}

pub fn serial_number_from_content_is_a_well_formed_urn_uuid_test() {
  let serial = sbom_uuid.serial_number_from_content("hello")
  // urn:uuid:8-4-4-4-12 lowercase hex, 45 characters total.
  string.starts_with(serial, "urn:uuid:") |> should.equal(True)
  string.length(serial) |> should.equal(45)
  // Version nibble (UUIDv8, custom) and RFC 9562 variant are set.
  string.slice(serial, 23, 1) |> should.equal("8")
  let variant = string.slice(serial, 28, 1)
  { variant == "8" || variant == "9" || variant == "a" || variant == "b" }
  |> should.equal(True)
}

pub fn resolve_source_date_epoch_uses_value_when_present_test() {
  sbom_uuid.resolve_source_date_epoch(Ok("1700000000"))
  |> should.equal(1_700_000_000)
}

pub fn resolve_source_date_epoch_trims_whitespace_test() {
  sbom_uuid.resolve_source_date_epoch(Ok("  42\n"))
  |> should.equal(42)
}

pub fn resolve_source_date_epoch_falls_back_to_zero_when_absent_test() {
  sbom_uuid.resolve_source_date_epoch(Error(Nil))
  |> should.equal(0)
}

pub fn resolve_source_date_epoch_falls_back_to_zero_when_unparseable_test() {
  sbom_uuid.resolve_source_date_epoch(Ok("not-a-number"))
  |> should.equal(0)
}

pub fn resolve_source_date_epoch_rejects_negative_test() {
  sbom_uuid.resolve_source_date_epoch(Ok("-5"))
  |> should.equal(0)
}

pub fn timestamp_of_epoch_formats_unix_epoch_as_utc_test() {
  sbom_uuid.timestamp_of_epoch(0)
  |> should.equal("1970-01-01T00:00:00Z")
}
