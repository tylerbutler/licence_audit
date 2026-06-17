import gleam/bit_array
import gleam/int
import gleam/string

import licence_audit/env

/// Generate a CycloneDX-compatible `urn:uuid:<v4>` serial number.
pub fn serial_number() -> String {
  uuid_urn_from_bytes(random_bytes(16), version_bits: 0x40)
}

/// Derive a deterministic `urn:uuid` serial number from arbitrary BOM content.
///
/// The content is hashed with SHA-256 and the first 16 bytes are formatted as
/// an RFC 9562 version-8 (custom) UUID. Identical content always yields the
/// same serial number, so two SBOMs generated from the same dependency set
/// compare equal — while a change anywhere in the content changes the serial.
pub fn serial_number_from_content(content: String) -> String {
  uuid_urn_from_bytes(
    sha256(bit_array.from_string(content)),
    version_bits: 0x80,
  )
}

fn uuid_urn_from_bytes(
  bytes: BitArray,
  version_bits version_bits: Int,
) -> String {
  let assert <<
    b0,
    b1,
    b2,
    b3,
    b4,
    b5,
    b6,
    b7,
    b8,
    b9,
    b10,
    b11,
    b12,
    b13,
    b14,
    b15,
    _:bits,
  >> = bytes
  let v6 = int.bitwise_or(int.bitwise_and(b6, 0x0f), version_bits)
  let v8 = int.bitwise_or(int.bitwise_and(b8, 0x3f), 0x80)
  let hex =
    <<b0, b1, b2, b3, b4, b5, v6, b7, v8, b9, b10, b11, b12, b13, b14, b15>>
    |> bit_array.base16_encode
    |> string.lowercase
  "urn:uuid:"
  <> string.slice(hex, 0, 8)
  <> "-"
  <> string.slice(hex, 8, 4)
  <> "-"
  <> string.slice(hex, 12, 4)
  <> "-"
  <> string.slice(hex, 16, 4)
  <> "-"
  <> string.slice(hex, 20, 12)
}

/// Resolve the reproducible-build timestamp (seconds since the Unix epoch) from
/// a `SOURCE_DATE_EPOCH` value. Follows the reproducible-builds convention: a
/// missing, non-numeric, or negative value falls back to epoch 0.
pub fn resolve_source_date_epoch(raw: Result(String, Nil)) -> Int {
  case raw {
    Ok(value) ->
      case int.parse(string.trim(value)) {
        Ok(seconds) if seconds >= 0 -> seconds
        _ -> 0
      }
    Error(Nil) -> 0
  }
}

/// The reproducible timestamp string: `SOURCE_DATE_EPOCH` formatted as a UTC
/// RFC 3339 instant, falling back to `1970-01-01T00:00:00Z` when unset.
pub fn reproducible_timestamp() -> String {
  env.get("SOURCE_DATE_EPOCH")
  |> resolve_source_date_epoch
  |> timestamp_of_epoch
}

/// Current UTC time as an RFC 3339 string with a trailing `Z` (seconds
/// precision), e.g. `2026-05-24T22:51:00Z`.
@external(erlang, "sbom_uuid_ffi", "timestamp_now_utc")
pub fn timestamp_now() -> String

/// Format the given number of seconds since the Unix epoch as a UTC RFC 3339
/// instant (e.g. `0` -> `1970-01-01T00:00:00Z`).
@external(erlang, "sbom_uuid_ffi", "timestamp_of_epoch_utc")
pub fn timestamp_of_epoch(seconds: Int) -> String

@external(erlang, "sbom_uuid_ffi", "sha256")
fn sha256(data: BitArray) -> BitArray

@external(erlang, "sbom_uuid_ffi", "random_bytes")
fn random_bytes(size: Int) -> BitArray
