import youid/uuid

/// Generate a CycloneDX-compatible `urn:uuid:<v4>` serial number.
///
/// Note: youid's built-in `Urn` format drops the canonical UUID dashes,
/// so we prepend the prefix to the `String` (dashed) form manually.
pub fn serial_number() -> String {
  "urn:uuid:" <> { uuid.v4() |> uuid.format(uuid.String) }
}

/// Current UTC timestamp formatted as RFC 3339 with a trailing `Z`.
@external(erlang, "sbom_uuid_ffi", "timestamp_now_utc")
pub fn timestamp_now() -> String
