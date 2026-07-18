import gleeunit/should
import licence_audit/spdx

pub fn single_identifier_test() {
  should.equal(
    spdx.identifiers_of("Apache-2.0"),
    Ok([
      spdx.LicenseRequirement("Apache-2.0"),
    ]),
  )
}

pub fn trailing_plus_is_stripped_test() {
  should.equal(
    spdx.identifiers_of("GPL-2.0+"),
    Ok([
      spdx.LicenseRequirement("GPL-2.0"),
    ]),
  )
}

pub fn and_includes_all_operands_test() {
  should.equal(
    spdx.identifiers_of("MIT AND Apache-2.0"),
    Ok([
      spdx.LicenseRequirement("MIT"),
      spdx.LicenseRequirement("Apache-2.0"),
    ]),
  )
}

pub fn or_includes_all_alternatives_test() {
  should.equal(
    spdx.identifiers_of("(MIT OR Apache-2.0)"),
    Ok([
      spdx.LicenseRequirement("MIT"),
      spdx.LicenseRequirement("Apache-2.0"),
    ]),
  )
}

pub fn with_exception_is_classified_test() {
  should.equal(
    spdx.identifiers_of("Apache-2.0 WITH LLVM-exception"),
    Ok([
      spdx.LicenseRequirement("Apache-2.0"),
      spdx.ExceptionRequirement("LLVM-exception"),
    ]),
  )
}

pub fn nested_expression_collects_all_ids_test() {
  should.equal(
    spdx.identifiers_of("(MIT OR Apache-2.0) AND BSD-3-Clause"),
    Ok([
      spdx.LicenseRequirement("MIT"),
      spdx.LicenseRequirement("Apache-2.0"),
      spdx.LicenseRequirement("BSD-3-Clause"),
    ]),
  )
}

pub fn license_ref_is_unresolvable_test() {
  should.equal(spdx.identifiers_of("LicenseRef-My-Custom"), Error(Nil))
  should.equal(spdx.identifiers_of("MIT OR LicenseRef-X"), Error(Nil))
}

pub fn required_identifiers_unions_and_dedupes_test() {
  should.equal(
    spdx.required_identifiers(["Apache-2.0", "MIT OR Apache-2.0"]),
    Ok([
      spdx.LicenseRequirement("Apache-2.0"),
      spdx.LicenseRequirement("MIT"),
    ]),
  )
}

pub fn required_identifiers_fails_on_any_ref_test() {
  should.equal(
    spdx.required_identifiers(["MIT", "LicenseRef-Custom"]),
    Error(Nil),
  )
}

pub fn detail_request_is_pinned_to_commit_test() {
  let request = spdx.detail_request(spdx.LicenseRequirement("Apache-2.0"))
  should.equal(request.host, "raw.githubusercontent.com")
  should.equal(
    request.path,
    "/spdx/license-list-data/"
      <> spdx.license_list_commit
      <> "/json/details/Apache-2.0.json",
  )
}

pub fn exception_detail_request_uses_exceptions_path_test() {
  let request = spdx.detail_request(spdx.ExceptionRequirement("LLVM-exception"))
  should.equal(
    request.path,
    "/spdx/license-list-data/"
      <> spdx.license_list_commit
      <> "/json/exceptions/LLVM-exception.json",
  )
}

pub fn index_requests_are_pinned_test() {
  should.equal(
    spdx.index_request(spdx.LicenceIndex).path,
    "/spdx/license-list-data/"
      <> spdx.license_list_commit
      <> "/json/licenses.json",
  )
  should.equal(
    spdx.index_request(spdx.ExceptionIndex).path,
    "/spdx/license-list-data/"
      <> spdx.license_list_commit
      <> "/json/exceptions.json",
  )
}

pub fn indexes_decode_and_canonicalize_ids_test() {
  let body =
    "{\"licenses\":[{\"licenseId\":\"Apache-2.0\"},{\"licenseId\":\"MIT\"}]}"
  let assert Ok(ids) = spdx.decode_index(spdx.LicenceIndex, body)
  should.equal(
    spdx.canonical_requirement(spdx.LicenseRequirement("mit"), ids),
    Ok(spdx.LicenseRequirement("MIT")),
  )
  should.equal(
    spdx.canonical_requirement(spdx.LicenseRequirement("unknown"), ids),
    Error(Nil),
  )
  should.equal(spdx.decode_cached_index(spdx.encode_index(ids)), Ok(ids))
}

pub fn decode_text_reads_license_text_test() {
  let body = "{\"licenseText\":\"Canonical Apache text\"}"
  should.equal(
    spdx.decode_text(spdx.LicenseRequirement("Apache-2.0"), body),
    Ok("Canonical Apache text"),
  )
}

pub fn decode_text_reads_exception_text_test() {
  let body = "{\"licenseExceptionText\":\"Canonical exception text\"}"
  should.equal(
    spdx.decode_text(spdx.ExceptionRequirement("LLVM-exception"), body),
    Ok("Canonical exception text"),
  )
}

pub fn decode_text_missing_field_is_error_test() {
  should.equal(
    spdx.decode_text(spdx.LicenseRequirement("Apache-2.0"), "{\"name\":\"x\"}"),
    Error(Nil),
  )
}

pub fn synthetic_path_labels_origin_test() {
  should.equal(
    spdx.synthetic_path(spdx.LicenseRequirement("Apache-2.0")),
    "SPDX-License-List/Apache-2.0.txt",
  )
  should.equal(
    spdx.synthetic_path(spdx.ExceptionRequirement("LLVM-exception")),
    "SPDX-License-List/exceptions/LLVM-exception.txt",
  )
}
