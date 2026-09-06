import gleam/list
import gleam/option.{None, Some}
import gleam/string
import gleam/time/timestamp
import gleeunit/should
import licence_audit/config
import licence_audit/exception
import licence_audit/osv
import licence_audit/policy

fn entry(finding: exception.Finding) -> exception.Exception {
  exception.Exception(
    number: 1,
    purl: "pkg:hex/example@1.2.3",
    finding: finding,
    reason: "Reviewed for this release",
    expires: Some("2026-12-31"),
  )
}

fn parse(fields: String) -> Result(config.Policy, config.Error) {
  config.parse(
    "[tools.licence_audit]\nallow = [\"MIT\"]\n"
    <> "[[tools.licence_audit.exceptions]]\n"
    <> fields,
  )
}

const base = "purl = \"pkg:hex/example@1.2.3\"\nfinding = \"advisory\"\nadvisory = \"CVE-2026-12345\"\nreason = \"Reviewed\"\n"

pub fn parse_array_of_tables_and_optional_expiry_test() {
  let assert Ok(parsed) = parse(base <> "expires = \"2026-12-31\"\n")
  let assert [exception] = parsed.exceptions
  should.equal(exception.number, 1)
  should.equal(exception.expires, Some("2026-12-31"))
  let assert Ok(parsed) = parse(base)
  let assert [exception] = parsed.exceptions
  should.equal(exception.expires, None)
}

pub fn exceptions_can_be_the_only_policy_setting_test() {
  let assert Ok(parsed) =
    config.parse("[[tools.licence_audit.exceptions]]\n" <> base)
  should.equal(list.length(parsed.exceptions), 1)
}

pub fn inline_exception_tables_use_the_same_validation_test() {
  let assert Ok(parsed) =
    config.parse(
      "[tools.licence_audit]\nexceptions = [{ purl = \"pkg:hex/example@1.2.3\", finding = \"no-licences-declared\", reason = \"Reviewed\" }]\n",
    )
  should.equal(list.length(parsed.exceptions), 1)
  let assert Error(config.InvalidException(_)) =
    config.parse("[tools.licence_audit]\nexceptions = [42]\n")
}

pub fn invalid_exception_fields_fail_test() {
  [
    "",
    string.replace(base, "reason = \"Reviewed\"", "reason = \"  \""),
    string.replace(base, "advisory =", "advisory_typo ="),
    base <> "licence = \"MIT\"\n",
    base <> "temporary = true\n",
    base <> "expires = 2026-12-31\n",
    base <> "expires = \"2026-02-30\"\n",
    base <> "expires = \"2026-2-01\"\n",
    base <> "expires = \"2026-12-31T00:00:00Z\"\n",
    string.replace(base, "finding = \"advisory\"", "finding = \"ignore-all\""),
    string.replace(base, "advisory = \"CVE-2026-12345\"", "advisory = 7"),
  ]
  |> list.each(fn(fields) {
    let assert Error(config.InvalidException(message)) = parse(fields)
    assert string.contains(message, "exceptions[1]")
  })
  let assert Error(config.InvalidException(_)) =
    config.parse("[tools.licence_audit]\nexceptions = \"ignore\"\n")
  let assert Error(config.InvalidException(message)) =
    parse(base <> "[tools.licence_audit.exceptions.extra]\nfield = true\n")
  assert string.contains(message, "exceptions.extra.field")
}

pub fn exact_purl_validation_test() {
  [
    "pkg:hex/example",
    "pkg:hex/example@*",
    "pkg:hex/example@>=1.0.0",
    "pkg:hex/example@1.2.x",
    "pkg:hex/example@01.2.3",
    "pkg:hex/example@1.2.3?other=value",
    "pkg:hex/example@1.2.3#path",
    "pkg:hex/Example@1.2.3",
    "pkg:github/owner/repo@main",
    "pkg:github/owner/repo@abc1234",
    "pkg:generic/example@1.2.3",
  ]
  |> list.each(fn(purl) {
    let assert Error(config.InvalidException(_)) =
      parse(string.replace(base, "pkg:hex/example@1.2.3", purl))
  })
  [
    "pkg:hex/example@1.2.3-rc.1+build.4",
    "pkg:github/owner/repo@" <> string.repeat("a", 40),
    "pkg:github/owner/repo@" <> string.repeat("b", 64),
  ]
  |> list.each(fn(purl) {
    let assert Ok(_) =
      parse(string.replace(base, "pkg:hex/example@1.2.3", purl))
  })
}

pub fn selectors_require_only_their_own_fields_test() {
  let licence =
    "purl = \"pkg:hex/example@1.2.3\"\nfinding = \"denied-licence\"\nlicence = \"GPL-3.0-only\"\nreason = \"Reviewed\"\n"
  let assert Ok(_) = parse(licence)
  let assert Ok(_) =
    parse(string.replace(licence, "denied-licence", "unallowed-licence"))
  let missing =
    "purl = \"pkg:hex/example@1.2.3\"\nfinding = \"no-licences-declared\"\nreason = \"Reviewed\"\n"
  let assert Ok(_) = parse(missing)
  let assert Error(config.InvalidException(_)) =
    parse(missing <> "licence = \"MIT\"\n")
  let assert Error(config.InvalidException(_)) =
    parse(string.replace(
      licence,
      "pkg:hex/example@1.2.3",
      "pkg:github/owner/repo@" <> string.repeat("a", 40),
    ))
}

pub fn duplicates_and_alias_overlaps_fail_test() {
  let assert Error(config.InvalidException(message)) =
    parse(base <> "[[tools.licence_audit.exceptions]]\n" <> base)
  assert string.contains(message, "exceptions[1] and exceptions[2]")
  let first = entry(exception.Advisory("CVE-2026-12345"))
  let second =
    exception.Exception(
      ..first,
      number: 2,
      finding: exception.Advisory("GHSA-example"),
    )
  let assert Error(message) =
    exception.decide(
      [first, second],
      first.purl,
      second.finding,
      ["CVE-2026-12345"],
      "2026-12-01",
    )
  assert string.contains(message, "exceptions[1] and exceptions[2]")
  let assert Error(_) =
    exception.validate_identities([first], [first.purl, first.purl])
}

pub fn exact_scope_and_finding_match_test() {
  let waiver = entry(exception.DeniedLicence("GPL-3.0-only"))
  let assert Ok(exception.Excepted(_)) =
    exception.decide([waiver], waiver.purl, waiver.finding, [], "2026-12-31")
  [
    #("pkg:hex/example@1.2.4", waiver.finding),
    #("pkg:hex/other@1.2.3", waiver.finding),
    #(waiver.purl, exception.UnallowedLicence("GPL-3.0-only")),
    #(waiver.purl, exception.DeniedLicence("MIT")),
    #(waiver.purl, exception.Advisory("GPL-3.0-only")),
  ]
  |> list.each(fn(pair) {
    should.equal(
      exception.decide([waiver], pair.0, pair.1, [], "2026-12-01"),
      Ok(exception.Unaccepted),
    )
  })
}

pub fn advisory_matching_uses_only_direct_aliases_test() {
  let waiver = entry(exception.Advisory("CVE-2026-12345"))
  let assert Ok(exception.Excepted(_)) =
    exception.decide(
      [waiver],
      waiver.purl,
      exception.Advisory("GHSA-example"),
      ["CVE-2026-12345"],
      "2026-12-01",
    )
  should.equal(
    exception.decide(
      [waiver],
      waiver.purl,
      exception.Advisory("GHSA-other"),
      [],
      "2026-12-01",
    ),
    Ok(exception.Unaccepted),
  )
  should.equal(
    exception.decide(
      [waiver],
      waiver.purl,
      exception.Advisory("cve-2026-12345"),
      [],
      "2026-12-01",
    ),
    Ok(exception.Unaccepted),
  )
}

pub fn utc_expiry_boundaries_and_dates_test() {
  let waiver = entry(exception.NoLicencesDeclared)
  [
    #("2026-12-30T23:59:59Z", False),
    #("2026-12-31T23:59:59.999999999Z", False),
    #("2027-01-01T00:00:00Z", True),
    #("2027-01-01T01:00:00+01:00", True),
  ]
  |> list.each(fn(pair) {
    let assert Ok(now) = timestamp.parse_rfc3339(pair.0)
    should.equal(exception.is_expired(waiver, exception.utc_date(now)), pair.1)
  })
  should.equal(exception.validate_date("2024-02-29"), Ok(Nil))
  let assert Error(_) = exception.validate_date("2025-02-29")
  let assert Error(_) = exception.validate_date("2026-04-31")
  should.equal(
    exception.is_expired(
      exception.Exception(..waiver, expires: None),
      "9999-12-31",
    ),
    False,
  )
}

pub fn complete_licence_findings_preserve_deny_precedence_test() {
  let assert Ok(rules) =
    policy.new(allow: ["MIT"], deny: ["MIT", "GPL-3.0-only"], check_mode: True)
  should.equal(
    policy.findings(rules, ["Apache-2.0", "MIT", "GPL-3.0-only", "MIT"]),
    [
      exception.DeniedLicence("MIT"),
      exception.DeniedLicence("GPL-3.0-only"),
      exception.UnallowedLicence("Apache-2.0"),
    ],
  )
  should.equal(policy.findings(rules, []), [exception.NoLicencesDeclared])
}

pub fn summary_distinguishes_unused_disabled_and_expired_test() {
  let waiver = entry(exception.Advisory("CVE-2026-12345"))
  let summary =
    exception.summary(
      [waiver],
      "2027-01-01",
      exception.NotEvaluated("licence scan disabled"),
      exception.Evaluated([], []),
    )
  assert string.contains(summary, "expired; unused")
  let summary =
    exception.summary(
      [waiver],
      "2026-12-31",
      exception.Evaluated([], []),
      exception.NotEvaluated("vulnerability scan disabled"),
    )
  assert string.contains(summary, "not evaluated: vulnerability scan disabled")
  let summary =
    exception.summary(
      [waiver],
      "2026-12-31",
      exception.Evaluated([], []),
      exception.Evaluated([], [#(waiver.purl, "OSV request failed")]),
    )
  assert string.contains(summary, "not evaluated: OSV request failed")
  assert !string.contains(summary, "unused")
}

pub fn osv_aliases_decode_without_inferred_related_ids_test() {
  let assert Ok(vuln) =
    osv.decode_vuln_body(
      "{\"id\":\"GHSA-example\",\"aliases\":[\"CVE-2026-12345\"],\"related\":[\"CVE-2026-99999\"]}",
      "OSV-requested",
    )
  should.equal(vuln.id, "GHSA-example")
  should.equal(vuln.aliases, ["CVE-2026-12345"])
  let assert Ok(vuln) = osv.decode_vuln_body("{}", "OSV-requested")
  should.equal(vuln.aliases, [])
  let assert Error(_) =
    osv.decode_vuln_body("{\"aliases\":\"CVE-2026-12345\"}", "OSV-requested")
}
