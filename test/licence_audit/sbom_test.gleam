import gleam/dynamic/decode
import gleam/json
import gleam/regexp
import gleam/string
import gleeunit/should
import licence_audit/sbom_uuid

pub fn generate_serial_number_returns_urn_v4_test() {
  let serial = sbom_uuid.serial_number()
  let assert Ok(re) =
    regexp.from_string(
      "^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    )
  let assert True = regexp.check(with: re, content: serial)
}

pub fn serial_number_two_calls_differ_test() {
  let first = sbom_uuid.serial_number()
  let second = sbom_uuid.serial_number()
  let assert False = first == second
}

pub fn timestamp_rfc3339_z_suffix_test() {
  let ts = sbom_uuid.timestamp_now()
  let assert True = string.ends_with(ts, "Z")
  should.equal(string.length(ts), 20)
}

import gleam/option.{None, Some}
import licence_audit/error
import licence_audit/hex
import licence_audit/manifest
import licence_audit/osv
import licence_audit/sbom

pub fn purl_for_hex_test() {
  let entry =
    manifest.SbomEntry(
      name: "birch",
      version: "0.2.1",
      kind: manifest.Direct,
      requirements: [],
      provenance: manifest.HexProvenance(
        outer_checksum: "DEADBEEF",
        inner_checksum: None,
      ),
    )
  should.equal(sbom.purl_for(entry), Ok("pkg:hex/birch@0.2.1"))
}

pub fn purl_for_hex_lowercases_name_segment_only_test() {
  let entry =
    manifest.SbomEntry(
      name: "Birch",
      version: "0.2.1",
      kind: manifest.Direct,
      requirements: [],
      provenance: manifest.HexProvenance(
        outer_checksum: "DEADBEEF",
        inner_checksum: None,
      ),
    )
  should.equal(sbom.purl_for(entry), Ok("pkg:hex/birch@0.2.1"))
}

pub fn purl_for_github_git_https_test() {
  let entry = github_git_entry("https://github.com/tylerbutler/gluegun")
  should.equal(
    sbom.purl_for(entry),
    Ok(
      "pkg:github/tylerbutler/gluegun@fa4c8ee919138fc8ffddd2642165a89654e61999",
    ),
  )
}

pub fn purl_for_github_lowercases_owner_and_repo_segments_only_test() {
  let entry = github_git_entry("https://github.com/TylerButler/GlueGun")
  should.equal(
    sbom.purl_for(entry),
    Ok(
      "pkg:github/tylerbutler/gluegun@fa4c8ee919138fc8ffddd2642165a89654e61999",
    ),
  )
}

pub fn purl_for_github_git_with_dot_git_suffix_test() {
  let entry = github_git_entry("https://github.com/tylerbutler/gluegun.git")
  should.equal(
    sbom.purl_for(entry),
    Ok(
      "pkg:github/tylerbutler/gluegun@fa4c8ee919138fc8ffddd2642165a89654e61999",
    ),
  )
}

pub fn purl_for_non_github_git_errors_test() {
  let entry =
    manifest.SbomEntry(
      name: "foo",
      version: "1.0.0",
      kind: manifest.Direct,
      requirements: [],
      provenance: manifest.GitProvenance(
        repo: "https://gitlab.com/x/foo",
        commit: "abc",
      ),
    )
  let assert Error(err) = sbom.purl_for(entry)
  let assert error.UnsupportedSourceForSbom(package, source, _) = err
  should.equal(package, "foo")
  should.equal(source, "git")
}

pub fn purl_for_path_dep_errors_test() {
  let entry =
    manifest.SbomEntry(
      name: "local_dep",
      version: "0.1.0",
      kind: manifest.Direct,
      requirements: [],
      provenance: manifest.PathProvenance(path: "../local_dep"),
    )
  let assert Error(err) = sbom.purl_for(entry)
  let assert error.UnsupportedSourceForSbom(package, source, _) = err
  should.equal(package, "local_dep")
  should.equal(source, "path")
}

pub fn purl_for_unknown_source_errors_test() {
  let entry =
    manifest.SbomEntry(
      name: "weird",
      version: "1.0.0",
      kind: manifest.Direct,
      requirements: [],
      provenance: manifest.UnknownProvenance(source: "rebar3"),
    )
  let assert Error(err) = sbom.purl_for(entry)
  let assert error.UnsupportedSourceForSbom(_, source, _) = err
  should.equal(source, "rebar3")
}

fn github_git_entry(repo: String) -> manifest.SbomEntry {
  manifest.SbomEntry(
    name: "gluegun",
    version: "0.1.0",
    kind: manifest.Direct,
    requirements: [],
    provenance: manifest.GitProvenance(
      repo: repo,
      commit: "fa4c8ee919138fc8ffddd2642165a89654e61999",
    ),
  )
}

pub fn license_entries_maps_known_spdx_to_id_test() {
  let entries = sbom.license_entries(["Apache-2.0", "MIT"])
  should.equal(entries, [sbom.LicenseId("Apache-2.0"), sbom.LicenseId("MIT")])
}

pub fn license_entries_case_insensitive_spdx_match_test() {
  let entries = sbom.license_entries(["apache-2.0"])
  should.equal(entries, [sbom.LicenseId("Apache-2.0")])
}

pub fn license_entries_maps_common_spdx_ids_beyond_original_allowlist_test() {
  let entries =
    sbom.license_entries([
      "postgresql", "blueoak-1.0.0", "bsd-4-clause", "lgpl-2.0-or-later",
    ])
  should.equal(entries, [
    sbom.LicenseId("PostgreSQL"),
    sbom.LicenseId("BlueOak-1.0.0"),
    sbom.LicenseId("BSD-4-Clause"),
    sbom.LicenseId("LGPL-2.0-or-later"),
  ])
}

pub fn license_entries_deduplicates_declared_licences_test() {
  let entries = sbom.license_entries(["MIT", "mit", "Apache-2.0", "apache-2.0"])
  should.equal(entries, [sbom.LicenseId("MIT"), sbom.LicenseId("Apache-2.0")])
}

pub fn license_entries_unknown_string_becomes_name_test() {
  let entries = sbom.license_entries(["Custom Corporate Licence"])
  should.equal(entries, [sbom.LicenseName("Custom Corporate Licence")])
}

pub fn license_entries_treats_spdx_ids_outside_cdx16_as_names_test() {
  let entries =
    sbom.license_entries(["Brian-Gladman-3-Clause-no-conversion", "MVT-1.1"])

  should.equal(entries, [
    sbom.LicenseName("Brian-Gladman-3-Clause-no-conversion"),
    sbom.LicenseName("MVT-1.1"),
  ])
}

pub fn license_entries_empty_list_test() {
  should.equal(sbom.license_entries([]), [])
}

import gleam/dict

pub fn render_includes_required_top_level_fields_test() {
  let json_str = sbom.render(minimal_input())
  let assert True = string.contains(json_str, "\"bomFormat\":\"CycloneDX\"")
  let assert True = string.contains(json_str, "\"specVersion\":\"1.6\"")
  let assert True =
    string.contains(
      json_str,
      "\"serialNumber\":\"urn:uuid:00000000-0000-4000-8000-000000000001\"",
    )
  let assert True =
    string.contains(json_str, "\"timestamp\":\"2026-05-24T22:51:00Z\"")
}

pub fn render_includes_cyclonedx_schema_uri_test() {
  let assert Ok(schema) =
    json.parse(
      sbom.render(minimal_input()),
      decode.at(["$schema"], decode.string),
    )

  should.equal(schema, "https://cyclonedx.org/schema/bom-1.6.schema.json")
}

pub fn render_emits_root_metadata_component_test() {
  let json_str = sbom.render(minimal_input())
  let assert True = string.contains(json_str, "\"name\":\"licence_audit\"")
  let assert True = string.contains(json_str, "\"version\":\"0.1.0\"")
  let assert True = string.contains(json_str, "\"bom-ref\":\"root\"")
}

pub fn render_root_metadata_omits_unknown_supplier_and_emits_unversioned_purl_test() {
  let json_str = sbom.render(minimal_input())
  let assert Ok(metadata_supplier) =
    json.parse(
      json_str,
      decode.optionally_at(
        ["metadata", "supplier", "name"],
        "__missing__",
        decode.string,
      ),
    )
  let assert Ok(component_supplier) =
    json.parse(
      json_str,
      decode.optionally_at(
        ["metadata", "component", "supplier", "name"],
        "__missing__",
        decode.string,
      ),
    )
  let assert Ok(purl) =
    json.parse(
      json_str,
      decode.at(["metadata", "component", "purl"], decode.string),
    )

  should.equal(metadata_supplier, "__missing__")
  should.equal(component_supplier, "__missing__")
  should.equal(purl, "pkg:github/tylerbutler/licence_audit")
}

pub fn render_root_metadata_component_omits_purl_without_repository_test() {
  let root = sbom.RootComponent(..minimal_input().root, repository: None)
  let json_str = sbom.render(sbom.SbomInput(..minimal_input(), root: root))
  let assert Ok(purl) =
    json.parse(
      json_str,
      decode.optionally_at(
        ["metadata", "component", "purl"],
        "__missing__",
        decode.string,
      ),
    )

  should.equal(purl, "__missing__")
}

pub fn render_root_metadata_component_emits_purl_when_version_empty_test() {
  let root = sbom.RootComponent(..minimal_input().root, version: "")
  let json_str = sbom.render(sbom.SbomInput(..minimal_input(), root: root))
  let assert Ok(purl) =
    json.parse(
      json_str,
      decode.at(["metadata", "component", "purl"], decode.string),
    )

  should.equal(purl, "pkg:github/tylerbutler/licence_audit")
}

pub fn render_emits_provenance_metadata_test() {
  let json_str = sbom.render(minimal_input())
  let assert True = string.contains(json_str, "\"authors\":")
  let assert True = string.contains(json_str, "\"supplier\":")
  let assert True = string.contains(json_str, "\"lifecycles\":")
  let assert True = string.contains(json_str, "\"phase\":\"build\"")
}

pub fn render_declares_complete_composition_test() {
  let json_str = sbom.render(minimal_input())
  let assert True = string.contains(json_str, "\"compositions\":")
  let assert True = string.contains(json_str, "\"aggregate\":\"complete\"")
}

pub fn render_enriches_root_component_test() {
  let json_str = sbom.render(minimal_input())
  let assert True =
    string.contains(
      json_str,
      "\"description\":\"Audit licences of locked Hex dependencies\"",
    )
  // Root licence appears as an SPDX id, and the repo as a vcs reference.
  let assert True = string.contains(json_str, "\"id\":\"Apache-2.0\"")
  let assert True =
    string.contains(
      json_str,
      "\"url\":\"https://github.com/tylerbutler/licence_audit\"",
    )
}

pub fn render_emits_hex_component_with_hash_and_license_test() {
  let json_str = sbom.render(minimal_input())
  let assert True =
    string.contains(json_str, "\"purl\":\"pkg:hex/birch@0.2.1\"")
  let assert True = string.contains(json_str, "\"alg\":\"SHA-256\"")
  let assert True = string.contains(json_str, "\"content\":\"deadbeef\"")
  let assert True = string.contains(json_str, "\"id\":\"Apache-2.0\"")
  // CycloneDX 1.6: licences are flagged as declared (vs concluded).
  let assert True =
    string.contains(json_str, "\"acknowledgement\":\"declared\"")
}

pub fn render_emits_dependency_graph_test() {
  let json_str = sbom.render(minimal_input())
  let assert True = string.contains(json_str, "\"dependencies\":")
  let assert True = string.contains(json_str, "\"ref\":\"root\"")
  let assert True =
    string.contains(json_str, "\"dependsOn\":[\"pkg:hex/birch@0.2.1\"]")
}

pub fn render_offline_omits_licenses_test() {
  // No package metadata (offline) and a root without its own licences, so no
  // component should declare a licence.
  let bare_root =
    sbom.RootComponent(
      name: "x",
      version: "0.0.0",
      description: None,
      licences: [],
      repository: None,
    )
  let input =
    sbom.SbomInput(
      ..minimal_input(),
      package_metadata: dict.new(),
      root: bare_root,
    )
  let json_str = sbom.render(input)
  let assert False = string.contains(json_str, "\"licenses\":")
}

pub fn render_emits_component_description_test() {
  let json_str = sbom.render(minimal_input())
  let assert True =
    string.contains(json_str, "\"description\":\"A logging library for Gleam\"")
}

pub fn render_emits_component_external_references_test() {
  let json_str = sbom.render(minimal_input())
  // Hex tarball distribution reference is added for every Hex component.
  let assert True = string.contains(json_str, "\"type\":\"distribution\"")
  let assert True =
    string.contains(json_str, "https://repo.hex.pm/tarballs/birch-0.2.1.tar")
  // meta.links are mapped to typed references, label preserved as comment.
  let assert True = string.contains(json_str, "\"type\":\"vcs\"")
  let assert True =
    string.contains(json_str, "https://github.com/tylerbutler/birch")
}

pub fn render_offline_still_emits_distribution_reference_test() {
  // The tarball URL is derived from provenance, so it survives offline mode
  // even though licences and descriptions (which need a Hex fetch) do not.
  let input = sbom.SbomInput(..minimal_input(), package_metadata: dict.new())
  let json_str = sbom.render(input)
  let assert True =
    string.contains(json_str, "https://repo.hex.pm/tarballs/birch-0.2.1.tar")
}

pub fn render_errors_on_unsupported_source_test() {
  let bad_entry =
    manifest.SbomEntry(
      name: "foo",
      version: "1.0.0",
      kind: manifest.Direct,
      requirements: [],
      provenance: manifest.PathProvenance(path: "../foo"),
    )
  let input =
    sbom.SbomInput(
      ..minimal_input(),
      manifest: manifest.SbomManifest(entries: [bad_entry], root_requirements: [
        "foo",
      ]),
    )
  let assert Error(err) = sbom.try_render(input)
  let assert error.UnsupportedSourceForSbom(_, _, _) = err
}

pub fn reproducible_serial_is_byte_stable_test() {
  // Same input + content-derived serial => byte-identical output (issue #9).
  let input =
    sbom.SbomInput(..minimal_input(), serial_number: sbom.ContentDerivedSerial)
  sbom.render(input) |> should.equal(sbom.render(input))
}

pub fn reproducible_serial_is_a_content_derived_urn_uuid_test() {
  let input =
    sbom.SbomInput(..minimal_input(), serial_number: sbom.ContentDerivedSerial)
  let serial = serial_of(sbom.render(input))
  string.starts_with(serial, "urn:uuid:") |> should.equal(True)
  string.length(serial) |> should.equal(45)
}

pub fn reproducible_serial_changes_with_dependency_set_test() {
  let one =
    sbom.SbomInput(..minimal_input(), serial_number: sbom.ContentDerivedSerial)
  let extra =
    manifest.SbomEntry(
      name: "gleam_stdlib",
      version: "1.0.0",
      kind: manifest.Direct,
      requirements: [],
      provenance: manifest.HexProvenance(
        outer_checksum: "ABCD",
        inner_checksum: None,
      ),
    )
  let two =
    sbom.SbomInput(
      ..one,
      manifest: manifest.SbomManifest(
        entries: [hex_entry("birch", "0.2.1"), extra],
        root_requirements: ["birch"],
      ),
    )
  { serial_of(sbom.render(one)) == serial_of(sbom.render(two)) }
  |> should.equal(False)
}

pub fn components_are_emitted_sorted_by_purl_test() {
  // Entries supplied out of order are emitted sorted by purl.
  let input =
    sbom.SbomInput(
      ..minimal_input(),
      manifest: manifest.SbomManifest(
        entries: [hex_entry("zeta", "1.0.0"), hex_entry("alpha", "1.0.0")],
        root_requirements: [],
      ),
    )
  let rendered = sbom.render(input)
  let assert Ok(#(before, _)) =
    string.split_once(rendered, on: "pkg:hex/zeta@1.0.0")
  string.contains(before, "pkg:hex/alpha@1.0.0") |> should.equal(True)
}

pub fn render_omits_component_version_when_empty_test() {
  let entry =
    manifest.SbomEntry(
      name: "GlueGun",
      version: "",
      kind: manifest.Direct,
      requirements: [],
      provenance: manifest.GitProvenance(
        repo: "https://github.com/TylerButler/GlueGun",
        commit: "fa4c8ee919138fc8ffddd2642165a89654e61999",
      ),
    )
  let input =
    sbom.SbomInput(
      ..minimal_input(),
      manifest: manifest.SbomManifest(entries: [entry], root_requirements: [
        "GlueGun",
      ]),
      package_metadata: dict.new(),
    )
  let json_str = sbom.render(input)
  let assert Ok(versions) =
    json.parse(
      json_str,
      decode.field(
        "components",
        decode.list(component_version_or_missing_decoder()),
        decode.success,
      ),
    )
  let assert Ok(purls) =
    json.parse(
      json_str,
      decode.field(
        "components",
        decode.list(component_purl_decoder()),
        decode.success,
      ),
    )

  should.equal(versions, ["__missing__"])
  should.equal(purls, [
    "pkg:github/tylerbutler/gluegun@fa4c8ee919138fc8ffddd2642165a89654e61999",
  ])
}

fn component_version_or_missing_decoder() {
  use version <- decode.optional_field("version", "__missing__", decode.string)
  decode.success(version)
}

fn component_purl_decoder() {
  use purl <- decode.field("purl", decode.string)
  decode.success(purl)
}

fn serial_of(rendered: String) -> String {
  let assert Ok(#(_, after)) =
    string.split_once(rendered, on: "\"serialNumber\":\"")
  let assert Ok(#(serial, _)) = string.split_once(after, on: "\"")
  serial
}

fn hex_entry(name: String, version: String) -> manifest.SbomEntry {
  manifest.SbomEntry(
    name: name,
    version: version,
    kind: manifest.Direct,
    requirements: [],
    provenance: manifest.HexProvenance(
      outer_checksum: "DEADBEEF",
      inner_checksum: None,
    ),
  )
}

fn minimal_input() -> sbom.SbomInput {
  let entry =
    manifest.SbomEntry(
      name: "birch",
      version: "0.2.1",
      kind: manifest.Direct,
      requirements: [],
      provenance: manifest.HexProvenance(
        outer_checksum: "DEADBEEF",
        inner_checksum: None,
      ),
    )
  let manifest_value =
    manifest.SbomManifest(entries: [entry], root_requirements: ["birch"])
  let package_metadata =
    dict.new()
    |> dict.insert(
      "birch",
      hex.PackageMetadata(
        licences: ["Apache-2.0"],
        description: Some("A logging library for Gleam"),
        links: [#("GitHub", "https://github.com/tylerbutler/birch")],
        publisher: Some("birch_owner"),
      ),
    )
  sbom.SbomInput(
    manifest: manifest_value,
    root: sbom.RootComponent(
      name: "licence_audit",
      version: "0.1.0",
      description: Some("Audit licences of locked Hex dependencies"),
      licences: ["Apache-2.0"],
      repository: Some("https://github.com/tylerbutler/licence_audit"),
    ),
    tool_version: "0.1.0",
    serial_number: sbom.FixedSerial(
      "urn:uuid:00000000-0000-4000-8000-000000000001",
    ),
    timestamp: "2026-05-24T22:51:00Z",
    package_metadata: package_metadata,
    scopes: dict.new(),
    vulnerabilities: [],
  )
}

pub fn render_omits_vulnerabilities_when_absent_test() {
  // A plain SBOM (no embedded vulns) must keep its existing shape.
  let assert False =
    string.contains(sbom.render(minimal_input()), "\"vulnerabilities\":")
}

pub fn render_embeds_vulnerabilities_with_ratings_and_affects_test() {
  let vuln =
    osv.Vulnerability(
      id: "GHSA-aaaa-bbbb-cccc",
      summary: "Cross-site scripting in example",
      severity: osv.High,
      scores: [
        osv.Score(
          kind: "CVSS_V3",
          vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        ),
      ],
    )
  let input =
    sbom.SbomInput(..minimal_input(), vulnerabilities: [
      sbom.EmbeddedVulnerability(vuln: vuln, affects: ["pkg:hex/birch@0.2.1"]),
    ])
  let out = sbom.render(input)

  assert string.contains(out, "\"vulnerabilities\":")
  assert string.contains(out, "\"id\":\"GHSA-aaaa-bbbb-cccc\"")
  // source points at the OSV advisory page.
  assert string.contains(
    out,
    "\"url\":\"https://osv.dev/vulnerability/GHSA-aaaa-bbbb-cccc\"",
  )
  // The raw CVSS vector and mapped method are preserved in ratings.
  assert string.contains(out, "\"method\":\"CVSSv31\"")
  assert string.contains(out, "\"vector\":\"CVSS:3.1/AV:N")
  assert string.contains(out, "\"severity\":\"high\"")
  // affects references the component bom-ref (purl).
  assert string.contains(out, "\"affects\":[{\"ref\":\"pkg:hex/birch@0.2.1\"}]")
  assert string.contains(
    out,
    "\"description\":\"Cross-site scripting in example\"",
  )
}

pub fn render_embeds_vulnerability_without_cvss_vector_test() {
  // When OSV reports no machine-readable vector, ratings carry just the
  // severity bucket (no method/vector keys).
  let vuln =
    osv.Vulnerability(
      id: "CVE-2024-0002",
      summary: "",
      severity: osv.Medium,
      scores: [],
    )
  let input =
    sbom.SbomInput(..minimal_input(), vulnerabilities: [
      sbom.EmbeddedVulnerability(vuln: vuln, affects: ["pkg:hex/birch@0.2.1"]),
    ])
  let out = sbom.render(input)

  assert string.contains(out, "\"id\":\"CVE-2024-0002\"")
  assert string.contains(out, "\"severity\":\"medium\"")
  assert !string.contains(out, "\"method\":")
}

pub fn render_emits_scope_property_test() {
  let input =
    sbom.SbomInput(
      ..minimal_input(),
      scopes: dict.from_list([#("birch", manifest.Dev)]),
    )
  let output = sbom.render(input)

  assert string.contains(output, "licence_audit:scope")
  assert string.contains(output, "\"value\":\"dev\"")
}

pub fn render_emits_publisher_when_metadata_has_one_test() {
  // The minimal input fixture sets the birch publisher to "birch_owner".
  let output = sbom.render(minimal_input())

  assert string.contains(output, "\"publisher\":\"birch_owner\"")
}

pub fn render_emits_supplier_for_every_hex_component_test() {
  // Every Hex component carries the same supplier object so SBOM consumers
  // can identify the registry the artefact was supplied from.
  let output = sbom.render(minimal_input())

  assert string.contains(
    output,
    "\"supplier\":{\"name\":\"Hex\",\"url\":[\"https://hex.pm/packages/birch\"]}",
  )
}

pub fn render_emits_supplier_even_when_publisher_absent_test() {
  // Supplier identifies *where* the artefact came from (the Hex registry),
  // not who authored it, so it must be emitted regardless of whether Hex
  // exposes owner / maintainer information.
  let metadata =
    dict.from_list([
      #(
        "birch",
        hex.PackageMetadata(
          licences: ["Apache-2.0"],
          description: None,
          links: [],
          publisher: None,
        ),
      ),
    ])
  let output =
    sbom.render(sbom.SbomInput(..minimal_input(), package_metadata: metadata))

  assert string.contains(
    output,
    "\"supplier\":{\"name\":\"Hex\",\"url\":[\"https://hex.pm/packages/birch\"]}",
  )
  assert !string.contains(output, "\"publisher\":")
}

pub fn render_omits_publisher_when_metadata_has_none_test() {
  let metadata =
    dict.from_list([
      #(
        "birch",
        hex.PackageMetadata(
          licences: ["Apache-2.0"],
          description: None,
          links: [],
          publisher: None,
        ),
      ),
    ])
  let output =
    sbom.render(sbom.SbomInput(..minimal_input(), package_metadata: metadata))

  assert !string.contains(output, "\"publisher\":")
}

pub fn render_emits_inner_checksum_property_when_present_test() {
  let entry =
    manifest.SbomEntry(
      name: "birch",
      version: "0.2.1",
      kind: manifest.Direct,
      requirements: [],
      provenance: manifest.HexProvenance(
        outer_checksum: "DEADBEEF",
        inner_checksum: Some("CAFEBABE"),
      ),
    )
  let input =
    sbom.SbomInput(
      ..minimal_input(),
      manifest: manifest.SbomManifest(entries: [entry], root_requirements: [
        "birch",
      ]),
    )
  let output = sbom.render(input)

  // Outer hash still surfaces in the standard `hashes` block...
  assert string.contains(output, "\"content\":\"deadbeef\"")
  // ...and the inner checksum is labelled as a property so consumers can tell
  // the two SHA-256 hashes apart (CycloneDX `hashes` has no scope/label).
  assert string.contains(output, "licence_audit:hex_inner_checksum")
  assert string.contains(output, "\"value\":\"cafebabe\"")
}

pub fn render_omits_inner_checksum_property_when_absent_test() {
  let output = sbom.render(minimal_input())

  assert !string.contains(output, "licence_audit:hex_inner_checksum")
}
