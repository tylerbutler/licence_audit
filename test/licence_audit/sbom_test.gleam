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

import licence_audit/error
import licence_audit/manifest
import licence_audit/sbom

pub fn purl_for_hex_test() {
  let entry =
    manifest.SbomEntry(
      name: "birch",
      version: "0.2.1",
      kind: manifest.Direct,
      requirements: [],
      provenance: manifest.HexProvenance(outer_checksum: "DEADBEEF"),
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

pub fn license_entries_unknown_string_becomes_name_test() {
  let entries = sbom.license_entries(["Custom Corporate Licence"])
  should.equal(entries, [sbom.LicenseName("Custom Corporate Licence")])
}

pub fn license_entries_empty_list_test() {
  should.equal(sbom.license_entries([]), [])
}

import gleam/dict

pub fn render_includes_required_top_level_fields_test() {
  let json_str = sbom.render(minimal_input())
  let assert True = string.contains(json_str, "\"bomFormat\":\"CycloneDX\"")
  let assert True = string.contains(json_str, "\"specVersion\":\"1.5\"")
  let assert True =
    string.contains(
      json_str,
      "\"serialNumber\":\"urn:uuid:00000000-0000-4000-8000-000000000001\"",
    )
  let assert True =
    string.contains(json_str, "\"timestamp\":\"2026-05-24T22:51:00Z\"")
}

pub fn render_emits_root_metadata_component_test() {
  let json_str = sbom.render(minimal_input())
  let assert True = string.contains(json_str, "\"name\":\"licence_audit\"")
  let assert True = string.contains(json_str, "\"version\":\"0.1.0\"")
  let assert True = string.contains(json_str, "\"bom-ref\":\"root\"")
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

pub fn render_emits_hex_component_with_hash_and_license_test() {
  let json_str = sbom.render(minimal_input())
  let assert True =
    string.contains(json_str, "\"purl\":\"pkg:hex/birch@0.2.1\"")
  let assert True = string.contains(json_str, "\"alg\":\"SHA-256\"")
  let assert True = string.contains(json_str, "\"content\":\"deadbeef\"")
  let assert True = string.contains(json_str, "\"id\":\"Apache-2.0\"")
}

pub fn render_emits_dependency_graph_test() {
  let json_str = sbom.render(minimal_input())
  let assert True = string.contains(json_str, "\"dependencies\":")
  let assert True = string.contains(json_str, "\"ref\":\"root\"")
  let assert True =
    string.contains(json_str, "\"dependsOn\":[\"pkg:hex/birch@0.2.1\"]")
}

pub fn render_offline_omits_licenses_test() {
  let input = sbom.SbomInput(..minimal_input(), license_metadata: dict.new())
  let json_str = sbom.render(input)
  let assert False = string.contains(json_str, "\"licenses\":")
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

fn minimal_input() -> sbom.SbomInput {
  let entry =
    manifest.SbomEntry(
      name: "birch",
      version: "0.2.1",
      kind: manifest.Direct,
      requirements: [],
      provenance: manifest.HexProvenance(outer_checksum: "DEADBEEF"),
    )
  let manifest_value =
    manifest.SbomManifest(entries: [entry], root_requirements: ["birch"])
  let licenses =
    dict.new()
    |> dict.insert("birch", ["Apache-2.0"])
  sbom.SbomInput(
    manifest: manifest_value,
    root: sbom.RootComponent(name: "licence_audit", version: "0.1.0"),
    tool_version: "0.1.0",
    serial_number: "urn:uuid:00000000-0000-4000-8000-000000000001",
    timestamp: "2026-05-24T22:51:00Z",
    license_metadata: licenses,
    scopes: dict.new(),
  )
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
