import gleam/dict
import gleam/dynamic/decode
import gleam/json
import gleam/list
import gleam/option.{None, Some}
import gleam/string
import gleeunit/should
import licence_audit/error
import licence_audit/hex
import licence_audit/manifest
import licence_audit/sbom
import licence_audit/sbom_spdx
import simplifile

fn fixture() -> sbom.SbomInput {
  sbom.SbomInput(
    manifest: manifest.SbomManifest(
      entries: [
        manifest.SbomEntry(
          name: "a_b",
          version: "1.0.0",
          requirements: ["a-b", "a-b"],
          provenance: manifest.HexProvenance(
            string.repeat("A", 64),
            Some(string.repeat("B", 64)),
          ),
        ),
        manifest.SbomEntry(
          name: "a-b",
          version: "",
          requirements: [],
          provenance: manifest.GitProvenance(
            "https://github.com/example/example.git",
            string.repeat("c", 40),
          ),
        ),
        manifest.SbomEntry(
          name: "unknown",
          version: "2.0.0",
          requirements: [],
          provenance: manifest.HexProvenance(string.repeat("d", 64), None),
        ),
      ],
      root_requirements: ["unknown", "a_b"],
    ),
    root: sbom.RootComponent(
      name: "example",
      version: "1.0.0",
      description: None,
      licences: ["LicenseRef-Private \"custom\""],
      repository: None,
    ),
    tool_version: "0.13.1",
    timestamp: "1970-01-01T00:00:00Z",
    serial_number: sbom.ContentDerivedSerial,
    package_metadata: dict.from_list([
      #(
        "a_b",
        hex.PackageMetadata(
          licences: ["mit"],
          description: None,
          links: [],
          publisher: None,
        ),
      ),
      #(
        "a-b",
        hex.PackageMetadata(
          licences: ["MIT", "Apache-2.0"],
          description: None,
          links: [],
          publisher: None,
        ),
      ),
    ]),
    scopes: dict.new(),
    vulnerabilities: [],
  )
}

fn package_decoder() -> decode.Decoder(#(String, String, String)) {
  use name <- decode.field("name", decode.string)
  use id <- decode.field("SPDXID", decode.string)
  use licence <- decode.field("licenseDeclared", decode.string)
  decode.success(#(name, id, licence))
}

fn relationship_decoder() -> decode.Decoder(#(String, String, String)) {
  use from <- decode.field("spdxElementId", decode.string)
  use kind <- decode.field("relationshipType", decode.string)
  use to <- decode.field("relatedSpdxElement", decode.string)
  decode.success(#(from, kind, to))
}

pub fn renders_resolved_graph_and_conservative_licences_test() {
  let assert Ok(document) = sbom_spdx.try_render(fixture())
  let assert Ok(packages) =
    json.parse(
      document,
      decode.at(["packages"], decode.list(package_decoder())),
    )
  packages
  |> should.equal([
    #("example", "SPDXRef-Root", "NOASSERTION"),
    #("a-b", "SPDXRef-Package-612D62", "NOASSERTION"),
    #("a_b", "SPDXRef-Package-615F62", "MIT"),
    #("unknown", "SPDXRef-Package-756E6B6E6F776E", "NOASSERTION"),
  ])
  let assert Ok(relationships) =
    json.parse(
      document,
      decode.at(["relationships"], decode.list(relationship_decoder())),
    )
  relationships
  |> should.equal([
    #("SPDXRef-DOCUMENT", "DESCRIBES", "SPDXRef-Root"),
    #("SPDXRef-Root", "DEPENDS_ON", "SPDXRef-Package-615F62"),
    #("SPDXRef-Root", "DEPENDS_ON", "SPDXRef-Package-756E6B6E6F776E"),
    #("SPDXRef-Package-615F62", "DEPENDS_ON", "SPDXRef-Package-612D62"),
  ])
  // The external schema/semantic check consumes this mixed-source fixture.
  simplifile.write("build/spdx-test.json", document) |> should.be_ok
}

pub fn output_is_stable_under_manifest_and_requirement_reordering_test() {
  let input = fixture()
  let reordered =
    sbom.SbomInput(
      ..input,
      manifest: manifest.SbomManifest(
        entries: list.reverse(input.manifest.entries),
        root_requirements: list.reverse(input.manifest.root_requirements),
      ),
    )
  sbom_spdx.try_render(input) |> should.equal(sbom_spdx.try_render(reordered))
  let changed = sbom.SbomInput(..input, tool_version: "0.13.2")
  let namespace_decoder = decode.at(["documentNamespace"], decode.string)
  let assert Ok(first) = sbom_spdx.try_render(input)
  let assert Ok(second) = sbom_spdx.try_render(changed)
  json.parse(first, namespace_decoder)
  |> should.not_equal(json.parse(second, namespace_decoder))
}

pub fn checksums_use_only_outer_hash_and_lowercase_test() {
  let assert Ok(document) = sbom_spdx.try_render(fixture())
  let decoder = {
    use packages <- decode.field(
      "packages",
      decode.list({
        use name <- decode.field("name", decode.string)
        use checksums <- decode.optional_field(
          "checksums",
          [],
          decode.list(decode.at(["checksumValue"], decode.string)),
        )
        decode.success(#(name, checksums))
      }),
    )
    decode.success(packages)
  }
  let assert Ok(packages) = json.parse(document, decoder)
  packages
  |> should.equal([
    #("example", []),
    #("a-b", []),
    #("a_b", [string.repeat("a", 64)]),
    #("unknown", [string.repeat("d", 64)]),
  ])
}

pub fn rejects_invalid_checksum_and_unsupported_source_test() {
  let input = fixture()
  let assert [entry, ..] = input.manifest.entries
  list.each(["DEADBEEF", string.repeat("g", 64)], fn(checksum) {
    let invalid =
      manifest.SbomEntry(
        ..entry,
        provenance: manifest.HexProvenance(checksum, None),
      )
    let changed =
      sbom.SbomInput(
        ..input,
        manifest: manifest.SbomManifest(
          entries: [invalid],
          root_requirements: [],
        ),
      )
    sbom_spdx.try_render(changed)
    |> should.equal(
      Error(error.Input("Invalid locked SHA-256 checksum for a_b")),
    )
  })
  let changed =
    sbom.SbomInput(
      ..input,
      manifest: manifest.SbomManifest(
        entries: [
          manifest.SbomEntry(..entry, provenance: manifest.PathProvenance(".")),
        ],
        root_requirements: [],
      ),
    )
  let assert Error(error.UnsupportedSourceForSbom(..)) =
    sbom_spdx.try_render(changed)
}

pub fn empty_manifest_is_a_valid_root_document_test() {
  let input =
    sbom.SbomInput(
      ..fixture(),
      manifest: manifest.SbomManifest(entries: [], root_requirements: []),
    )
  let assert Ok(document) = sbom_spdx.try_render(input)
  simplifile.write("build/spdx-empty-test.json", document) |> should.be_ok
}

pub fn spdx_licences_are_not_limited_to_the_cyclonedx_schema_test() {
  let input = fixture()
  let assert Ok(document) =
    sbom_spdx.try_render(
      sbom.SbomInput(
        ..input,
        root: sbom.RootComponent(..input.root, licences: ["mvt-1.1"]),
      ),
    )
  let assert Ok(packages) =
    json.parse(
      document,
      decode.at(["packages"], decode.list(package_decoder())),
    )
  let assert [#(_, _, licence), ..] = packages
  licence |> should.equal("MVT-1.1")
  sbom.license_entries(["mvt-1.1"])
  |> should.equal([sbom.LicenseName("mvt-1.1")])
}
