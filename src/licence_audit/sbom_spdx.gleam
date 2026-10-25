import gleam/bit_array
import gleam/dict
import gleam/json
import gleam/list
import gleam/result
import gleam/string
import licence_audit/error
import licence_audit/manifest
import licence_audit/sbom
import licence_audit/sbom_uuid

const root_id = "SPDXRef-Root"

/// Render the locked package graph without asserting file analysis or inferred
/// licence choices. Source validation is shared with the CycloneDX renderer.
pub fn try_render(input: sbom.SbomInput) -> Result(String, error.Error) {
  let entries =
    list.sort(input.manifest.entries, fn(a, b) {
      string.compare(a.name, b.name)
    })
  use packages <- result.try(
    list.try_map(entries, fn(entry) { package_json(entry, input) }),
  )
  let identifiers =
    dict.from_list(
      list.map(entries, fn(entry) { #(entry.name, package_id(entry)) }),
    )
  let relationships = [
    relationship("SPDXRef-DOCUMENT", "DESCRIBES", root_id),
    ..list.append(
      dependency_relationships(
        root_id,
        input.manifest.root_requirements,
        identifiers,
      ),
      list.flat_map(entries, fn(entry) {
        dependency_relationships(
          package_id(entry),
          entry.requirements,
          identifiers,
        )
      }),
    )
  ]
  let root =
    json.object(list.append(
      [
        #("SPDXID", json.string(root_id)),
        #("name", json.string(input.root.name)),
        #("versionInfo", json.string(input.root.version)),
        #("downloadLocation", json.string("NOASSERTION")),
        #("filesAnalyzed", json.bool(False)),
        #("licenseConcluded", json.string("NOASSERTION")),
        #("copyrightText", json.string("NOASSERTION")),
      ],
      licence_fields(input.root.licences),
    ))
  let fields = [
    #("spdxVersion", json.string("SPDX-2.3")),
    #("dataLicense", json.string("CC0-1.0")),
    #("SPDXID", json.string("SPDXRef-DOCUMENT")),
    #("name", json.string(input.root.name <> "-" <> input.root.version)),
    #(
      "creationInfo",
      json.object([
        #("created", json.string(input.timestamp)),
        #(
          "creators",
          json.array(
            ["Tool: licence_audit-" <> input.tool_version],
            json.string,
          ),
        ),
      ]),
    ),
    #("packages", json.preprocessed_array([root, ..packages])),
    #("relationships", json.preprocessed_array(relationships)),
  ]
  use namespace <- result.try(case input.serial_number {
    sbom.FixedSerial(value) -> Ok(value)
    sbom.ContentDerivedSerial ->
      fields
      |> json.object
      |> json.to_string
      |> sbom_uuid.serial_number_from_content
      |> result.replace_error(error.SbomSerialNumberFailed)
  })
  Ok(
    list.append(fields, [#("documentNamespace", json.string(namespace))])
    |> json.object
    |> json.to_string,
  )
}

fn package_id(entry: manifest.SbomEntry) -> String {
  // Hex encoding is reversible and collision-free, including punctuation and
  // Unicode; lossy replacement with '-' would alias distinct package names.
  "SPDXRef-Package-"
  <> bit_array.base16_encode(bit_array.from_string(entry.name))
}

fn package_json(
  entry: manifest.SbomEntry,
  input: sbom.SbomInput,
) -> Result(json.Json, error.Error) {
  use purl <- result.try(sbom.purl_for(entry))
  use source_fields <- result.try(case entry.provenance {
    manifest.HexProvenance(checksum, _) -> {
      let checksum = string.lowercase(checksum)
      case
        string.length(checksum) == 64
        && list.all(string.to_graphemes(checksum), fn(char) {
          string.contains("0123456789abcdef", char)
        })
      {
        False ->
          Error(error.Input(
            "Invalid locked SHA-256 checksum for " <> entry.name,
          ))
        True ->
          Ok([
            #(
              "downloadLocation",
              json.string(
                "https://repo.hex.pm/tarballs/"
                <> entry.name
                <> "-"
                <> entry.version
                <> ".tar",
              ),
            ),
            #(
              "checksums",
              json.preprocessed_array([
                json.object([
                  #("algorithm", json.string("SHA256")),
                  #("checksumValue", json.string(checksum)),
                ]),
              ]),
            ),
          ])
      }
    }
    manifest.GitProvenance(repo, commit) ->
      Ok([
        #("downloadLocation", json.string("git+" <> repo <> "@" <> commit)),
      ])
    manifest.PathProvenance(_) | manifest.UnknownProvenance(_) ->
      Ok([#("downloadLocation", json.string("NOASSERTION"))])
  })
  let licences = case dict.get(input.package_metadata, entry.name) {
    Ok(metadata) -> metadata.licences
    Error(_) -> []
  }
  Ok(
    [
      #("SPDXID", json.string(package_id(entry))),
      #("name", json.string(entry.name)),
      #("versionInfo", json.string(entry.version)),
      #("filesAnalyzed", json.bool(False)),
      #("licenseConcluded", json.string("NOASSERTION")),
      #("copyrightText", json.string("NOASSERTION")),
      #(
        "externalRefs",
        json.preprocessed_array([
          json.object([
            #("referenceCategory", json.string("PACKAGE-MANAGER")),
            #("referenceType", json.string("purl")),
            #("referenceLocator", json.string(purl)),
          ]),
        ]),
      ),
      ..list.append(source_fields, licence_fields(licences))
    ]
    |> json.object,
  )
}

fn licence_fields(licences: List(String)) -> List(#(String, json.Json)) {
  case list.unique(list.map(licences, sbom.spdx_license_id)) {
    [Ok(id)] -> [#("licenseDeclared", json.string(id))]
    [] -> [#("licenseDeclared", json.string("NOASSERTION"))]
    _ -> [
      #("licenseDeclared", json.string("NOASSERTION")),
      // Hex supplies no AND/OR operator and custom names supply no licence
      // text. Preserve the declaration without inventing an expression or text.
      #(
        "licenseComments",
        json.string(
          "Unresolved declared licences (no inferred AND/OR or licence text): "
          <> json.to_string(json.array(
            list.sort(list.unique(licences), string.compare),
            json.string,
          )),
        ),
      ),
    ]
  }
}

fn dependency_relationships(
  parent: String,
  requirements: List(String),
  identifiers: dict.Dict(String, String),
) -> List(json.Json) {
  requirements
  |> list.unique
  |> list.sort(string.compare)
  |> list.filter_map(fn(name) {
    dict.get(identifiers, name)
    |> result.map(fn(id) { relationship(parent, "DEPENDS_ON", id) })
  })
}

fn relationship(from: String, kind: String, to: String) -> json.Json {
  json.object([
    #("spdxElementId", json.string(from)),
    #("relationshipType", json.string(kind)),
    #("relatedSpdxElement", json.string(to)),
  ])
}
